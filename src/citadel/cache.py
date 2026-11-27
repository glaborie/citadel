"""Citadel-owned answer cache: exact first, then semantic, within one partition.

ADR-018 decides the shape. The partition key carries tenant, entitlement hash,
agent, prompt-pack version, model alias, tool-context version and the policy
version, so a lookup can only ever see an entry the same subject could have
produced. Nothing here trusts OmniRoute's cache; this table is the only cache.

Only a text answer that passed the output DLP gate is stored, and only on the
first step of a run (empty history), so a tool result - and therefore any T1/T2
effect or approval - cannot enter the cache. A store or embedder failure is a
miss, never a served entry: the run falls back to the model and keeps every
control.
"""

from __future__ import annotations

import hashlib
import json
import math
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final, Protocol

import psycopg
from psycopg.types.json import Jsonb

from citadel.db import tenant_connection
from citadel.retrieval.errors import RetrievalUnavailable

DEFAULT_TTL_SECONDS: Final = 3600
# Conservative on purpose: a false hit answers a different question. Calibrate
# with `calibrate_threshold` once a labelled paraphrase set exists for the pack.
DEFAULT_SIMILARITY: Final = 0.95
MAX_SEMANTIC_CANDIDATES: Final = 200


class CacheUnavailable(RuntimeError):
    """The backing store could not answer. The caller treats that as a miss."""


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


def entitlement_hash(values: Sequence[str]) -> str:
    """The digest of the subject's entitlement set, not the set itself."""
    material = "\n".join(sorted(values)).encode("utf-8")
    return "sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class CacheKey:
    tenant_id: str
    entitlement_hash: str
    agent_id: str
    prompt_pack_version: str
    model: str
    tool_context_version: str
    policy_version: str

    def __post_init__(self) -> None:
        required = (
            "tenant_id",
            "entitlement_hash",
            "agent_id",
            "prompt_pack_version",
            "model",
            "tool_context_version",
            "policy_version",
        )
        missing = [name for name in required if not getattr(self, name)]
        if missing:
            raise ValueError(f"cache key is missing {', '.join(missing)}")

    def partition(self) -> str:
        material = json.dumps(
            {
                "v": 1,
                "tenant": self.tenant_id,
                "entitlements": self.entitlement_hash,
                "agent": self.agent_id,
                "prompt_pack": self.prompt_pack_version,
                "model": self.model,
                "tool_context": self.tool_context_version,
                "policy": self.policy_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CacheEntry:
    tenant_id: str
    partition_key: str
    prompt_digest: str
    answer: str
    answer_model: str
    embedding: tuple[float, ...] | None
    embedding_model: str
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class CacheHit:
    answer: str
    model: str
    match: str  # exact | semantic
    score: float
    partition_key: str
    prompt_digest: str


def cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right) or not left:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=True))
    norm = math.sqrt(sum(a * a for a in left)) * math.sqrt(sum(b * b for b in right))
    return 0.0 if norm == 0.0 else dot / norm


def calibrate_threshold(positive: Sequence[float], negative: Sequence[float]) -> float:
    """Midpoint between the weakest true pair and the strongest false pair.

    Raises when the two sets overlap: no threshold separates them, so guessing
    one would ship a cache that answers the wrong question.
    """
    if not positive or not negative:
        raise ValueError("calibration needs both positive and negative pairs")
    lowest_positive = min(positive)
    highest_negative = max(negative)
    if lowest_positive <= highest_negative:
        raise ValueError("similarity sets overlap; no safe threshold exists")
    return round((lowest_positive + highest_negative) / 2, 6)


class CacheStore(Protocol):
    def get_exact(
        self, *, tenant_id: str, partition_key: str, prompt_digest: str, now: float
    ) -> CacheEntry | None: ...

    def candidates(
        self, *, tenant_id: str, partition_key: str, now: float, limit: int
    ) -> list[CacheEntry]: ...

    def put(self, entry: CacheEntry) -> None: ...

    def delete_tenant(self, tenant_id: str) -> int: ...


class InMemoryCacheStore:
    """The same contract as the Postgres store, for tests and red-team cases."""

    def __init__(self) -> None:
        self.entries: dict[tuple[str, str, str], CacheEntry] = {}

    def get_exact(
        self, *, tenant_id: str, partition_key: str, prompt_digest: str, now: float
    ) -> CacheEntry | None:
        entry = self.entries.get((tenant_id, partition_key, prompt_digest))
        return entry if entry is not None and entry.expires_at > now else None

    def candidates(
        self, *, tenant_id: str, partition_key: str, now: float, limit: int
    ) -> list[CacheEntry]:
        live = [
            entry
            for (tenant, partition, _), entry in self.entries.items()
            if tenant == tenant_id
            and partition == partition_key
            and entry.expires_at > now
            and entry.embedding is not None
        ]
        return sorted(live, key=lambda entry: entry.created_at, reverse=True)[:limit]

    def put(self, entry: CacheEntry) -> None:
        self.entries[(entry.tenant_id, entry.partition_key, entry.prompt_digest)] = entry

    def delete_tenant(self, tenant_id: str) -> int:
        doomed = [key for key in self.entries if key[0] == tenant_id]
        for key in doomed:
            del self.entries[key]
        return len(doomed)


_EXACT_SQL = """
    SELECT tenant_id, partition_key, prompt_digest, answer, answer_model,
           prompt_embedding, embedding_model, created_at, expires_at
      FROM cache_entries
     WHERE tenant_id = %s AND partition_key = %s AND prompt_digest = %s
       AND expires_at > now()
"""

_CANDIDATE_SQL = """
    SELECT tenant_id, partition_key, prompt_digest, answer, answer_model,
           prompt_embedding, embedding_model, created_at, expires_at
      FROM cache_entries
     WHERE tenant_id = %s AND partition_key = %s
       AND expires_at > now() AND prompt_embedding IS NOT NULL
     ORDER BY created_at DESC
     LIMIT %s
"""

_PUT_SQL = """
    INSERT INTO cache_entries
        (tenant_id, partition_key, prompt_digest, prompt_embedding,
         embedding_model, answer, answer_model, expires_at)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON CONFLICT (partition_key, prompt_digest) DO UPDATE
       SET answer = EXCLUDED.answer,
           answer_model = EXCLUDED.answer_model,
           prompt_embedding = EXCLUDED.prompt_embedding,
           embedding_model = EXCLUDED.embedding_model,
           created_at = now(),
           expires_at = EXCLUDED.expires_at
"""


class PostgresCacheStore:
    """Tenant-scoped through RLS: `tenant_connection` sets `app.tenant_id`."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def get_exact(
        self, *, tenant_id: str, partition_key: str, prompt_digest: str, now: float
    ) -> CacheEntry | None:
        del now  # the database clock decides expiry, so workers cannot disagree
        rows = self._rows(_EXACT_SQL, (tenant_id, partition_key, prompt_digest), tenant_id)
        return _entry(rows[0]) if rows else None

    def candidates(
        self, *, tenant_id: str, partition_key: str, now: float, limit: int
    ) -> list[CacheEntry]:
        del now
        rows = self._rows(_CANDIDATE_SQL, (tenant_id, partition_key, limit), tenant_id)
        return [_entry(row) for row in rows]

    def put(self, entry: CacheEntry) -> None:
        embedding = None if entry.embedding is None else Jsonb(list(entry.embedding))
        expires_at = datetime.fromtimestamp(entry.expires_at, tz=UTC)
        with _connection(self._dsn, entry.tenant_id) as conn:
            conn.execute(
                _PUT_SQL,
                (
                    entry.tenant_id,
                    entry.partition_key,
                    entry.prompt_digest,
                    embedding,
                    entry.embedding_model,
                    entry.answer,
                    entry.answer_model,
                    expires_at,
                ),
            )

    def delete_tenant(self, tenant_id: str) -> int:
        with _connection(self._dsn, tenant_id) as conn:
            deleted = conn.execute("DELETE FROM cache_entries WHERE tenant_id = %s", (tenant_id,))
            return int(deleted.rowcount)

    def _rows(self, sql: str, params: tuple[Any, ...], tenant_id: str) -> list[tuple[Any, ...]]:
        with _connection(self._dsn, tenant_id) as conn:
            return list(conn.execute(sql, params).fetchall())


@contextmanager
def _connection(dsn: str, tenant_id: str) -> Iterator[Any]:
    """A driver failure is a miss, not a crashed model step."""
    if not tenant_id:
        raise CacheUnavailable("cache access needs a tenant")
    try:
        with tenant_connection(dsn, tenant_id) as conn:
            yield conn
    except psycopg.Error as exc:
        raise CacheUnavailable(f"cache store unreachable: {exc}") from exc


def _entry(row: tuple[Any, ...]) -> CacheEntry:
    (
        tenant_id,
        partition_key,
        prompt_digest,
        answer,
        answer_model,
        embedding,
        embedding_model,
        created_at,
        expires_at,
    ) = row
    return CacheEntry(
        tenant_id=str(tenant_id),
        partition_key=str(partition_key),
        prompt_digest=str(prompt_digest),
        answer=str(answer),
        answer_model=str(answer_model),
        embedding=_vector(embedding),
        embedding_model=str(embedding_model),
        created_at=created_at.timestamp(),
        expires_at=expires_at.timestamp(),
    )


def _vector(raw: object) -> tuple[float, ...] | None:
    if not isinstance(raw, list) or not raw:
        return None
    return tuple(float(value) for value in raw)


@dataclass
class AnswerCache:
    """Exact lookup first, semantic only inside the same partition."""

    backend: CacheStore
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    similarity: float = DEFAULT_SIMILARITY
    embedder: Embedder | None = None
    embedding_model: str = ""

    def lookup(
        self, key: CacheKey, *, prompt_digest: str, task: str, semantic: bool = True
    ) -> CacheHit | None:
        partition = key.partition()
        now = time.time()
        exact = self._exact(key, partition, prompt_digest, now)
        if exact is not None:
            return _hit(exact, match="exact", score=1.0)
        if not semantic or self.embedder is None:
            return None
        return self._semantic(key, partition, task, now)

    def _exact(
        self, key: CacheKey, partition: str, prompt_digest: str, now: float
    ) -> CacheEntry | None:
        try:
            return self.backend.get_exact(
                tenant_id=key.tenant_id,
                partition_key=partition,
                prompt_digest=prompt_digest,
                now=now,
            )
        except CacheUnavailable:
            return None

    def _semantic(self, key: CacheKey, partition: str, task: str, now: float) -> CacheHit | None:
        vector = self._embed(task)
        if vector is None:
            return None
        try:
            candidates = self.backend.candidates(
                tenant_id=key.tenant_id,
                partition_key=partition,
                now=now,
                limit=MAX_SEMANTIC_CANDIDATES,
            )
        except CacheUnavailable:
            return None

        best: tuple[float, CacheEntry] | None = None
        for entry in candidates:
            if entry.embedding is None or entry.embedding_model != self.embedding_model:
                continue
            score = cosine(vector, entry.embedding)
            if score >= self.similarity and (best is None or score > best[0]):
                best = (score, entry)
        if best is None:
            return None
        return _hit(best[1], match="semantic", score=best[0])

    def store(
        self, key: CacheKey, *, prompt_digest: str, task: str, answer: str, model: str
    ) -> bool:
        if not answer:
            return False
        embedding = self._embed(task) if self.embedder is not None else None
        now = time.time()
        entry = CacheEntry(
            tenant_id=key.tenant_id,
            partition_key=key.partition(),
            prompt_digest=prompt_digest,
            answer=answer,
            answer_model=model,
            embedding=embedding,
            embedding_model=self.embedding_model if embedding is not None else "",
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        try:
            self.backend.put(entry)
        except CacheUnavailable:
            return False
        return True

    def invalidate_tenant(self, tenant_id: str) -> int:
        return self.backend.delete_tenant(tenant_id)

    def _embed(self, text: str) -> tuple[float, ...] | None:
        if self.embedder is None:
            return None
        try:
            vectors = self.embedder.embed([text])
        except RetrievalUnavailable:
            return None
        if not vectors or not vectors[0]:
            return None
        return tuple(float(value) for value in vectors[0])


def _hit(entry: CacheEntry, *, match: str, score: float) -> CacheHit:
    return CacheHit(
        answer=entry.answer,
        model=entry.answer_model,
        match=match,
        score=score,
        partition_key=entry.partition_key,
        prompt_digest=entry.prompt_digest,
    )
