"""Permission-aware hybrid search over one tenant's collection.

The ACL is a Qdrant filter inside the request, never a check on the response:
each prefetch carries the subject's entitlement tags, so a chunk outside them is
never a candidate for fusion or reranking. The collection name comes from the
same tenant that produced the tags, which makes a cross-tenant read a collection
that does not exist rather than a filter someone could forget.

Fusion is RRF over a dense and a sparse query, then a cross-encoder rerank. Both
endpoints see only text that passed the caller's redactor, and either endpoint
failing refuses the query instead of silently returning the fused order.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Any

from qdrant_client import QdrantClient, models

from citadel.retrieval.embed import Embedder
from citadel.retrieval.errors import QueryRefused, RetrievalUnavailable
from citadel.retrieval.ingest import DENSE, SPARSE, collection_name, sparse
from citadel.retrieval.rerank import Reranker

# Architecture §6: rerank top 50 to top 8.
CANDIDATES: int = 50
TOP_K: int = 8


@dataclass(frozen=True)
class Entitlements:
    """The ACL tags a subject holds, and the digest the audit event records."""

    tags: tuple[str, ...]

    @classmethod
    def for_tenant(cls, tenant_id: str, *, documents: Sequence[str] = ()) -> Entitlements:
        collection_name(tenant_id)  # refuse a tenant that cannot name a collection
        tags = {f"tenant:{tenant_id}", *(f"doc:{uri}" for uri in documents)}
        return cls(tags=tuple(sorted(tags)))

    @property
    def filter_set_hash(self) -> str:
        material = "\n".join(self.tags).encode()
        return "sha256:" + hashlib.sha256(material).hexdigest()


@dataclass(frozen=True)
class SearchRequest:
    tenant_id: str
    query: str
    top_k: int = TOP_K
    candidates: int = CANDIDATES
    entitlements: Entitlements | None = None


@dataclass(frozen=True)
class Citation:
    chunk_id: str
    source_uri: str
    revision: str
    score: float


@dataclass(frozen=True)
class RetrievedChunk:
    citation: Citation
    text: str


@dataclass(frozen=True)
class Results:
    query_digest: str
    collection: str
    filter_set_hash: str
    top_k: int
    chunks: tuple[RetrievedChunk, ...]

    @property
    def citations(self) -> list[dict[str, Any]]:
        return [
            {
                "chunk_id": chunk.citation.chunk_id,
                "source_uri": chunk.citation.source_uri,
                "revision": chunk.citation.revision,
                "score": chunk.citation.score,
            }
            for chunk in self.chunks
        ]


def query_digest(query: str) -> str:
    """The text is not written to the ledger; this is what a reviewer compares."""
    return "sha256:" + hashlib.sha256(query.encode()).hexdigest()


def acl_filter(tags: Sequence[str]) -> models.Filter:
    """One condition: the chunk's ACL array shares at least one tag with the subject.

    An empty tag set would match nothing in Qdrant anyway, but refusing it keeps
    "no entitlement" from becoming a request whose meaning depends on the server.
    """
    if not tags:
        raise QueryRefused("no entitlements, so there is no filter that permits a chunk")
    return models.Filter(
        must=[models.FieldCondition(key="acl", match=models.MatchAny(any=list(tags)))]
    )


def _entitled(request: SearchRequest) -> tuple[str, Entitlements, models.Filter]:
    name = collection_name(request.tenant_id)
    entitlements = request.entitlements or Entitlements.for_tenant(request.tenant_id)
    if f"tenant:{request.tenant_id}" not in entitlements.tags:
        raise QueryRefused("the entitlement set does not belong to this tenant")
    return name, entitlements, acl_filter(entitlements.tags)


def _dense(embedder: Embedder, text: str) -> list[float]:
    vectors = embedder.embed([text])
    if len(vectors) != 1 or not vectors[0]:
        raise RetrievalUnavailable("the embedder returned no vector for the query")
    return vectors[0]


def _payload_text(point: models.ScoredPoint, *, tenant_id: str) -> tuple[str, str, str]:
    """The citation fields, or a refusal - a malformed point is not a result."""
    payload = point.payload if isinstance(point.payload, dict) else {}
    if payload.get("tenant_id") != tenant_id:
        raise RetrievalUnavailable("a point from another tenant's collection was returned")
    source_uri, revision, text = (
        payload.get("source_uri"),
        payload.get("revision"),
        payload.get("text"),
    )
    if not all(isinstance(value, str) and value for value in (source_uri, revision, text)):
        raise RetrievalUnavailable("a candidate is missing source_uri, revision or text")
    return str(source_uri), str(revision), str(text)


@dataclass(frozen=True)
class _Candidate:
    chunk_id: str
    source_uri: str
    revision: str
    text: str

    @classmethod
    def from_point(cls, point: models.ScoredPoint, tenant_id: str) -> _Candidate:
        source_uri, revision, text = _payload_text(point, tenant_id=tenant_id)
        return cls(chunk_id=str(point.id), source_uri=source_uri, revision=revision, text=text)


def _candidates(points: Sequence[models.ScoredPoint], tenant_id: str) -> list[_Candidate]:
    return [_Candidate.from_point(point, tenant_id) for point in points]


def _fused(
    client: QdrantClient,
    request: SearchRequest,
    text: str,
    embedder: Embedder,
    acl: models.Filter,
) -> list[_Candidate]:
    """One request: both prefetches carry the ACL filter, then RRF fuses them."""
    response = client.query_points(
        collection_name(request.tenant_id),
        prefetch=[
            models.Prefetch(
                query=_dense(embedder, text),
                using=DENSE,
                filter=acl,
                limit=request.candidates,
            ),
            models.Prefetch(query=sparse(text), using=SPARSE, filter=acl, limit=request.candidates),
        ],
        query=models.FusionQuery(fusion=models.Fusion.RRF),
        limit=request.candidates,
        with_payload=True,
        with_vectors=False,
    )
    return _candidates(response.points, request.tenant_id)


def _ranked(
    request: SearchRequest,
    text: str,
    candidates: Sequence[_Candidate],
    reranker: Reranker,
    redact: Callable[[str], str] | None,
) -> tuple[RetrievedChunk, ...]:
    texts = [redact(item.text) if redact is not None else item.text for item in candidates]
    ranked = reranker.rerank(text, texts, top_n=request.top_k)
    return tuple(
        RetrievedChunk(
            citation=Citation(
                chunk_id=candidates[index].chunk_id,
                source_uri=candidates[index].source_uri,
                revision=candidates[index].revision,
                score=score,
            ),
            text=texts[index],
        )
        for index, score in ranked
    )


def search(
    client: QdrantClient,
    request: SearchRequest,
    embedder: Embedder,
    reranker: Reranker,
    redact: Callable[[str], str] | None = None,
) -> Results:
    """Dense + sparse in one request, RRF, then rerank the fused candidates."""
    if request.top_k <= 0 or request.candidates < request.top_k:
        raise QueryRefused("candidates must be at least top_k, and both must be positive")
    name, entitlements, acl = _entitled(request)
    # The hosted embedder and the reranker see the same DLP-cleaned query; the
    # digest still describes the text the caller asked with.
    text = redact(request.query) if redact is not None else request.query
    candidates = _fused(client, request, text, embedder, acl)
    return Results(
        query_digest=query_digest(request.query),
        collection=name,
        filter_set_hash=entitlements.filter_set_hash,
        top_k=request.top_k,
        chunks=_ranked(request, text, candidates, reranker, redact) if candidates else (),
    )
