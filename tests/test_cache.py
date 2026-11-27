"""The cache partition, TTL, invalidation and fail-closed behaviour."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import pytest

from citadel.cache import (
    AnswerCache,
    CacheEntry,
    CacheKey,
    CacheUnavailable,
    Embedder,
    InMemoryCacheStore,
    calibrate_threshold,
    cosine,
    entitlement_hash,
)
from citadel.retrieval.errors import RetrievalUnavailable


class Vectors:
    """An embedder whose vectors are named in the test, with no network."""

    def __init__(self, mapping: Mapping[str, Sequence[float]]) -> None:
        self._mapping = mapping

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [[float(value) for value in self._mapping[text]] for text in texts]


def key(**overrides: str) -> CacheKey:
    base = {
        "tenant_id": "lab-a",
        "entitlement_hash": entitlement_hash(["operator"]),
        "agent_id": "docker",
        "prompt_pack_version": "docker-1.0.0",
        "model": "auto/best-fast",
        "tool_context_version": "sha256:tools",
        "policy_version": "sha256:policy",
    }
    base.update(overrides)
    return CacheKey(**base)


def cache(
    *,
    store: InMemoryCacheStore | None = None,
    embedder: Embedder | None = None,
    embedding_model: str = "",
    similarity: float = 0.95,
    ttl_seconds: int = 3600,
) -> tuple[AnswerCache, InMemoryCacheStore]:
    store = store or InMemoryCacheStore()
    answer_cache = AnswerCache(
        backend=store,
        embedder=embedder,
        embedding_model=embedding_model,
        similarity=similarity,
        ttl_seconds=ttl_seconds,
    )
    return answer_cache, store


def test_the_partition_changes_with_every_component() -> None:
    """A key that drops one field lets two subjects share an answer."""
    base = key().partition()
    variants = [
        key(tenant_id="lab-b"),
        key(entitlement_hash=entitlement_hash(["operator", "approver"])),
        key(agent_id="github"),
        key(prompt_pack_version="docker-1.0.1"),
        key(model="auto/best-reasoning"),
        key(tool_context_version="sha256:other-tools"),
        key(policy_version="sha256:other-policy"),
    ]
    assert all(variant.partition() != base for variant in variants)


def test_the_partition_is_stable_and_order_insensitive() -> None:
    assert key().partition() == key().partition()
    assert entitlement_hash(["a", "b"]) == entitlement_hash(["b", "a"])


def test_a_key_missing_a_component_is_refused() -> None:
    with pytest.raises(ValueError):
        key(tenant_id="")
    with pytest.raises(ValueError):
        key(policy_version="")


def test_an_exact_answer_is_served_only_inside_its_partition() -> None:
    answer_cache, _ = cache()
    answer_cache.store(key(), prompt_digest="sha256:q", task="why?", answer="disk full", model="m")

    hit = answer_cache.lookup(key(), prompt_digest="sha256:q", task="why?")
    assert hit is not None and (hit.match, hit.answer) == ("exact", "disk full")

    assert (
        answer_cache.lookup(key(tenant_id="lab-b"), prompt_digest="sha256:q", task="why?") is None
    )
    reader = entitlement_hash(["reader"])
    assert (
        answer_cache.lookup(key(entitlement_hash=reader), prompt_digest="sha256:q", task="why?")
        is None
    )
    assert (
        answer_cache.lookup(key(policy_version="sha256:v2"), prompt_digest="sha256:q", task="why?")
        is None
    )
    assert (
        answer_cache.lookup(
            key(tool_context_version="sha256:t2"), prompt_digest="sha256:q", task="why?"
        )
        is None
    )


def test_a_semantic_hit_needs_the_threshold_and_the_same_embedding_model() -> None:
    embedder = Vectors(
        {
            "restart checkout-api": [1.0, 0.0],
            "checkout-api keeps restarting": [0.995, 0.1],
            "unrelated": [0.0, 1.0],
        }
    )
    answer_cache, _ = cache(embedder=embedder, embedding_model="embed-1", similarity=0.9)
    answer_cache.store(
        key(),
        prompt_digest="sha256:q",
        task="restart checkout-api",
        answer="restart it",
        model="m",
    )

    hit = answer_cache.lookup(
        key(), prompt_digest="sha256:other", task="checkout-api keeps restarting"
    )
    assert hit is not None and hit.match == "semantic"
    assert hit.score >= 0.9

    assert answer_cache.lookup(key(), prompt_digest="sha256:other", task="unrelated") is None
    # A vector from another embedding model is not comparable, even in the same partition.
    shared = InMemoryCacheStore()
    writer, _ = cache(store=shared, embedder=embedder, embedding_model="embed-1", similarity=0.9)
    writer.store(
        key(), prompt_digest="sha256:q", task="restart checkout-api", answer="restart it", model="m"
    )
    reader = AnswerCache(backend=shared, embedder=embedder, embedding_model="embed-2")
    assert (
        reader.lookup(key(), prompt_digest="sha256:other", task="checkout-api keeps restarting")
        is None
    )


def test_every_entry_expires() -> None:
    answer_cache, _ = cache(ttl_seconds=-1)
    answer_cache.store(key(), prompt_digest="sha256:q", task="why?", answer="disk full", model="m")
    assert answer_cache.lookup(key(), prompt_digest="sha256:q", task="why?") is None


def test_invalidating_a_tenant_removes_only_its_entries() -> None:
    answer_cache, store = cache()
    answer_cache.store(key(), prompt_digest="sha256:q", task="why?", answer="a", model="m")
    answer_cache.store(
        key(tenant_id="lab-b"), prompt_digest="sha256:q", task="why?", answer="b", model="m"
    )

    assert answer_cache.invalidate_tenant("lab-a") == 1
    assert answer_cache.lookup(key(), prompt_digest="sha256:q", task="why?") is None
    assert (
        answer_cache.lookup(key(tenant_id="lab-b"), prompt_digest="sha256:q", task="why?")
        is not None
    )
    assert len(store.entries) == 1


class DeadStore(InMemoryCacheStore):
    def get_exact(
        self, *, tenant_id: str, partition_key: str, prompt_digest: str, now: float
    ) -> CacheEntry | None:
        raise CacheUnavailable("down")

    def put(self, entry: CacheEntry) -> None:
        raise CacheUnavailable("down")


def test_an_unavailable_store_is_a_miss_not_a_stale_answer() -> None:
    answer_cache = AnswerCache(
        backend=DeadStore(),
        embedder=Vectors({"why?": [1.0, 0.0]}),
        embedding_model="e",
    )
    assert answer_cache.lookup(key(), prompt_digest="sha256:q", task="why?") is None
    assert (
        answer_cache.store(key(), prompt_digest="sha256:q", task="why?", answer="a", model="m")
        is False
    )


class DeadEmbedder:
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        raise RetrievalUnavailable("embedder down")


def test_a_dead_embedder_still_allows_exact_hits() -> None:
    answer_cache = AnswerCache(backend=InMemoryCacheStore(), embedder=DeadEmbedder())
    assert answer_cache.store(key(), prompt_digest="sha256:q", task="why?", answer="a", model="m")
    assert answer_cache.lookup(key(), prompt_digest="sha256:q", task="why?") is not None
    assert answer_cache.lookup(key(), prompt_digest="sha256:other", task="why?") is None


def test_a_threshold_is_only_calibrated_when_the_sets_separate() -> None:
    assert calibrate_threshold([0.97, 0.99], [0.6, 0.8]) == pytest.approx(0.885)
    with pytest.raises(ValueError):
        calibrate_threshold([0.7, 0.99], [0.6, 0.8])
    with pytest.raises(ValueError):
        calibrate_threshold([], [0.1])


def test_cosine_is_zero_for_a_zero_or_mismatched_vector() -> None:
    assert cosine([1.0, 0.0], [1.0, 0.0]) == pytest.approx(1.0)
    assert cosine([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)
    assert cosine([], [1.0]) == 0.0
    assert cosine([0.0, 0.0], [1.0, 0.0]) == 0.0
