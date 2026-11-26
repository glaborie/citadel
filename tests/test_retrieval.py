"""Hybrid retrieval: the ACL is in the query, RRF fuses, the reranker orders."""

from __future__ import annotations

import json
from collections.abc import Sequence
from types import SimpleNamespace
from typing import Any

import pytest
from qdrant_client import QdrantClient, models

from citadel import dlp
from citadel.evals.graders import grade
from citadel.evals.recorder import rows_to_events
from citadel.evals.schema import Case, check_events
from citadel.retrieval import ingest, query
from citadel.retrieval.activities import RetrievalActivities, RetrievalRequest
from citadel.retrieval.embed import OmniRouteEmbedder
from citadel.retrieval.errors import QueryRefused, RetrievalUnavailable
from citadel.retrieval.rerank import TeiReranker

TENANTS = ("lab-a", "lab-b", "lab-c")


def _vector(text: str) -> list[float]:
    """A stand-in whose distance means something: the first word decides."""
    words = ["alpha", "beta", "gamma"]
    return [1.0 if word in text.lower() else 0.0 for word in words]


class FakeEmbedder:
    def __init__(self) -> None:
        self.seen: list[list[str]] = []

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        self.seen.append(list(texts))
        return [_vector(text) for text in texts]


class FakeReranker:
    def __init__(self) -> None:
        self.seen: list[list[str]] = []
        self.queries: list[str] = []

    def rerank(self, query: str, texts: Sequence[str], *, top_n: int) -> list[tuple[int, float]]:
        self.queries.append(query)
        self.seen.append(list(texts))
        # Reverse the fused order so a test can tell reranking happened.
        ranked = [(index, 0.5 + index / 100) for index in range(len(texts))]
        return list(reversed(ranked))[:top_n]


def _ingest(client: QdrantClient, tenant: str, name: str, text: str) -> None:
    ingest.ingest(
        client,
        tenant=tenant,
        documents=[ingest.Document(source_uri=f"fs:{name}", content=text)],
        embedder=FakeEmbedder(),
    )


def _request(tenant: str, text: str = "alpha", **kwargs: Any) -> query.SearchRequest:
    return query.SearchRequest(tenant_id=tenant, query=text, **kwargs)


def _search(client: QdrantClient, tenant: str, text: str = "alpha") -> query.Results:
    return query.search(client, _request(tenant, text), FakeEmbedder(), FakeReranker())


def test_every_tenant_pairing_only_sees_its_own_chunks() -> None:
    """The same closest vector exists in every collection; only the tenant's is read."""
    client = QdrantClient(location=":memory:")
    for tenant in TENANTS:
        _ingest(client, tenant, tenant, "alpha runbook")

    for reader in TENANTS:
        _assert_isolated(_search(client, reader), reader)


def _assert_isolated(results: query.Results, reader: str) -> None:
    sources = {chunk.citation.source_uri for chunk in results.chunks}
    assert results.collection == ingest.collection_name(reader)
    assert results.chunks, f"{reader} lost its own chunk"
    assert sources == {f"fs:{reader}"}
    for writer in TENANTS:
        if writer != reader:
            assert f"fs:{writer}" not in sources


def test_the_acl_filter_is_in_the_request_and_fusion_is_rrf() -> None:
    seen: dict[str, Any] = {}

    class RecordingClient:
        def query_points(self, name: str, **kwargs: Any) -> Any:
            seen.update(kwargs)
            seen["collection"] = name
            return SimpleNamespace(points=[])

    results = query.search(
        RecordingClient(),  # type: ignore[arg-type]
        _request("lab-a", top_k=3),
        FakeEmbedder(),
        FakeReranker(),
    )

    assert results.chunks == ()
    prefetches = seen["prefetch"]
    assert [item.using for item in prefetches] == [ingest.DENSE, ingest.SPARSE]
    for prefetch in prefetches:
        condition = prefetch.filter.must[0]
        assert condition.key == "acl"
        assert condition.match.any == ["tenant:lab-a"]
    assert seen["query"].fusion == models.Fusion.RRF
    assert seen["limit"] == query.CANDIDATES


def test_the_filter_set_hash_is_tenant_scoped_and_never_the_query_text() -> None:
    a = query.Entitlements.for_tenant("lab-a")
    b = query.Entitlements.for_tenant("lab-b")

    assert a.filter_set_hash.startswith("sha256:")
    assert a.filter_set_hash != b.filter_set_hash
    assert a.filter_set_hash == query.Entitlements.for_tenant("lab-a").filter_set_hash


def test_entitlements_for_another_tenant_are_refused() -> None:
    with pytest.raises(QueryRefused, match="does not belong"):
        query.search(
            QdrantClient(location=":memory:"),
            _request("lab-a", entitlements=query.Entitlements.for_tenant("lab-b")),
            FakeEmbedder(),
            FakeReranker(),
        )
    with pytest.raises(QueryRefused, match="no entitlements"):
        query.acl_filter([])


def test_redaction_happens_before_the_reranker_and_in_the_result() -> None:
    client = QdrantClient(location=":memory:")
    _ingest(client, "lab-a", "contact", "alpha owner is alice@example.com")
    reranker = FakeReranker()

    results = query.search(
        client,
        _request("lab-a"),
        FakeEmbedder(),
        reranker,
        redact=lambda text: text.replace("alice@example.com", "<EMAIL_ADDRESS>"),
    )

    assert reranker.seen == [["alpha owner is <EMAIL_ADDRESS>"]]
    assert results.chunks[0].text == "alpha owner is <EMAIL_ADDRESS>"
    assert "alice@example.com" not in results.chunks[0].text


def test_ingestion_redacts_before_embedding_but_stores_the_written_chunk() -> None:
    client = QdrantClient(location=":memory:")
    embedder = FakeEmbedder()

    ingest.ingest(
        client,
        tenant="lab-a",
        documents=[ingest.Document(source_uri="fs:contact", content="alpha alice@example.com")],
        embedder=embedder,
        redact=lambda text: text.replace("alice@example.com", "<EMAIL_ADDRESS>"),
    )

    assert embedder.seen == [["alpha <EMAIL_ADDRESS>"]]
    stored = client.scroll(ingest.collection_name("lab-a"), limit=10, with_payload=True)[0]
    assert stored[0].payload is not None
    assert stored[0].payload["text"] == "alpha alice@example.com"


def test_a_reranker_failure_refuses_the_query() -> None:
    class Broken:
        def rerank(
            self, query: str, texts: Sequence[str], *, top_n: int
        ) -> list[tuple[int, float]]:
            raise RetrievalUnavailable("no reranker")

    client = QdrantClient(location=":memory:")
    _ingest(client, "lab-a", "runbook", "alpha runbook")

    with pytest.raises(RetrievalUnavailable):
        query.search(client, _request("lab-a"), FakeEmbedder(), Broken())


class _Reply:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def test_embedding_vectors_are_reordered_by_index() -> None:
    embedder = OmniRouteEmbedder(
        base_url="http://gateway/v1",
        api_key="k",
        model="embed",
        opener=lambda request, timeout=None: _Reply(
            {"data": [{"index": 1, "embedding": [0.0, 2.0]}, {"index": 0, "embedding": [1.0]}]}
        ),
    )

    assert embedder.embed(["a", "b"]) == [[1.0], [0.0, 2.0]]


def test_embedding_refuses_a_wrong_count_or_missing_model() -> None:
    embedder = OmniRouteEmbedder(
        base_url="http://gateway",
        api_key="k",
        model="embed",
        opener=lambda request, timeout=None: _Reply({"data": []}),
    )
    with pytest.raises(RetrievalUnavailable, match="wrong number"):
        embedder.embed(["a"])

    with pytest.raises(RetrievalUnavailable, match="CITADEL_EMBEDDING_MODEL"):
        OmniRouteEmbedder(base_url="http://gateway", api_key="k", model="").embed(["a"])


def test_the_reranker_refuses_an_index_outside_the_candidates() -> None:
    reranker = TeiReranker(
        "http://reranker", opener=lambda request, timeout=None: _Reply([{"index": 5, "score": 1}])
    )

    with pytest.raises(RetrievalUnavailable, match="outside"):
        reranker.rerank("q", ["one"], top_n=1)


class FakeAudit:
    def __init__(self) -> None:
        self.rows: list[tuple[Any, ...]] = []

    def append(self, **kwargs: Any) -> SimpleNamespace:
        audit_id = f"audit-{len(self.rows) + 1}"
        self.rows.append((audit_id, kwargs["event_type"], kwargs["payload"]))
        return SimpleNamespace(audit_id=audit_id)


def _activity(client: QdrantClient, audit: FakeAudit) -> RetrievalActivities:
    return RetrievalActivities(
        audit=audit,  # type: ignore[arg-type]
        client=client,
        embedder=FakeEmbedder(),
        reranker=FakeReranker(),
        analyzer_url="http://presidio",
    )


def _run_start() -> tuple[Any, ...]:
    return (
        "audit-start",
        "run.start",
        {
            "run_id": "run-1",
            "tenant_id": "lab-a",
            "user_id": "user-alice",
            "agent_id": "docker",
            "prompt_pack_version": "docker-1.0.0",
            "model_alias": "auto/best-fast",
            "risk_tier": "T0",
        },
    )


def _run_end(citation_ids: list[str]) -> tuple[Any, ...]:
    return (
        "audit-end",
        "run.end",
        {
            "run_id": "run-1",
            "outcome": "completed",
            "citation_ids": citation_ids,
            "safety_flags": [],
        },
    )


def _trajectory(audit: FakeAudit, outcome: Any) -> list[dict[str, Any]]:
    citation_ids = [item["chunk_id"] for item in outcome.citations]
    return rows_to_events([_run_start(), *audit.rows, _run_end(citation_ids)])


def _citation_case(events: list[dict[str, Any]], *, minimum: int, sources: list[str]) -> Case:
    return Case(
        id="retrieval",
        version=1,
        tenant="lab-a",
        prompt="where is the checkout runbook",
        expectations={"min_citations": minimum, "required_citation_sources": sources},
        events=events,
    )


def _event(events: list[dict[str, Any]], event_type: str) -> dict[str, Any]:
    return next(event for event in events if event["type"] == event_type)


def _retrieved_run(client: QdrantClient, audit: FakeAudit) -> Any:
    return _activity(client, audit).retrieve(
        RetrievalRequest(
            run_id="run-1",
            tenant_id="lab-a",
            user_id="user-alice",
            agent_id="docker",
            query="alpha",
        )
    )


def _assert_exports(events: list[dict[str, Any]]) -> None:
    assert not check_events(events, tenant="lab-a")
    result_event = _event(events, "retrieval.result")
    assert "text" not in result_event
    assert result_event["source_uris"] == ["fs:runbooks/checkout-api.md"]
    query_event = _event(events, "retrieval.query")
    assert query_event["audit_id"] == "audit-1"
    assert "alpha" not in json.dumps(query_event)


def test_a_retrieval_run_exports_schema_valid_events_and_grades_citations(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dlp, "urlopen", lambda request, timeout=None: _Reply([]))
    client = QdrantClient(location=":memory:")
    _ingest(client, "lab-a", "runbooks/checkout-api.md", "alpha checkout runbook")
    audit = FakeAudit()
    outcome = _retrieved_run(client, audit)
    assert outcome.status == "answered"
    assert outcome.chunks[0]["text"] == "alpha checkout runbook"

    events = _trajectory(audit, outcome)
    _assert_exports(events)
    case = _citation_case(events, minimum=1, sources=["fs:runbooks/checkout-api.md"])
    assert [item for item in grade(case) if not item.passed] == []


def test_the_citation_grader_fails_an_unsupported_source() -> None:
    events = rows_to_events(
        [
            _run_start(),
            (
                "audit-result",
                "retrieval.result",
                {
                    "run_id": "run-1",
                    "chunk_ids": ["chunk-1"],
                    "source_uris": ["runbooks/other.md"],
                    "revisions": ["r1"],
                    "scores": [0.4],
                },
            ),
            _run_end([]),
        ]
    )
    case = _citation_case(events, minimum=1, sources=["runbooks/checkout-api.md"])

    failed = [item for item in grade(case) if not item.passed]
    assert failed and "required source" in failed[0].detail
