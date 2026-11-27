"""The run's retrieval caller: one search, both events, evidence in the context.

Temporal's time-skipping environment runs the real workflow and the real
retrieval activity, with only the Qdrant client, the embedder, the reranker and
the model step stubbed. That is the boundary the v0.2 exit review D1 was missing.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace
from typing import Any

import pytest
from qdrant_client import QdrantClient
from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from citadel import dlp
from citadel.evals.graders import grade
from citadel.evals.recorder import rows_to_events
from citadel.evals.schema import Case, check_events
from citadel.retrieval import ingest
from citadel.retrieval.activities import RetrievalActivities
from citadel.workflows.model_step import ModelStepRequest, ModelStepResult
from citadel.workflows.orchestrator import RunWorkflow
from citadel.workflows.types import RunEnd, RunInput, ToolResult

QUEUE = "orchestrator"
TENANTS = ("lab-a", "lab-b", "lab-c")


def _vector(text: str) -> list[float]:
    words = ["alpha", "beta", "gamma"]
    return [1.0 if word in text.lower() else 0.0 for word in words]


class FakeEmbedder:
    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        return [_vector(text) for text in texts]


class FakeReranker:
    def rerank(self, query: str, texts: Sequence[str], *, top_n: int) -> list[tuple[int, float]]:
        return [(index, 0.5 + index / 100) for index in range(len(texts))][:top_n]


class FakeAudit:
    """The activity's only audit dependency: append and hand back an id."""

    def __init__(self) -> None:
        self.rows: list[tuple[Any, ...]] = []

    def append(self, **kwargs: Any) -> SimpleNamespace:
        audit_id = f"audit-{len(self.rows) + 1}"
        self.rows.append((audit_id, kwargs["event_type"], kwargs["payload"]))
        return SimpleNamespace(audit_id=audit_id)


class _Reply:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _ingest(client: QdrantClient, tenant: str, text: str) -> None:
    ingest.ingest(
        client,
        tenant=tenant,
        documents=[ingest.Document(source_uri=f"fs:{tenant}/runbook.md", content=text)],
        embedder=FakeEmbedder(),
    )


def _input(tenant: str) -> RunInput:
    return RunInput(
        run_id=f"run-{tenant}",
        tenant_id=tenant,
        user_id="user-alice",
        agent_id="docker",
        tool="",
        task="alpha checkout runbook",
        max_steps=1,
        entitlements=["viewer"],
    )


async def _run(
    client: QdrantClient, audit: FakeAudit, tenant: str
) -> tuple[ToolResult, list[ModelStepRequest], list[RunEnd]]:
    requests: list[ModelStepRequest] = []
    ends: list[RunEnd] = []
    retrieval = RetrievalActivities(
        audit=audit,  # type: ignore[arg-type]
        client=client,
        embedder=FakeEmbedder(),
        reranker=FakeReranker(),
        analyzer_url="http://presidio",
    )

    @activity.defn(name="next_step")
    def stub_next_step(request: ModelStepRequest) -> ModelStepResult:
        requests.append(request)
        return ModelStepResult(
            status="answered",
            rule_id="model.answered",
            detail="answered",
            content=f"checkout-api restarted; see fs:{tenant}/runbook.md",
            prompt_digest="d" * 64,
            prompt_pack="docker-1.0.0",
        )

    @activity.defn(name="finish_run")
    def stub_finish_run(end: RunEnd) -> None:
        ends.append(end)

    env = await WorkflowEnvironment.start_time_skipping()
    executor = ThreadPoolExecutor(max_workers=4)
    try:
        async with Worker(
            env.client,
            task_queue=QUEUE,
            workflows=[RunWorkflow],
            activities=[retrieval.retrieve, stub_next_step, stub_finish_run],
            activity_executor=executor,
        ):
            handle = await env.client.start_workflow(
                RunWorkflow.run, _input(tenant), id=f"run-{tenant}", task_queue=QUEUE
            )
            result: ToolResult = await handle.result()
            return result, requests, ends
    finally:
        executor.shutdown(wait=False)
        await env.shutdown()


def _events(tenant: str, audit: FakeAudit, end: RunEnd) -> list[dict[str, Any]]:
    return rows_to_events(
        [
            (
                "audit-start",
                "run.start",
                {
                    "run_id": end.run_id,
                    "tenant_id": tenant,
                    "user_id": "user-alice",
                    "agent_id": "docker",
                    "prompt_pack_version": "docker-1.0.0",
                    "model_alias": "auto/best-fast",
                    "risk_tier": "T0",
                },
            ),
            *audit.rows,
            (
                "audit-end",
                "run.end",
                {
                    "run_id": end.run_id,
                    "outcome": end.outcome,
                    "citation_ids": end.citation_ids,
                    "safety_flags": end.safety_flags,
                },
            ),
        ]
    )


def test_a_task_run_retrieves_evidence_and_records_both_events(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dlp, "urlopen", lambda request, timeout=None: _Reply([]))
    client = QdrantClient(location=":memory:")
    _ingest(client, "lab-a", "alpha checkout runbook")
    audit = FakeAudit()

    result, requests, ends = asyncio.run(_run(client, audit, "lab-a"))

    assert (result.status, result.rule_id) == ("executed", "model.answered")
    assert len(requests) == 1
    assert "fs:lab-a/runbook.md" in requests[0].task
    assert "alpha checkout runbook" in requests[0].task
    assert ends[0].citation_ids, "run.end has to carry the retrieved chunk ids"

    events = _events("lab-a", audit, ends[0])
    assert not check_events(events, tenant="lab-a")
    query_event = next(event for event in events if event["type"] == "retrieval.query")
    result_event = next(event for event in events if event["type"] == "retrieval.result")
    assert query_event["collection"] == ingest.collection_name("lab-a")
    assert query_event["filter_set_hash"].startswith("sha256:")
    assert result_event["chunk_ids"] == ends[0].citation_ids
    assert result_event["source_uris"] == ["fs:lab-a/runbook.md"]
    assert "text" not in result_event, "the result event carries metadata, not the chunk"

    case = Case(
        id="retrieval-caller",
        version=1,
        tenant="lab-a",
        prompt="where is the checkout runbook",
        expectations={
            "min_citations": 1,
            "required_citation_sources": ["fs:lab-a/runbook.md"],
        },
        events=events,
        answer=result.output["answer"],
    )
    assert [item for item in grade(case) if not item.passed] == []


def test_every_tenant_pairing_only_sees_its_own_chunk(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(dlp, "urlopen", lambda request, timeout=None: _Reply([]))
    client = QdrantClient(location=":memory:")
    for tenant in TENANTS:
        _ingest(client, tenant, "alpha checkout runbook")

    for reader in TENANTS:
        audit = FakeAudit()
        result, requests, ends = asyncio.run(_run(client, audit, reader))

        assert result.status == "executed"
        assert requests[0].task.count("fs:") == 1, "one evidence block, one source"
        for writer in TENANTS:
            if writer != reader:
                assert f"fs:{writer}/runbook.md" not in requests[0].task
        sources = [
            source
            for event in _events(reader, audit, ends[0])
            if event["type"] == "retrieval.result"
            for source in event["source_uris"]
        ]
        assert sources == [f"fs:{reader}/runbook.md"]
