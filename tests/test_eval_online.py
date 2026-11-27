"""Sampling, redaction and the export shape, without MLflow and without a model."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import pytest

from citadel.dlp import DlpBlocked
from citadel.evals import online
from citadel.evals.schema import check_events

TENANT = "lab-a"
RUN = "7b1f3d2e-0000-4000-8000-000000000001"
ARGS_HASH = "c" * 64
BASE = "http://mlflow:5000"


def _events(**answer: Any) -> list[dict[str, Any]]:
    return [
        {
            "type": "run.start",
            "run_id": RUN,
            "tenant_id": TENANT,
            "user_id": "u-1",
            "agent_id": "devops",
            "prompt_pack_version": "devops-3",
            "model_alias": "auto/best-fast",
            "risk_tier": "T1",
        },
        {
            "type": "model.call",
            "run_id": RUN,
            "alias": "auto/best-fast",
            "provider": "openrouter",
            "model": "vendor/model",
            "input_hash": "a" * 64,
            "output_hash": "b" * 64,
            "tokens": 100,
            "cost": 0.02,
            "latency": 900,
            "audit_id": "audit-1",
        },
        {
            "type": "policy.decision",
            "run_id": RUN,
            "subject": "agent:devops",
            "tool": "read_logs",
            "args_hash": ARGS_HASH,
            "decision": "allow",
            "rule_id": "read-only-tools",
            "audit_id": "audit-0",
        },
        {
            "type": "tool.call",
            "run_id": RUN,
            "tool": "read_logs",
            "tier": "T0",
            "args_hash": ARGS_HASH,
            "idempotency_key": "idem-1",
            "status": "ok",
            "duration": 120,
            "audit_id": "audit-2",
            "output": {"lines": ["container started", "healthcheck ok"]},
        },
        {
            "type": "run.end",
            "run_id": RUN,
            "outcome": "succeeded",
            "citation_ids": [],
            "safety_flags": [],
            "answer": "The container is healthy.",
            **answer,
        },
    ]


def _pass_through(text: str) -> tuple[str, dict[str, Any]]:
    return text, {"surface": "record", "action": "pass"}


def _meta() -> online.Meta:
    return online.Meta(
        model_alias="auto/best-fast",
        prompt_pack_version="devops-3",
        dataset_version=4,
        judge=("groundedness",),
    )


def _sample(*, rate: float = 1.0, taken: int = 0, **answer: Any) -> online.Sample:
    return online.Sample(
        events=_events(**answer),
        tenant_id=TENANT,
        run_id=RUN,
        meta=_meta(),
        policy=online.Policy(rate=rate, cap=10, day="2026-11-27"),
        taken=taken,
    )


def _endpoint(dataset_id: str | None = None) -> online.Endpoint:
    return online.Endpoint(tracking_uri=BASE, experiment_id="1", dataset_id=dataset_id)


def test_the_draw_is_stable_and_bounded() -> None:
    first = online.bucket(RUN, TENANT)
    assert first == online.bucket(RUN, TENANT)
    assert 0.0 <= first < 1.0
    assert online.bucket(RUN, "lab-b") != first


def test_an_unset_rate_samples_nothing() -> None:
    policy = online.Policy(rate=0.0, cap=100, day="2026-11-27")
    assert not policy.admits(run_id=RUN, tenant_id=TENANT, taken=0)


def test_the_cap_bounds_a_bad_day() -> None:
    policy = online.Policy(rate=1.0, cap=2, day="2026-11-27")
    assert policy.admits(run_id=RUN, tenant_id=TENANT, taken=1)
    assert not policy.admits(run_id=RUN, tenant_id=TENANT, taken=2)


def test_a_full_rate_samples_every_run_and_the_draw_is_strictly_below() -> None:
    assert online.Policy(rate=1.0, cap=10, day="d").admits(run_id=RUN, tenant_id=TENANT, taken=0)
    draw = online.bucket(RUN, TENANT)
    exact = online.Policy(rate=draw, cap=10, day="d")
    assert not exact.admits(run_id=RUN, tenant_id=TENANT, taken=0)


def test_the_policy_reads_its_limits_from_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CITADEL_EVAL_SAMPLE_RATE", "0.25")
    monkeypatch.setenv("CITADEL_EVAL_SAMPLE_CAP", "7")
    policy = online.policy_from_env(datetime(2026, 11, 27, tzinfo=UTC))
    assert (policy.rate, policy.cap, policy.day) == (0.25, 7, "2026-11-27")


def test_a_nonsense_rate_falls_back_to_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CITADEL_EVAL_SAMPLE_RATE", "lots")
    assert online.policy_from_env().rate == 0.0


def test_the_record_carries_the_schema_and_the_comparison_metadata() -> None:
    record = online.build_record(_sample(), gate=_pass_through)

    assert check_events(record["outputs"]["trajectory"], tenant=TENANT) == []
    assert record["inputs"] == {
        "run_id": RUN,
        "tenant": TENANT,
        "model_alias": "auto/best-fast",
        "prompt_pack_version": "devops-3",
        "dataset_version": 4,
        "judge": ["groundedness"],
    }
    assert record["expectations"] == {}


def test_an_incomplete_trajectory_is_refused() -> None:
    sample = _sample()
    sample.events.pop()
    with pytest.raises(online.SampleRefused, match="exactly one run.end"):
        online.build_record(sample, gate=_pass_through)


def test_a_secret_refuses_the_whole_sample() -> None:
    """A block anywhere is a refusal: an eval row is not worth a leaked credential."""

    def blocked(text: str) -> tuple[str, dict[str, Any]]:
        report = {"surface": "record", "action": "block", "categories": ["SECRET"]}
        raise DlpBlocked("dlp_blocked", report)

    with pytest.raises(DlpBlocked):
        online.build_record(_sample(answer="my token is sk-live-123"), gate=blocked)


def test_pii_in_the_answer_is_redacted_in_place() -> None:
    def redacts(text: str) -> tuple[str, dict[str, Any]]:
        return text.replace("jane@example.com", "<EMAIL>"), {"action": "redact"}

    record = online.build_record(_sample(answer="write to jane@example.com"), gate=redacts)
    answer = record["outputs"]["trajectory"][-1]["answer"]
    assert answer == "write to <EMAIL>"
    assert "jane@example.com" not in json.dumps(record)


def test_a_tool_answer_that_cannot_survive_is_marked_not_dropped_in_silence() -> None:
    def breaks_the_json(text: str) -> tuple[str, dict[str, Any]]:
        return "<REDACTED BODY>", {"action": "redact"}

    record = online.build_record(_sample(), gate=breaks_the_json)
    tool = next(e for e in record["outputs"]["trajectory"] if e["type"] == "tool.call")

    assert "output" not in tool
    assert tool["output_redacted"] is True


def test_a_redacted_tool_answer_that_is_still_json_is_kept() -> None:
    def redacts_email(text: str) -> tuple[str, dict[str, Any]]:
        return text.replace("jane@example.com", "<EMAIL>"), {"action": "redact"}

    sample = _sample()
    next(e for e in sample.events if e["type"] == "tool.call")["output"] = {
        "contact": "jane@example.com"
    }
    record = online.build_record(sample, gate=redacts_email)
    tool = next(e for e in record["outputs"]["trajectory"] if e["type"] == "tool.call")

    assert tool["output"] == {"contact": "<EMAIL>"}
    assert "output_redacted" not in tool


def test_the_record_replays_through_the_offline_grader() -> None:
    """The acceptance: no agent, no MLflow, just the grader reading the row."""
    record = online.build_record(_sample(), gate=_pass_through)

    grades = online.replay(record)

    assert grades, "the grader produced nothing"
    assert {item.grader for item in grades} >= {"tool.selection", "citation.supported"}
    assert all(item.passed for item in grades), [item.detail for item in grades if not item.passed]


class _Reply:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _recording_opener(calls: list[tuple[str, dict[str, Any]]]) -> Any:
    def opener(request: Any, timeout: Any = None) -> _Reply:
        calls.append((request.full_url, json.loads(request.data)))
        if request.full_url.endswith("/datasets/create"):
            return _Reply({"dataset": {"dataset_id": "d-abc"}})
        return _Reply({"inserted_count": 1, "updated_count": 0})

    return opener


def test_the_first_push_creates_the_dataset_and_the_next_one_reuses_it() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    opener = _recording_opener(calls)
    record = online.build_record(_sample(), gate=_pass_through)

    first = online.push(record, endpoint=_endpoint(), opener=opener)
    second = online.push(record, endpoint=first, opener=opener)

    assert (first.dataset_id, second.dataset_id) == ("d-abc", "d-abc")
    creates = [url for url, _ in calls if url.endswith("/datasets/create")]
    assert len(creates) == 1, "the second push reuses the id the ledger recorded"
    merges = [body for url, body in calls if "/records" in url]
    assert isinstance(merges[0]["records"], str), "MLflow takes records as a JSON string"
    assert json.loads(merges[0]["records"])[0]["inputs"]["run_id"] == RUN


def test_merging_without_a_dataset_is_an_error() -> None:
    with pytest.raises(online.DatasetError, match="create one first"):
        online.merge_records({"inputs": {}}, endpoint=_endpoint(), opener=_recording_opener([]))


def test_a_rejected_merge_is_an_error_not_a_silent_no_op() -> None:
    endpoint = online.Endpoint(tracking_uri=BASE, experiment_id="1", dataset_id="d-abc")

    def refuses(request: Any, timeout: Any = None) -> _Reply:
        return _Reply({"inserted_count": 0, "updated_count": 0})

    with pytest.raises(online.DatasetError, match="accepted no record"):
        online.merge_records({"inputs": {}}, endpoint=endpoint, opener=refuses)


def test_a_write_failure_names_the_endpoint() -> None:
    def fails(request: Any, timeout: Any = None) -> _Reply:
        raise OSError("connection refused")

    with pytest.raises(online.DatasetError, match="datasets/create"):
        online.create_dataset(endpoint=_endpoint(), opener=fails)


def test_an_unsampled_run_never_reaches_the_dataset() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    outcome = online.offer(
        _sample(rate=0.0), endpoint=_endpoint(), gate=_pass_through, opener=_recording_opener(calls)
    )

    assert outcome is None
    assert calls == []


def test_a_sampled_run_returns_the_row_and_where_it_went() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    outcome = online.offer(
        _sample(), endpoint=_endpoint(), gate=_pass_through, opener=_recording_opener(calls)
    )

    assert outcome is not None
    record, used = outcome
    assert record["inputs"]["run_id"] == RUN
    assert used.dataset_id == "d-abc"


def test_the_dataset_id_is_recovered_from_the_ledger() -> None:
    """MLflow 3.18's search answers `{}`, so the id is remembered where runs are."""
    rows = [(7, {"dataset_id": "d-newest"}), (6, {"dataset_id": "d-older"})]
    assert online.dataset_id_from(rows) == "d-newest"
    assert online.dataset_id_from([]) is None
    assert online.dataset_id_from([(1, json.dumps({"dataset_id": "d-json"}))]) == "d-json"
