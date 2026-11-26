"""The recorder maps audit rows into a gradable trajectory, fail-closed."""

from __future__ import annotations

from typing import Any

from citadel.evals.graders import grade
from citadel.evals.recorder import main, rows_to_events
from citadel.evals.schema import Case, check_events

RUN_ID = "11111111-1111-1111-1111-111111111111"


def _rows() -> list[tuple[Any, ...]]:
    return [
        (
            "audit-1",
            "run.start",
            {
                "run_id": RUN_ID,
                "tenant_id": "lab-a",
                "user_id": "user-alice",
                "agent_id": "docker",
                "prompt_pack_version": "docker-1.0.0",
                "model_alias": "auto/best-fast",
                "risk_tier": "T0",
            },
        ),
        (
            "audit-2",
            "policy.decision",
            {
                "run_id": RUN_ID,
                "subject": "user-alice",
                "tool": "read_logs",
                "args_hash": "sha256:args",
                "decision": "allow",
                "rule_id": "policy.allowed",
                "tier": "T0",
            },
        ),
        (
            "audit-3",
            "tool.call",
            {
                "run_id": RUN_ID,
                "tool": "read_logs",
                "tier": "T0",
                "args_hash": "sha256:args",
                "idempotency_key": f"{RUN_ID}:read_logs:sha256:args",
                "status": "executed",
                "duration": 12,
            },
        ),
        (
            "audit-4",
            "run.end",
            {"run_id": RUN_ID, "outcome": "completed", "citation_ids": [], "safety_flags": []},
        ),
        ("audit-5", "session.note", {"run_id": RUN_ID, "text": "not a trajectory span"}),
    ]


def _case(events: list[dict[str, Any]]) -> Case:
    return Case(
        id="recorded",
        version=1,
        tenant="lab-a",
        prompt="recorded run",
        expectations={
            "allowed_tools": ["read_logs"],
            "forbidden_tools": ["delete_volume"],
            "required_tool_sequence": ["read_logs"],
            "max_risk_tier": "T0",
            "expected_outcome": "completed",
        },
        events=events,
    )


def _model_payload(**overrides: Any) -> dict[str, Any]:
    """The shape `ModelActivities._record` writes, success and refusal alike."""
    payload: dict[str, Any] = {
        "run_id": RUN_ID,
        "alias": "auto/best-fast",
        "provider": "omniroute",
        "model": "auto",
        "input_hash": "sha256:in",
        "output_hash": "sha256:out",
        "tokens": 120,
        "cost": None,
        "latency": 640,
        "cost_source": "unreported",
    }
    payload.update(overrides)
    return payload


def _with_model(payload: dict[str, Any]) -> list[tuple[Any, ...]]:
    rows = _rows()
    return [*rows[:1], ("audit-model", "model.call", payload), *rows[1:]]


def test_a_model_call_row_becomes_a_schema_valid_event() -> None:
    """The producer exists; the witness is that the recorder keeps its fields."""
    events = rows_to_events(_with_model(_model_payload()))

    call = next(event for event in events if event["type"] == "model.call")
    assert call["audit_id"] == "audit-model"
    assert (call["model"], call["tokens"], call["latency"]) == ("auto", 120, 640)
    # An unreported cost stays absent, never a zero the grader would trust.
    assert call["cost"] is None
    assert not check_events(events, tenant="lab-a")


def test_a_refused_model_call_exports_with_what_was_attempted() -> None:
    refusal = _model_payload(
        tokens=0,
        latency=0,
        output_hash="",
        status="refused",
        rule_id="pack.unavailable",
        detail="prompt pack could not be loaded",
    )

    events = rows_to_events(_with_model(refusal))

    call = next(event for event in events if event["type"] == "model.call")
    assert (call["status"], call["rule_id"]) == ("refused", "pack.unavailable")
    assert call["tokens"] == 0
    assert not check_events(events, tenant="lab-a")


def test_a_model_call_row_missing_a_field_is_refused_not_graded() -> None:
    incomplete = _model_payload()
    del incomplete["alias"]

    problems = check_events(rows_to_events(_with_model(incomplete)), tenant="lab-a")

    assert any("model.call: missing alias" in problem for problem in problems)


def test_audit_rows_become_a_gradable_trajectory() -> None:
    events = rows_to_events(_rows())

    assert [event["type"] for event in events] == [
        "run.start",
        "policy.decision",
        "tool.call",
        "run.end",
    ]
    assert events[1]["audit_id"] == "audit-2"
    assert events[2]["audit_id"] == "audit-3"
    assert not [item for item in grade(_case(events)) if not item.passed]


def test_audit_only_events_are_skipped() -> None:
    events = rows_to_events(_rows())
    assert "session.note" not in [event["type"] for event in events]


def test_missing_run_end_is_rejected() -> None:
    events = rows_to_events([row for row in _rows() if row[1] != "run.end"])
    problems = check_events(events, tenant="lab-a")
    assert any("exactly one run.end" in problem for problem in problems)


def test_export_without_a_dsn_fails() -> None:
    assert main(["--tenant", "lab-a", "--run", RUN_ID, "--dsn", ""]) == 2
