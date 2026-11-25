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
