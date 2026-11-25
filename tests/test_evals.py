"""Offline eval harness: the golden set passes and every hard grader can fail."""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from citadel.evals.graders import grade
from citadel.evals.runner import main
from citadel.evals.schema import Case, DatasetError, check_events, load_cases

GOLDEN = Path(__file__).resolve().parents[1] / "evals" / "golden" / "golden.json"


def _cases() -> list[Case]:
    return load_cases(GOLDEN)


def _case(case_id: str) -> Case:
    return next(case for case in _cases() if case.id == case_id)


def _mutate(case: Case, change: Callable[[list[dict[str, Any]]], None]) -> Case:
    events: list[dict[str, Any]] = json.loads(json.dumps(case.events))
    change(events)
    return Case(
        id=case.id,
        version=case.version,
        tenant=case.tenant,
        prompt=case.prompt,
        expectations=case.expectations,
        events=events,
        adversarial=case.adversarial,
    )


def _failed(case: Case) -> set[str]:
    return {item.grader for item in grade(case) if not item.passed}


def test_golden_dataset_has_at_least_twelve_cases_and_all_pass() -> None:
    cases = _cases()
    assert len(cases) >= 12
    assert {item.grader for item in grade(cases[0])}
    for case in cases:
        failed = _failed(case)
        assert not failed, f"{case.id} failed {sorted(failed)}"


def test_unknown_event_type_is_rejected() -> None:
    case = _case("devops-001")
    events = [*case.events, {"type": "made.up", "run_id": case.events[0]["run_id"]}]
    problems = check_events(events, tenant=case.tenant)
    assert any("unknown or missing type" in problem for problem in problems)


def test_cross_tenant_event_is_rejected() -> None:
    case = _case("devops-001")
    events = [dict(event) for event in case.events]
    events[0]["tenant_id"] = "lab-z"
    problems = check_events(events, tenant=case.tenant)
    assert any("is not 'lab-a'" in problem for problem in problems)


def test_two_run_ids_are_rejected() -> None:
    case = _case("devops-001")
    events = [dict(event) for event in case.events]
    events[1]["run_id"] = "run-other"
    problems = check_events(events, tenant=case.tenant)
    assert any("mixes run ids" in problem for problem in problems)


def test_forbidden_tool_fails_tool_selection() -> None:
    def add_delete(events: list[dict[str, Any]]) -> None:
        events.append(
            {
                "type": "tool.call",
                "run_id": events[0]["run_id"],
                "tool": "delete_volume",
                "tier": "T2",
                "args_hash": "sha256:args-x",
                "idempotency_key": "run:delete_volume:sha256:args-x",
                "status": "executed",
                "duration": 5,
                "audit_id": "audit-tool-x",
            }
        )

    assert "tool.selection" in _failed(_mutate(_case("devops-001"), add_delete))


def test_out_of_order_tools_fail_sequence() -> None:
    def swap(events: list[dict[str, Any]]) -> None:
        positions = [i for i, event in enumerate(events) if event.get("type") == "tool.call"]
        first, second = positions
        events[first], events[second] = events[second], events[first]

    assert "tool.sequence" in _failed(_mutate(_case("devops-001"), swap))


def test_execution_after_policy_deny_fails() -> None:
    def deny(events: list[dict[str, Any]]) -> None:
        decision = next(
            event
            for event in events
            if event.get("type") == "policy.decision" and event.get("tool") == "inspect_containers"
        )
        decision["decision"] = "deny"

    assert "policy.before_execution" in _failed(_mutate(_case("devops-001"), deny))


def test_t1_execution_without_approval_fails() -> None:
    def drop_approval(events: list[dict[str, Any]]) -> None:
        events.remove(next(event for event in events if event.get("type") == "approval.decision"))

    assert "approval.before_t1" in _failed(_mutate(_case("devops-002"), drop_approval))


def test_execution_after_dlp_block_fails() -> None:
    def execute(events: list[dict[str, Any]]) -> None:
        call = next(event for event in events if event.get("type") == "tool.call")
        call["status"] = "executed"

    assert "dlp.before_effect" in _failed(_mutate(_case("devops-006"), execute))


def test_idempotency_key_drift_fails() -> None:
    def drift(events: list[dict[str, Any]]) -> None:
        second = [index for index, event in enumerate(events) if event.get("type") == "tool.call"][
            1
        ]
        events[second]["idempotency_key"] = "changed"

    assert "idempotency.stable" in _failed(_mutate(_case("devops-008"), drift))


def test_missing_citations_fail() -> None:
    def drop(events: list[dict[str, Any]]) -> None:
        end = next(event for event in events if event.get("type") == "run.end")
        end["citation_ids"] = []

    assert "citation.supported" in _failed(_mutate(_case("devops-001"), drop))


def test_risk_ceiling_is_enforced() -> None:
    def escalate(events: list[dict[str, Any]]) -> None:
        events[0]["risk_tier"] = "T1"

    assert "risk.ceiling" in _failed(_mutate(_case("devops-001"), escalate))


def test_injection_that_reaches_a_writer_fails() -> None:
    def promote(events: list[dict[str, Any]]) -> None:
        call = next(event for event in events if event.get("type") == "tool.call")
        call["tier"] = "T1"

    assert "adversarial.injection" in _failed(_mutate(_case("devops-007"), promote))


def test_unknown_expectation_key_is_rejected(tmp_path: Path) -> None:
    raw: Any = json.loads(GOLDEN.read_text())
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["expectations"]["forbiden_tools"] = []
    path = tmp_path / "typo.json"
    path.write_text(json.dumps(raw))

    with pytest.raises(DatasetError, match="unknown expectation keys"):
        load_cases(path)


def test_cli_exits_nonzero_on_a_failing_trajectory(tmp_path: Path) -> None:
    raw: Any = json.loads(GOLDEN.read_text())
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["events"].append(
        {
            "type": "tool.call",
            "run_id": "run-devops-001",
            "tool": "restart_service",
            "tier": "T1",
            "args_hash": "sha256:args-x",
            "idempotency_key": "run-devops-001:restart_service:sha256:args-x",
            "status": "executed",
            "duration": 5,
            "audit_id": "audit-tool-x",
        }
    )
    path = tmp_path / "failing.json"
    path.write_text(json.dumps(raw))

    assert main([str(path)]) == 1
