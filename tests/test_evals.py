"""Offline eval harness: the golden set passes and every hard grader can fail."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from citadel.evals.graders import Grade, grade
from citadel.evals.runner import main
from citadel.evals.schema import (
    EVENT_TEXT_LIMIT,
    Case,
    DatasetError,
    check_events,
    load_cases,
)

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


def _citation_grade(case: Case) -> Grade:
    return next(item for item in grade(case) if item.grader == "citation.supported")


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


def test_an_argument_value_mismatch_fails_with_both_values() -> None:
    def slow_restart(events: list[dict[str, Any]]) -> None:
        call = next(event for event in events if event.get("type") == "tool.call")
        call["arguments"]["timeout"] = 600

    verdict = next(
        item
        for item in grade(_mutate(_case("devops-002"), slow_restart))
        if item.grader == "tool.arguments"
    )
    assert not verdict.passed
    assert "60" in verdict.detail, "the expectation must be visible in the failure"
    assert "600" in verdict.detail, "the actual value must be visible in the failure"


def test_an_assertion_on_arguments_a_record_does_not_carry_fails() -> None:
    def drop_values(events: list[dict[str, Any]]) -> None:
        call = next(event for event in events if event.get("type") == "tool.call")
        del call["arguments"]

    assert "tool.arguments" in _failed(_mutate(_case("devops-002"), drop_values))


def test_a_malformed_expected_arguments_entry_is_rejected(tmp_path: Path) -> None:
    raw: Any = json.loads(GOLDEN.read_text())
    raw["cases"] = [raw["cases"][1]]
    raw["cases"][0]["expectations"]["expected_arguments"] = [{"tool": "restart_service"}]
    path = tmp_path / "bad-arguments.json"
    path.write_text(json.dumps(raw))

    with pytest.raises(DatasetError, match="expected_arguments"):
        load_cases(path)


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


def test_an_operational_claim_without_a_citation_fails_with_the_claim() -> None:
    case = replace(
        _case("devops-001"),
        answer="checkout-api is unhealthy and the container is running.",
    )

    verdict = _citation_grade(case)

    assert not verdict.passed
    assert "checkout-api is unhealthy" in verdict.detail, "the claim must be visible"


def test_a_citation_that_names_no_retrieved_chunk_fails_with_the_source() -> None:
    case = replace(
        _case("devops-001"),
        answer="checkout-api is unhealthy; see runbooks/missing.md.",
    )

    verdict = _citation_grade(case)

    assert not verdict.passed
    assert "runbooks/missing.md" in verdict.detail, "the bad source must be visible"
    assert "checkout-api is unhealthy" in verdict.detail, "the claim must be visible"


def test_a_scheme_prefixed_source_uri_counts_as_a_citation() -> None:
    """Ingested sources are `fs:`/`gh:` URIs, so a verbatim copy must resolve."""

    def add_scheme(events: list[dict[str, Any]]) -> None:
        result = next(event for event in events if event["type"] == "retrieval.result")
        result["source_uris"] = [
            *(f"fs:{source}" for source in result["source_uris"]),
            "fs:checkout-api.md",
        ]
        end = next(event for event in events if event["type"] == "run.end")
        end["citation_ids"] = [
            f"fs:{citation}" if "/" in citation else citation for citation in end["citation_ids"]
        ]

    case = _mutate(_case("devops-001"), add_scheme)
    case = replace(
        case,
        # One scheme with a path, one at the root: the second has no slash to match.
        answer="checkout-api is unhealthy; see fs:runbooks/checkout-api.md and fs:checkout-api.md.",
        expectations={**case.expectations, "required_citation_sources": []},
    )

    assert _citation_grade(case).passed


def test_a_bare_uuid_chunk_id_counts_as_a_citation() -> None:
    """Qdrant point ids are UUIDs; a model copying one verbatim must resolve."""
    chunk_id = "8506d70c-59d5-5c43-baf3-3d7d895f7ff3"

    def use_uuid(events: list[dict[str, Any]]) -> None:
        result = next(event for event in events if event["type"] == "retrieval.result")
        result["chunk_ids"] = [chunk_id]
        end = next(event for event in events if event["type"] == "run.end")
        end["citation_ids"] = [chunk_id]

    case = _mutate(_case("devops-001"), use_uuid)
    case = replace(
        case,
        answer=f"checkout-api is unhealthy; see {chunk_id}.",
        expectations={
            **case.expectations,
            "min_citations": 1,
            "required_citation_sources": [],
        },
    )

    assert _citation_grade(case).passed


def test_a_run_end_citation_that_names_nothing_retrieved_fails() -> None:
    def add_bad_citation(events: list[dict[str, Any]]) -> None:
        end = next(event for event in events if event["type"] == "run.end")
        end["citation_ids"].append("chunk-missing")

    verdict = _citation_grade(_mutate(_case("devops-011"), add_bad_citation))

    assert not verdict.passed
    assert "chunk-missing" in verdict.detail


def test_general_reasoning_needs_no_citation() -> None:
    case = replace(_case("devops-001"), answer="Both sources agree on this point.")

    assert _citation_grade(case).passed


def test_the_cli_fails_an_uncited_claim(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    raw: Any = json.loads(GOLDEN.read_text())
    raw["cases"] = [raw["cases"][0]]
    raw["cases"][0]["answer"] = "checkout-api is unhealthy."
    path = tmp_path / "uncited.json"
    path.write_text(json.dumps(raw))

    assert main([str(path)]) == 1
    assert "operational claim" in capsys.readouterr().out


def test_a_recorded_output_has_to_be_an_object() -> None:
    """A bare string is not an answer a grader can assert on."""
    case = _case("devops-001")
    events = [dict(event) for event in case.events]
    call = next(event for event in events if event["type"] == "tool.call")
    call["output"] = "a bare string"

    problems = check_events(events, tenant=case.tenant)
    assert any("output must be an object" in problem for problem in problems)


def test_an_output_over_the_cap_is_refused_not_truncated_silently() -> None:
    """A trajectory carrying more than the cap is a writer bug, not a large answer."""
    case = _case("devops-001")
    events = [dict(event) for event in case.events]
    call = next(event for event in events if event["type"] == "tool.call")
    call["output"] = {"stdout": "x" * (EVENT_TEXT_LIMIT + 1)}

    problems = check_events(events, tenant=case.tenant)
    assert any("over the" in problem and "cap" in problem for problem in problems)


def test_output_and_a_marker_cannot_both_be_set() -> None:
    """The record says the answer is there, or says why it is not - not both."""
    case = _case("devops-001")
    events = [dict(event) for event in case.events]
    call = next(event for event in events if event["type"] == "tool.call")
    call["output"] = {"ok": 1}
    call["output_redacted"] = True

    problems = check_events(events, tenant=case.tenant)
    assert any("cannot both be set" in problem for problem in problems)
