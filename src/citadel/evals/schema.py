"""Trajectory schema and golden-case loading.

Fail-closed: an unknown event type, a missing required field, two run ids or a
foreign tenant is an error, not a skipped check. An eval harness that quietly
ignores what it does not understand would pass a trajectory it never graded.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from citadel.tools.bounds import DEFAULT_EVENT_LIMIT

TIERS = {"T0": 0, "T1": 1, "T2": 2}

# The largest tool answer a trajectory may carry. Above it the run says so with
# `output_too_large` and keeps the digest, rather than pretending there was none.
EVENT_TEXT_LIMIT = DEFAULT_EVENT_LIMIT

# Required fields per docs/evals/trajectory-schema.md. Extra fields are allowed:
# the runtime adds context (for example the tool on a dlp.event).
EVENT_FIELDS: dict[str, frozenset[str]] = {
    "run.start": frozenset(
        {
            "run_id",
            "tenant_id",
            "user_id",
            "agent_id",
            "prompt_pack_version",
            "model_alias",
            "risk_tier",
        }
    ),
    "model.call": frozenset(
        {
            "run_id",
            "alias",
            "provider",
            "model",
            "input_hash",
            "output_hash",
            "tokens",
            "cost",
            "latency",
            "audit_id",
        }
    ),
    "retrieval.query": frozenset(
        {"run_id", "tenant_id", "filter_set_hash", "top_k", "collection", "audit_id"}
    ),
    "retrieval.result": frozenset({"run_id", "chunk_ids", "source_uris", "revisions", "scores"}),
    "policy.decision": frozenset(
        {"run_id", "subject", "tool", "args_hash", "decision", "rule_id", "audit_id"}
    ),
    "dlp.event": frozenset(
        {"run_id", "surface", "categories", "action", "detector_version", "audit_id"}
    ),
    "approval.decision": frozenset(
        {"run_id", "approver", "decision", "reason", "ttl", "rule_id", "audit_id"}
    ),
    "tool.call": frozenset(
        {
            "run_id",
            "tool",
            "tier",
            "args_hash",
            "idempotency_key",
            "status",
            "duration",
            "audit_id",
        }
    ),
    "recovery": frozenset({"run_id", "failed_step", "strategy", "outcome"}),
    "cache.lookup": frozenset(
        {"run_id", "decision", "partition_key", "prompt_digest", "score", "audit_id"}
    ),
    "run.end": frozenset({"run_id", "outcome", "citation_ids", "safety_flags"}),
}

_LIST_FIELDS = frozenset(
    {
        "chunk_ids",
        "source_uris",
        "revisions",
        "scores",
        "categories",
        "citation_ids",
        "safety_flags",
    }
)

_STRING_LIST_FIELDS = frozenset(
    {"chunk_ids", "source_uris", "categories", "citation_ids", "safety_flags"}
)

EXPECTATION_KEYS = frozenset(
    {
        "allowed_tools",
        "forbidden_tools",
        "expected_arguments",
        "required_tool_sequence",
        "min_citations",
        "required_citation_sources",
        "max_risk_tier",
        # Documented graders that need an expectation to assert against.
        "required_policy_rules",
        "required_dlp",
        "recovery",
        "expected_outcome",
    }
)

ADVERSARIAL_KEYS = frozenset({"injected_content", "expected_behavior"})


class DatasetError(ValueError):
    pass


@dataclass(frozen=True)
class Case:
    id: str
    version: int
    tenant: str
    prompt: str
    expectations: dict[str, Any]
    events: list[dict[str, Any]]
    adversarial: dict[str, Any] | None = None
    # The answer the run produced, when the record has one. Judged rubrics read
    # it; a case that asks for judging without it is a dataset error rather than
    # a rubric that silently scores nothing.
    answer: str = ""
    judge: tuple[str, ...] = ()


def _output_object_problems(where: str, output: object) -> list[str]:
    """An answer the record keeps is an object that fits: evidence, not a dump."""
    if output is None:
        return []
    if not isinstance(output, dict):
        return [f"{where} tool.call: output must be an object"]
    size = len(json.dumps(output, ensure_ascii=False).encode("utf-8"))
    if size > EVENT_TEXT_LIMIT:
        return [f"{where} tool.call: output is {size} bytes, over the {EVENT_TEXT_LIMIT} cap"]
    return []


def _output_marker_problems(where: str, event: dict[str, Any]) -> list[str]:
    """The record says the answer is there, or says why it is not - never both."""
    problems = [
        f"{where} tool.call: {name} must be a boolean"
        for name in ("output_redacted", "output_too_large")
        if name in event and not isinstance(event[name], bool)
    ]
    present = [name for name in ("output_redacted", "output_too_large") if event.get(name)]
    if event.get("output") is not None and present:
        problems.append(f"{where} tool.call: output and {present[0]} cannot both be set")
    return problems


def _tool_output_problems(where: str, event: dict[str, Any]) -> list[str]:
    return _output_object_problems(where, event.get("output")) + _output_marker_problems(
        where, event
    )


def check_events(raw: object, *, tenant: str) -> list[str]:
    """Return every violation of the trajectory schema; empty means valid."""
    if not isinstance(raw, list) or not raw:
        return ["trajectory must be a non-empty array of events"]

    problems: list[str] = []
    run_ids: set[str] = set()
    starts = 0
    ends = 0

    for index, item in enumerate(raw):
        where = f"event {index}"
        if not isinstance(item, dict):
            problems.append(f"{where}: not an object")
            continue
        event: dict[str, Any] = item
        event_type = event.get("type")
        if not isinstance(event_type, str) or event_type not in EVENT_FIELDS:
            problems.append(f"{where}: unknown or missing type {event_type!r}")
            continue
        if event_type == "run.start":
            starts += 1
        elif event_type == "run.end":
            ends += 1

        missing = sorted(EVENT_FIELDS[event_type] - set(event))
        if missing:
            problems.append(f"{where} {event_type}: missing {', '.join(missing)}")

        run_id = event.get("run_id")
        if isinstance(run_id, str) and run_id:
            run_ids.add(run_id)
        else:
            problems.append(f"{where} {event_type}: run_id must be a non-empty string")

        declared = event.get("tenant_id")
        if declared is not None and declared != tenant:
            problems.append(f"{where} {event_type}: tenant {declared!r} is not {tenant!r}")

        if "audit_id" in event:
            audit_id = event.get("audit_id")
            if not isinstance(audit_id, str) or not audit_id:
                problems.append(f"{where} {event_type}: audit_id must be a non-empty string")

        tier = event.get("tier")
        if "tier" in event and tier not in TIERS:
            problems.append(f"{where} {event_type}: unknown tier {tier!r}")

        if event_type == "tool.call":
            problems.extend(_tool_output_problems(where, event))

        for field in sorted(_LIST_FIELDS & set(event)):
            if not isinstance(event[field], list):
                problems.append(f"{where} {event_type}: {field} must be an array")
            elif field in _STRING_LIST_FIELDS and not all(
                isinstance(item, str) for item in event[field]
            ):
                problems.append(f"{where} {event_type}: {field} must contain strings")

    if starts != 1:
        problems.append(f"trajectory must contain exactly one run.start, found {starts}")
    if ends != 1:
        problems.append(f"trajectory must contain exactly one run.end, found {ends}")
    if len(run_ids) > 1:
        problems.append(f"trajectory mixes run ids: {sorted(run_ids)}")
    return problems


def load_cases(path: Path) -> list[Case]:
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        raise DatasetError(f"{path}: {exc}") from exc
    records = raw.get("cases") if isinstance(raw, dict) else None
    if not isinstance(records, list):
        raise DatasetError(f"{path}: expected an object with a 'cases' array")

    cases = [_case(record, path) for record in records]
    seen: set[str] = set()
    for case in cases:
        if case.id in seen:
            raise DatasetError(f"{path}: duplicate case id {case.id!r}")
        seen.add(case.id)
    return cases


def _case(record: object, source: Path) -> Case:
    if not isinstance(record, dict):
        raise DatasetError(f"{source}: every case must be an object")

    case_id = record.get("id")
    version = record.get("version")
    tenant = record.get("tenant")
    prompt = record.get("prompt")
    expectations = record.get("expectations")
    events = record.get("events")

    if not isinstance(case_id, str) or not case_id:
        raise DatasetError(f"{source}: case id must be a non-empty string")
    if not isinstance(version, int) or isinstance(version, bool):
        raise DatasetError(f"{source}: case {case_id!r}: version must be an integer")
    if not isinstance(tenant, str) or not tenant:
        raise DatasetError(f"{source}: case {case_id!r}: tenant must be a non-empty string")
    if not isinstance(prompt, str) or not prompt:
        raise DatasetError(f"{source}: case {case_id!r}: prompt must be a non-empty string")
    if not isinstance(expectations, dict):
        raise DatasetError(f"{source}: case {case_id!r}: expectations must be an object")

    unknown = sorted(set(expectations) - EXPECTATION_KEYS)
    if unknown:
        raise DatasetError(f"{source}: case {case_id!r}: unknown expectation keys {unknown}")
    _check_expectation_values(expectations, case_id, source)

    adversarial = record.get("adversarial")
    if adversarial is not None:
        if not isinstance(adversarial, dict):
            raise DatasetError(f"{source}: case {case_id!r}: adversarial must be an object")
        unknown = sorted(set(adversarial) - ADVERSARIAL_KEYS)
        if unknown:
            raise DatasetError(f"{source}: case {case_id!r}: unknown adversarial keys {unknown}")
        behavior = adversarial.get("expected_behavior")
        if behavior is not None and not isinstance(behavior, str):
            raise DatasetError(f"{source}: case {case_id!r}: expected_behavior must be a string")

    problems = check_events(events, tenant=tenant)
    if problems:
        raise DatasetError(f"{source}: case {case_id!r}: " + "; ".join(problems))

    answer = record.get("answer", "")
    if not isinstance(answer, str):
        raise DatasetError(f"{source}: case {case_id!r}: answer must be a string")
    judge = record.get("judge", [])
    if not isinstance(judge, list) or any(not isinstance(item, str) for item in judge):
        raise DatasetError(f"{source}: case {case_id!r}: judge must be an array of dimensions")
    if judge and not answer:
        # The judge grades an answer. Without one there is nothing to measure, and
        # a missing measurement must not read as a passed one.
        raise DatasetError(f"{source}: case {case_id!r}: judge dimensions need an answer")

    return Case(
        id=case_id,
        version=version,
        tenant=tenant,
        prompt=prompt,
        expectations=cast(dict[str, Any], expectations),
        events=cast(list[dict[str, Any]], events),
        adversarial=cast(dict[str, Any] | None, adversarial),
        answer=answer,
        judge=tuple(judge),
    )


def _check_expectation_values(expectations: dict[str, Any], case_id: str, source: Path) -> None:
    def fail(message: str) -> None:
        raise DatasetError(f"{source}: case {case_id!r}: {message}")

    for key in (
        "allowed_tools",
        "forbidden_tools",
        "required_tool_sequence",
        "required_citation_sources",
    ):
        if key in expectations and not _all_strings(expectations[key]):
            fail(f"{key} must be an array of strings")

    if "expected_arguments" in expectations:
        assertions = expectations["expected_arguments"]
        if not isinstance(assertions, list):
            fail("expected_arguments must be an array")
        for assertion in assertions:
            if not isinstance(assertion, dict):
                fail("each expected_arguments item must be an object")
            unknown = sorted(set(assertion) - {"tool", "arguments"})
            if unknown:
                fail(f"unknown expected_arguments keys {unknown}")
            if not isinstance(assertion.get("tool"), str):
                fail("each expected_arguments item needs a string tool")
            if not isinstance(assertion.get("arguments"), dict) or not assertion["arguments"]:
                fail("each expected_arguments item needs a non-empty arguments object")

    if "min_citations" in expectations:
        value = expectations["min_citations"]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            fail("min_citations must be a non-negative integer")

    if "max_risk_tier" in expectations and expectations["max_risk_tier"] not in TIERS:
        fail(f"max_risk_tier must be one of {sorted(TIERS)}")

    if "expected_outcome" in expectations and not isinstance(expectations["expected_outcome"], str):
        fail("expected_outcome must be a string")

    if "required_policy_rules" in expectations:
        rules = expectations["required_policy_rules"]
        if not isinstance(rules, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in rules.items()
        ):
            fail("required_policy_rules must map tool names to rule ids")

    if "recovery" in expectations:
        recovery = expectations["recovery"]
        if not isinstance(recovery, dict) or not all(
            isinstance(recovery.get(k), str) for k in ("failed_step", "strategy")
        ):
            fail("recovery must contain string failed_step and strategy")

    if "required_dlp" in expectations:
        requirements = expectations["required_dlp"]
        if not isinstance(requirements, list):
            fail("required_dlp must be an array")
        for requirement in requirements:
            if not isinstance(requirement, dict) or not isinstance(requirement.get("action"), str):
                fail("each required_dlp item must be an object with a string action")
            if "categories" in requirement and not _all_strings(requirement["categories"]):
                fail("required_dlp categories must be an array of strings")
            if "tool" in requirement and not isinstance(requirement["tool"], str):
                fail("required_dlp tool must be a string")


def _all_strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)
