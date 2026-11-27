"""Manifest checks for the red-team pack.

These tests do not execute attacks. They keep the pack honest: unique ids, a
known category and verdict per case, a named control, and a milestone. The
documents and the pack drift apart easily, so the control names are also
checked against ``docs/``.

Executing the cases lives in ``tests/redteam/test_pack.py`` once fixtures and
the stub tool server land; this module is the gate that keeps the catalogue
itself from rotting.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest

PACK = Path(__file__).parent / "cases.json"
DOCS = Path(__file__).parents[2] / "docs"

CATEGORIES = {
    "injection",
    "authorization",
    "hitl",
    "dlp",
    "durability",
    "cache",
    "cost",
    "evaluation",
}
TIERS = {"T0", "T1", "T2"}
VERDICTS = {
    "blocked",
    "blocked_or_refused",
    "refused",
    "denied",
    "denied_and_alerted",
    "denied_and_flagged",
    "denied_fail_closed",
    "auto_denied",
    "gated",
    "redacted",
    "redacted_before_model",
    "flag_and_continue_readonly",
    "zero_results",
    "cache_miss",
    "cache_invalidated",
    "aborted_at_budget",
    "gate_failed",
    "audit_gap_detected",
    "allowed_once",
    "allowed_readonly",
}
pytestmark = pytest.mark.redteam

MILESTONES = {"v0.1", "v0.2", "v0.3", "v0.4"}
ID_RE = re.compile(r"^RT-[A-Z]+-\d{2}$")
CONTROL_RE = re.compile(r"^[a-z][a-z0-9_]+$")
MILESTONE_RE = re.compile(r"^v0\.[1-4]$")


def load_pack() -> dict[str, Any]:
    with PACK.open(encoding="utf-8") as handle:
        data: dict[str, Any] = json.load(handle)
    return data


def cases() -> list[dict[str, Any]]:
    return [case for case in load_pack()["cases"]]


def test_pack_header() -> None:
    pack = load_pack()
    assert pack["pack"] == "citadel-redteam"
    assert isinstance(pack["version"], int) and pack["version"] >= 1
    assert isinstance(pack["notes"], list) and pack["notes"]


def test_ids_are_unique_and_well_formed() -> None:
    ids = [case["id"] for case in cases()]
    assert len(ids) == len(set(ids)), f"duplicate ids: {sorted(ids)}"
    bad = [case_id for case_id in ids if not ID_RE.match(case_id)]
    assert not bad, f"malformed ids: {bad}"


def test_every_case_is_classified() -> None:
    for case in cases():
        assert case["category"] in CATEGORIES, case["id"]
        assert case["tier"] in TIERS, case["id"]
        assert case["expect"]["verdict"] in VERDICTS, case["id"]
        assert case["milestone"] in MILESTONES, case["id"]
        assert isinstance(case["title"], str) and len(case["title"]) > 8


def test_every_case_has_a_control_and_evidence() -> None:
    for case in cases():
        controls = case["controls"]
        assert controls, f"{case['id']} names no control"
        for control in controls:
            assert CONTROL_RE.match(control), f"{case['id']}: {control}"
        evidence = case["expect"]["evidence"]
        assert isinstance(evidence, str) and evidence.strip(), case["id"]


def test_safety_cases_expect_no_side_effects_unless_stated() -> None:
    allowed = {"none", "exactly one", "none beyond the single call"}
    for case in cases():
        if case["category"] in {"injection", "authorization", "dlp"}:
            assert case["expect"]["side_effects"] in allowed, case["id"]


def test_fixtures_follow_the_layout() -> None:
    # A fixture is data and may be shared by several cases: the two-tenant
    # corpus is used by both the ACL and the cache case on purpose.
    missing: list[str] = []
    for case in cases():
        fixture = case["fixture"]
        if fixture is None:
            continue
        assert fixture.startswith("fixtures/"), f"{case['id']}: {fixture}"
        if not (Path(__file__).parent / fixture).exists():
            missing.append(f"{case['id']} -> {fixture}")
    if missing:
        pytest.skip(f"{len(missing)} fixtures still to create: {', '.join(missing[:6])}")


def test_control_names_are_documented() -> None:
    corpus = "\n".join(
        path.read_text(encoding="utf-8", errors="ignore") for path in DOCS.rglob("*.md")
    )
    undocumented = sorted(
        {control for case in cases() for control in case["controls"] if control not in corpus}
    )
    assert not undocumented, f"controls missing from docs/: {undocumented}"


def test_doc_lists_every_case() -> None:
    doc = (DOCS / "security" / "red-team-pack.md").read_text(encoding="utf-8")
    absent = [case["id"] for case in cases() if case["id"] not in doc]
    assert not absent, f"cases missing from red-team-pack.md: {absent}"


def test_coverage_spans_the_milestones() -> None:
    by_milestone = {case["milestone"] for case in cases()}
    assert "v0.1" in by_milestone
    assert len(by_milestone) >= 3, "pack should not be a single-milestone list"
