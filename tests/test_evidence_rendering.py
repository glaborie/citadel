"""What the judge is shown, and that a rater is shown the same thing."""

from __future__ import annotations

import dataclasses
import re
from pathlib import Path

from citadel.evals.rubric import IDENTIFIER_FIELDS, render_evidence
from citadel.evals.schema import Case, load_cases

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "evals" / "calibration" / "sample-v1.json"
SHEET = ROOT / "docs" / "evals" / "calibration-sheet-v2.md"


def cases() -> list[Case]:
    return load_cases(SAMPLE)


def test_no_recorded_field_is_hidden_from_the_judge() -> None:
    """A field the record holds and the judge cannot see is a fact the answer cannot cite."""
    for case in cases():
        evidence = render_evidence(case)
        for event in case.events:
            for field, value in event.items():
                if field == "type" or field in IDENTIFIER_FIELDS:
                    continue
                if value in ("", None, [], {}):
                    continue
                assert f"{field}=" in evidence, f"{case.id}: {field} never reaches the judge"


def test_a_long_value_is_clipped_but_says_so() -> None:
    """Truncation has to be visible: a shortened log otherwise reads as a complete one."""
    case = cases()[0]
    padded = case.events[0] | {"detail": "x" * 400}
    rendered = render_evidence(dataclasses.replace(case, events=[padded]))

    assert "chars)" in rendered


def test_the_judge_sees_every_fact_an_answer_reports() -> None:
    """The v1 sheet hid approvers, latencies, durations and retrieval scores; answers cited them."""
    facts = (
        re.compile(r"user-[a-z]+"),
        re.compile(r"\b\d+(?:\.\d+)?\s?(?:ms|s)\b"),
        re.compile(r"\b0\.\d+\b"),
        re.compile(r"\bchunk-[0-9a-f]{4,}\b"),
    )
    for case in cases():
        evidence = render_evidence(case)
        text = f"{case.prompt} {case.answer or ''}"
        for pattern in facts:
            for fact in sorted(set(pattern.findall(text))):
                assert fact in evidence, f"{case.id}: answer cites {fact!r}, evidence hides it"


def test_the_sheet_shows_the_judge_evidence_verbatim() -> None:
    """A rater scoring what the judge was not shown measures a different question."""
    sheet = SHEET.read_text(encoding="utf-8")
    for case in cases():
        lines = render_evidence(case).splitlines()
        assert lines[0] in sheet, case.id
        assert lines[-1][:120] in sheet, case.id


def test_the_sheet_carries_the_scores_already_written_on_it() -> None:
    """Re-rendering evidence corrects what was shown; it does not reset the labels."""
    sheet = SHEET.read_text(encoding="utf-8")
    scored = re.findall(
        r"^score: plan=[1-4] grounding=[1-4] recovery=[1-4] escalation=[1-4]$", sheet, re.M
    )

    assert len(scored) == 30


def test_a_recorded_tool_answer_reaches_the_judge() -> None:
    """The whole point of #156: an answer that quotes a tool can be checked against it."""
    import dataclasses

    case = cases()[0]
    events = [dict(event) for event in case.events]
    for event in events:
        if event["type"] == "tool.call":
            event["output"] = {"stdout": "consumer reconnecting every 90000 ms"}
            break
    rendered = render_evidence(dataclasses.replace(case, events=events))

    assert "output=" in rendered
    assert "reconnecting every 90000 ms" in rendered


def test_a_stated_duration_appears_in_the_evidence() -> None:
    """The rater took these on trust in v1; the record now has to carry them."""
    seconds = re.compile(r"\b(\d+(?:\.\d+)?)\s?seconds?\b")
    millis = re.compile(r"\b(\d+)\s?ms\b")
    for case in cases():
        evidence = render_evidence(case)
        text = case.answer or ""
        for value in seconds.findall(text):
            as_ms = str(int(float(value) * 1000))
            assert value in evidence or as_ms in evidence, (
                f"{case.id}: answer says {value} seconds, evidence says neither {value} nor {as_ms}"
            )
        for value in millis.findall(text):
            assert value in evidence, f"{case.id}: answer says {value} ms, evidence does not"
