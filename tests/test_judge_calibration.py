"""The calibration numbers, and the gates they do or do not earn."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs" / "evals" / "judge-calibration.md"
RUBRICS = ROOT / "evals" / "golden" / "rubrics.json"
SCORES = ROOT / "evals" / "calibration" / "judge-scores-v1.json"
HUMAN = ROOT / "evals" / "calibration" / "labels-human-v1.json"
LABELS = ROOT / "evals" / "calibration" / "labels"
THRESHOLD = 0.61


def reported() -> dict[str, float]:
    """The kappa per dimension, read from the block a human reads."""
    text = DOC.read_text(encoding="utf-8")
    line = next(line for line in text.splitlines() if line.startswith("kappa  "))
    found = re.findall(r"(plan|grounding|recovery|escalation) (\d+\.\d+)", line)
    return {name: float(value) for name, value in found}


def test_the_doc_reports_a_kappa_for_every_dimension() -> None:
    assert set(reported()) == {"plan", "grounding", "recovery", "escalation"}


def test_no_dimension_gates_without_clearing_the_threshold() -> None:
    """A `gates: true` beside a kappa below 0.61 is the lie this test exists to stop."""
    rubrics = {entry["dimension"]: entry for entry in json.loads(RUBRICS.read_text())["rubrics"]}

    for dimension, kappa in reported().items():
        if kappa >= THRESHOLD:
            continue
        assert rubrics[dimension]["gates"] is False, dimension


def test_a_dimension_that_gates_has_to_show_its_kappa() -> None:
    gating = [
        entry["dimension"]
        for entry in json.loads(RUBRICS.read_text())["rubrics"]
        if entry["gates"]
    ]
    for dimension in gating:
        assert reported()[dimension] >= THRESHOLD, dimension


def test_the_recorded_judge_run_names_the_instrument() -> None:
    """A kappa without the model alias and rubric version is not reproducible."""
    payload = json.loads(SCORES.read_text(encoding="utf-8"))

    assert payload["alias"]
    assert isinstance(payload["rubric_version"], int)
    assert payload["recorded"]
    scored = [item for item in payload["items"] if "score" in item]
    assert scored, "no scored items"
    assert all(1 <= item["score"] <= 4 for item in scored)


def test_unreadable_verdicts_are_recorded_as_errors_not_scores() -> None:
    payload = json.loads(SCORES.read_text(encoding="utf-8"))
    broken = [item for item in payload["items"] if "error" in item]

    assert broken, "the DLP-refused items should be recorded as errors, not dropped"
    for item in broken:
        assert "score" not in item
        assert item["error"]


def test_the_labels_cover_the_sheet_and_pair_with_the_scores() -> None:
    human = json.loads(HUMAN.read_text(encoding="utf-8"))
    assert len(human["items"]) == 30
    assert all(set(item) >= {"id", "sample_id", "plan", "grounding", "recovery", "escalation"}
               for item in human["items"])

    judged = {
        (item["id"], item["dimension"])
        for item in json.loads(SCORES.read_text(encoding="utf-8"))["items"]
        if "score" in item
    }
    for dimension in ("plan", "grounding", "recovery", "escalation"):
        rows = json.loads((LABELS / f"{dimension}.json").read_text(encoding="utf-8"))["items"]
        assert rows, dimension
        for row in rows:
            assert (row["id"], dimension) in judged
            assert 1 <= row["human"] <= 4 and 1 <= row["judge"] <= 4


def rubric_catalogue() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(RUBRICS.read_text(encoding="utf-8"))
    return raw


def test_the_catalogue_records_rubric_v2() -> None:
    """The numbers above were measured on v1; the anchors that failed are now v2."""
    catalogue = rubric_catalogue()
    entries = {entry["dimension"]: entry for entry in catalogue["rubrics"]}

    assert catalogue["rubric_version"] == 2
    assert entries["grounding"]["version"] == 2
    assert entries["recovery"]["version"] == 2
    assert entries["plan"]["version"] == 1, "plan did not earn a rewrite"
    assert entries["escalation"]["version"] == 1, "escalation did not earn a rewrite"


def test_the_grounding_boundary_separates_inference_from_assertion() -> None:
    """v1 lost this distinction to eleven 4-vs-2 disagreements; v2 has to state it."""
    entry = {item["dimension"]: item for item in rubric_catalogue()["rubrics"]}["grounding"]

    assert "inference" in entry["levels"]["4"]
    assert "no evidence named" in entry["levels"]["2"]
    assert "inference" in entry["question"]


def test_the_recovery_boundary_says_that_nothing_failed_is_a_four() -> None:
    """v1 had no entry for a run without a failure, and twelve items scored 4 against 1."""
    entry = {item["dimension"]: item for item in rubric_catalogue()["rubrics"]}["recovery"]

    assert entry["levels"]["4"].startswith("Nothing failed")
    assert "three or more times" in entry["levels"]["1"]


def test_no_dimension_gates_after_the_rewrite_either() -> None:
    """Rewriting a rubric is not evidence; a new kappa is, and there is not one yet."""
    assert all(item["gates"] is False for item in rubric_catalogue()["rubrics"])
