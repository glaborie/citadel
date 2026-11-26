"""The calibration numbers, and the gates they do or do not earn.

Two measurements are recorded now - v1 on the lossy renderer, v2 on the complete one -
so every assertion names the version it is about. A single `kappa` line that a later
block could overwrite is how a stale number starts describing a new rubric.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
DOC = ROOT / "docs" / "evals" / "judge-calibration.md"
RUBRICS = ROOT / "evals" / "golden" / "rubrics.json"
THRESHOLD = 0.61
DIMENSIONS = ("plan", "grounding", "recovery", "escalation")


def artifacts(version: int) -> tuple[Path, Path, Path]:
    calibration = ROOT / "evals" / "calibration"
    labels = calibration / "labels" if version == 1 else calibration / f"labels-v{version}"
    return (
        calibration / f"judge-scores-v{version}.json",
        calibration / f"labels-human-v{version}.json",
        labels,
    )


def blocks() -> dict[int, str]:
    """The doc result blocks, keyed by rubric version. A block owns its heading."""
    text = DOC.read_text(encoding="utf-8")
    found: dict[int, str] = {}
    for chunk in re.split(r"^## Result: ", text, flags=re.MULTILINE)[1:]:
        match = re.search(r"rubric v(\d+)", chunk)
        if match:
            found[int(match.group(1))] = chunk
    return found


def reported(version: int) -> dict[str, float]:
    """The kappa per dimension for one measurement, read from the block a human reads."""
    body = blocks()[version]
    line = next(line for line in body.splitlines() if line.startswith("kappa  "))
    found = re.findall(r"(plan|grounding|recovery|escalation) (\d+\.\d+)", line)
    return {name: float(value) for name, value in found}


def test_both_measurements_are_recorded_and_dated() -> None:
    assert set(blocks()) == {1, 2}
    for version, body in blocks().items():
        assert re.search(r"measured \d{4}-\d{2}-\d{2}", body), version


def test_the_doc_reports_a_kappa_for_every_dimension() -> None:
    for version in (1, 2):
        assert set(reported(version)) == set(DIMENSIONS), version


def test_each_block_names_the_instrument_and_the_sample_size() -> None:
    """A kappa without the alias, the rubric version and n is not reproducible."""
    for version, body in blocks().items():
        assert "judge  " in body, version
        assert re.search(r"n  +\d+", body), version


def rubric_catalogue() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(RUBRICS.read_text(encoding="utf-8"))
    return raw


def test_no_dimension_gates_without_clearing_the_threshold() -> None:
    """A `gates: true` beside a kappa below 0.61 is the lie this test exists to stop."""
    entries = {entry["dimension"]: entry for entry in rubric_catalogue()["rubrics"]}
    latest = max(blocks())

    for dimension, kappa in reported(latest).items():
        if kappa >= THRESHOLD:
            continue
        assert entries[dimension]["gates"] is False, dimension


def test_a_dimension_that_gates_has_to_show_its_kappa() -> None:
    entries = {entry["dimension"]: entry for entry in rubric_catalogue()["rubrics"]}
    latest = max(blocks())
    for dimension, entry in entries.items():
        if entry["gates"]:
            assert reported(latest)[dimension] >= THRESHOLD, dimension


def test_the_recorded_judge_run_names_the_instrument() -> None:
    for version in (1, 2):
        scores, _, _ = artifacts(version)
        payload = json.loads(scores.read_text(encoding="utf-8"))

        assert payload["alias"], version
        assert payload["rubric_version"] == version, version
        assert payload["recorded"], version
        scored = [item for item in payload["items"] if "score" in item]
        assert scored, f"v{version}: no scored items"
        assert all(1 <= item["score"] <= 4 for item in scored)


def test_unreadable_verdicts_are_recorded_as_errors_not_scores() -> None:
    """The v1 run's DLP-refused items: kept in the file, excluded from the pair."""
    scores, _, _ = artifacts(1)
    payload = json.loads(scores.read_text(encoding="utf-8"))
    broken = [item for item in payload["items"] if "error" in item]

    assert broken, "the DLP-refused items should be recorded as errors, not dropped"
    for item in broken:
        assert "score" not in item
        assert item["error"]


def test_the_labels_cover_the_sheet_and_pair_with_the_scores() -> None:
    for version in (1, 2):
        scores, human_path, labels = artifacts(version)
        human = json.loads(human_path.read_text(encoding="utf-8"))
        assert len(human["items"]) == 30, version
        assert all(
            set(item)
            >= {"id", "sample_id", "plan", "grounding", "recovery", "escalation"}
            for item in human["items"]
        ), version

        judged = {
            (item["id"], item["dimension"])
            for item in json.loads(scores.read_text(encoding="utf-8"))["items"]
            if "score" in item
        }
        for dimension in DIMENSIONS:
            rows = json.loads((labels / f"{dimension}.json").read_text(encoding="utf-8"))["items"]
            assert rows, f"v{version} {dimension}"
            for row in rows:
                assert (row["id"], dimension) in judged
                assert 1 <= row["human"] <= 4 and 1 <= row["judge"] <= 4


def test_the_catalogue_records_rubric_v2() -> None:
    """The v1 anchors that failed were rewritten; plan and escalation were not."""
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
    """Rewriting a rubric is not evidence; a kappa under v2 is, and this file has one."""
    assert all(item["gates"] is False for item in rubric_catalogue()["rubrics"])
