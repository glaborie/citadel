"""The judge-calibration sample: 30 items with a known spread, and a blind sheet."""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

from citadel.evals.schema import check_events, load_cases

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "evals" / "calibration" / "sample-v1.json"
SHEET = ROOT / "docs" / "evals" / "calibration-sheet-v1.md"  # the labelled artifact
KEY = ROOT / "evals" / "calibration" / "label-key-v1.json"
BUILDER = ROOT / "scripts" / "build-calibration-sample.py"

BAND_WORDS = ("near-miss", "partial", "clean", "mutation", "derived_from")


def sample() -> dict[str, Any]:
    raw: dict[str, Any] = json.loads(SAMPLE.read_text(encoding="utf-8"))
    return raw


def test_the_sample_is_thirty_items_at_ten_each() -> None:
    """A sample calibrated only on successes looks excellent and gates nothing."""
    bands = Counter(case["provenance"]["band"] for case in sample()["cases"])

    assert len(sample()["cases"]) == 30
    assert bands == {"clean": 10, "partial": 10, "near-miss": 10}


def test_every_item_is_a_valid_trajectory_with_an_answer_and_four_dimensions() -> None:
    for case in sample()["cases"]:
        assert check_events(case["events"], tenant=case["tenant"]) == [], case["id"]
        assert case["answer"].strip(), case["id"]
        assert case["judge"] == ["plan", "grounding", "recovery", "escalation"], case["id"]


def test_the_sample_loads_through_the_same_loader_as_the_goldens() -> None:
    """If the calibration set drifted from the trajectory schema it would grade nothing."""
    cases = load_cases(SAMPLE)

    assert len(cases) == 30
    assert all(case.judge for case in cases)


def test_the_sample_says_how_it_was_made() -> None:
    provenance = sample()["provenance"]

    assert provenance["kind"] == "authored"
    assert "no partial or failing trajectories" in provenance["note"]
    assert all(case["provenance"]["derived_from"] for case in sample()["cases"])


def test_each_variant_names_its_flaw_and_keeps_its_base() -> None:
    for case in sample()["cases"]:
        prov = case["provenance"]
        if prov["band"] == "clean":
            assert prov["mutation"] == "none", case["id"]
        else:
            assert prov["mutation"] != "none", case["id"]
        assert prov["derived_from"].startswith("devops-"), case["id"]


def test_the_sheet_is_blind() -> None:
    """A sheet that names the band measures the answer key, not the judge."""
    sections = SHEET.read_text(encoding="utf-8").split("\n## item-")[1:]

    assert len(sections) == 30
    for section in sections:
        lowered = section.lower()
        for word in BAND_WORDS:
            assert word not in lowered, f"sheet leaks {word!r}"
        assert "score: plan=" in section


def test_the_key_covers_every_item_and_is_not_the_sheet() -> None:
    key = json.loads(KEY.read_text(encoding="utf-8"))
    ids = {case["id"] for case in sample()["cases"]}

    assert set(key["bands"]) == set(key["items"]) == {f"item-{n:02d}" for n in range(1, 31)}
    assert set(key["items"].values()) == ids
    assert "bands" not in SHEET.read_text(encoding="utf-8")


def test_the_builder_is_deterministic_and_matches_the_committed_sample(tmp_path: Path) -> None:
    """The sample is generated, so it must be regenerable byte for byte."""
    result = subprocess.run(
        [sys.executable, str(BUILDER), "--check"], capture_output=True, text=True, cwd=ROOT
    )

    assert result.returncode == 0, result.stderr
    assert "10/10/10" in result.stdout


def test_the_sample_is_not_part_of_the_graded_dataset() -> None:
    """Calibration items are labelled, not gated: they must not move the eval baseline."""
    golden = json.loads((ROOT / "evals" / "golden" / "golden.json").read_text(encoding="utf-8"))
    golden_ids = {case["id"] for case in golden["cases"]}

    assert not any(case["id"].startswith("cal-") for case in golden["cases"])
    assert not golden_ids & {case["id"] for case in sample()["cases"]}
