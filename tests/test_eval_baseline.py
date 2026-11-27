"""The baseline table and the gate that reads it."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from citadel.evals import baseline
from citadel.evals.graders import Grade
from citadel.evals.runner import main, run
from citadel.evals.schema import DatasetError, load_cases

DATASET = Path("evals/golden/golden.json")
BASELINE = Path("evals/baseline.json")


def score(passed: int, total: int, gating: bool = True) -> baseline.Score:
    return baseline.Score(passed=passed, total=total, gating=gating)


def row(scores: dict[str, baseline.Score], name: str = "v1") -> baseline.Row:
    return baseline.Row(
        key=baseline.Key(dataset=name, prompts="docker-1.0.0", model="auto/best-fast"),
        scores=scores,
        recorded="2026-11-26",
    )


def test_the_key_comes_from_the_trajectories_not_from_an_argument() -> None:
    """A baseline is only comparable to a run recorded under the same pack and model."""
    key = baseline.key_for(load_cases(DATASET), dataset="v1")

    assert key.dataset == "v1"
    assert "docker-1.0.0" in key.prompts
    assert "auto/best-reasoning" in key.model
    assert key.judge == baseline.OFFLINE


def test_a_dataset_without_a_version_cannot_be_keyed(tmp_path: Path) -> None:
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    raw.pop("dataset_version")
    path = tmp_path / "noversion.json"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(DatasetError, match="no dataset_version"):
        baseline.dataset_version(path)


def test_a_report_only_dimension_stays_report_only_in_the_row() -> None:
    grades = [
        Grade("devops-001", "tool.selection", True, ""),
        Grade("devops-001", "judge.plan", False, "", gating=False),
    ]

    scores = baseline.summarise(grades)

    assert scores["tool.selection"] == score(1, 1, True)
    assert scores["judge.plan"] == score(0, 1, False)


def test_a_drop_names_both_rates_and_the_row_it_was_judged_against() -> None:
    compared = baseline.compare(
        {"tool.selection": score(12, 14)}, row({"tool.selection": score(14, 14)})
    )

    assert len(compared) == 1
    assert "12/14" in compared[0] and "14/14" in compared[0]
    assert "v1" in compared[0]


def test_an_improvement_is_not_a_regression() -> None:
    compared = baseline.compare(
        {"tool.selection": score(14, 14)}, row({"tool.selection": score(12, 14)})
    )
    assert compared == []


def test_a_grader_that_stopped_appearing_is_a_regression() -> None:
    """Not measured is not passed, and the row is the only place that notices."""
    compared = baseline.compare({}, row({"tool.arguments": score(14, 14)}))

    assert compared == ["tool.arguments: no longer graded (baseline 14/14)"]


def test_record_refuses_to_rewrite_a_score_for_a_known_key(tmp_path: Path) -> None:
    """Otherwise "the numbers moved" would pass as "the numbers are recorded"."""
    path = tmp_path / "baseline.json"
    baseline.record(path, row({"tool.selection": score(14, 14)}))
    before = path.read_text(encoding="utf-8")

    with pytest.raises(DatasetError, match="not a new baseline"):
        baseline.record(path, row({"tool.selection": score(12, 14)}))

    assert path.read_text(encoding="utf-8") == before


def test_a_new_key_adds_a_row_and_leaves_the_old_one_alone(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline.record(path, row({"tool.selection": score(14, 14)}, name="v1"))
    baseline.record(path, row({"tool.selection": score(13, 14)}, name="v2"))

    rows = baseline.load(path)

    assert [item.key.dataset for item in rows] == ["v1", "v2"]
    assert rows[0].scores["tool.selection"] == score(14, 14)


def test_a_model_alias_change_is_compared_with_the_accepted_row(tmp_path: Path) -> None:
    """The alias is the experiment, not a break: the accepted row stays the reference."""
    path = tmp_path / "baseline.json"
    accepted = baseline.Row(
        key=baseline.Key(dataset="v2", prompts="docker-1.0.0", model="auto/best-fast"),
        scores={"tool.selection": score(14, 14)},
        recorded="2026-11-26",
    )
    baseline.record(path, accepted)
    changed = baseline.Row(
        key=baseline.Key(dataset="v2", prompts="docker-1.0.0", model="auto/best-reasoning"),
        scores={"tool.selection": score(13, 14)},
        recorded="2026-11-27",
    )

    reference = baseline.comparable(changed.key, baseline.load(path))

    assert reference == accepted
    assert reference is not None
    assert baseline.compare(changed.scores, reference) == [
        "tool.selection: 13/14 (0.929) is below the baseline 14/14 (1.000) for "
        "v2 · docker-1.0.0 · auto/best-fast · judge=offline"
    ]

    baseline.record(path, changed)
    rows = baseline.load(path)
    assert [item.key.model for item in rows] == ["auto/best-fast", "auto/best-reasoning"]
    assert rows[0].scores == accepted.scores, "the accepted row was not overwritten"


def test_a_changed_prompt_pack_is_not_comparable() -> None:
    """A different pack is a different suite; comparing it would call a change a regression."""
    accepted = baseline.Row(
        key=baseline.Key(dataset="v2", prompts="docker-1.0.0", model="auto/best-fast"),
        scores={"tool.selection": score(14, 14)},
        recorded="2026-11-26",
    )
    changed = baseline.Row(
        key=baseline.Key(dataset="v2", prompts="docker-1.0.1", model="auto/best-fast"),
        scores={"tool.selection": score(13, 14)},
        recorded="2026-11-27",
    )

    assert baseline.comparable(changed.key, [accepted]) is None


def test_a_judge_change_is_not_comparable() -> None:
    accepted = baseline.Row(
        key=baseline.Key(dataset="v2", prompts="docker-1.0.0", model="auto/best-fast"),
        scores={"judge.plan": score(2, 2, gating=False)},
        recorded="2026-11-26",
    )
    changed = baseline.Row(
        key=baseline.Key(
            dataset="v2", prompts="docker-1.0.0", model="auto/best-fast", judge="plan"
        ),
        scores={"judge.plan": score(1, 2, gating=False)},
        recorded="2026-11-27",
    )

    assert baseline.comparable(changed.key, [accepted]) is None


def test_recording_the_same_run_twice_says_so(tmp_path: Path) -> None:
    path = tmp_path / "baseline.json"
    baseline.record(path, row({"tool.selection": score(14, 14)}))

    assert "unchanged" in baseline.record(path, row({"tool.selection": score(14, 14)}))


def test_a_missing_baseline_file_is_no_rows(tmp_path: Path) -> None:
    assert baseline.load(tmp_path / "absent.json") == []


def test_the_table_marks_report_only_cells() -> None:
    rendered = baseline.render(
        [row({"tool.selection": score(14, 14), "judge.plan": score(1, 14, False)})],
        row({"tool.selection": score(13, 14)}),
    )

    assert rendered.startswith("| Grader |")
    assert "this run" in rendered
    assert "1/14 (7%)*" in rendered
    assert "no measured kappa" in rendered


def test_the_committed_baseline_still_describes_the_committed_dataset() -> None:
    """The rows are pinned to a dataset and a pack; a change to either needs a new row."""
    current = baseline.summarise(run(DATASET))
    key = baseline.key_for(load_cases(DATASET), dataset=baseline.dataset_version(DATASET))
    rows = [item for item in baseline.load(BASELINE) if item.key == key]

    assert rows, f"no baseline row for {key.label()} - record one with --record"
    assert baseline.compare(current, rows[0]) == []


def test_the_cli_gate_passes_on_the_committed_baseline(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--gate"]) == 0
    assert "gating graders at or above baseline" in capsys.readouterr().err


def test_the_cli_gate_fails_when_a_grader_stops_being_produced(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A row naming a grader the suite no longer emits must fail, not pass quietly."""
    edited = json.loads(BASELINE.read_text(encoding="utf-8"))
    version = baseline.dataset_version(DATASET)
    row = next(item for item in edited["baselines"] if item["dataset"] == version)
    scores = row["scores"]
    scores["tool.selection.renamed"] = scores.pop("tool.selection")
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps(edited), encoding="utf-8")

    assert main(["--gate", "--baseline", str(path)]) == 1
    assert "no longer graded" in capsys.readouterr().err


def test_the_cli_gate_refuses_to_pass_on_a_key_it_has_no_row_for(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["--gate", "--baseline", str(tmp_path / "absent.json")]) == 1
    assert "no baseline row" in capsys.readouterr().err


def test_the_cli_table_is_markdown_on_stdout(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--table"]) == 0
    out = capsys.readouterr().out

    assert out.startswith("| Grader |")
    assert "| tool.selection |" in out


def _rewrite_dataset(tmp_path: Path, **run_start: str) -> Path:
    raw = json.loads(DATASET.read_text(encoding="utf-8"))
    for case in raw["cases"]:
        for event in case["events"]:
            if event["type"] == "run.start":
                event.update(run_start)
    path = tmp_path / "dataset.json"
    path.write_text(json.dumps(raw), encoding="utf-8")
    return path


def test_the_cli_gate_compares_a_new_alias_against_the_accepted_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An alias bump is a diff against the accepted row, not a missing baseline."""
    dataset = _rewrite_dataset(tmp_path, model_alias="auto/next")

    assert main([str(dataset), "--gate"]) == 0
    assert "gating graders at or above baseline" in capsys.readouterr().err


def test_the_cli_gate_does_not_compare_across_prompt_packs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A new pack has no accepted row of its own; it must be recorded, not guessed."""
    dataset = _rewrite_dataset(tmp_path, prompt_pack_version="docker-9.9.9")

    assert main([str(dataset), "--gate"]) == 1
    assert "no baseline row" in capsys.readouterr().err
