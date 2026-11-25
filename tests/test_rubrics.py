"""Judged rubrics: reading verdicts, gating bands, and the fail-closed edges."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from citadel.evals import runner
from citadel.evals.rubric import (
    JudgeMisread,
    JudgeUnavailable,
    Rubric,
    ScriptedJudge,
    Verdict,
    band,
    judge_case,
    load_rubrics,
    parse_verdict,
    render_evidence,
)
from citadel.evals.schema import Case, DatasetError, load_cases

RUBRICS = Path(__file__).parents[1] / "evals/golden/rubrics.json"
DATASET = Path(__file__).parents[1] / "evals/golden/golden.json"


@pytest.fixture
def rubric() -> Rubric:
    return load_rubrics(RUBRICS)["plan"]


def case(dataset: Path = DATASET) -> Case:
    return load_cases(dataset)[0]


# ------------------------------------------------------------------- verdicts


def test_a_plain_json_verdict_is_read(rubric: Rubric) -> None:
    verdict = parse_verdict('{"score": 4, "rationale": "steps follow the symptom"}', rubric=rubric)

    assert verdict == Verdict(score=4, rationale="steps follow the symptom")


@pytest.mark.parametrize(
    "reply",
    [
        '```json\n{"score": 3, "rationale": "sound"}\n```',
        'Here is my grade.\n{"score": 3, "rationale": "sound"}\nThank you.',
    ],
)
def test_a_fenced_or_explained_verdict_is_still_read(rubric: Rubric, reply: str) -> None:
    assert parse_verdict(reply, rubric=rubric).score == 3


@pytest.mark.parametrize(
    "reply",
    [
        "The trajectory is good, I would give it a 4.",
        '{"score": "4", "rationale": "quoted"}',
        '{"score": true, "rationale": "bool"}',
        '{"score": 7, "rationale": "off the scale"}',
        '{"rationale": "no score"}',
        '{"score": 4, "rationale": 12}',
        '{"score": 4, "rationale": "truncated"',
    ],
)
def test_an_unreadable_verdict_is_a_misread_not_a_guess(rubric: Rubric, reply: str) -> None:
    """A judge you have to guess at is worse than one you cannot reach."""
    with pytest.raises(JudgeMisread):
        parse_verdict(reply, rubric=rubric)


# --------------------------------------------------------------------- bands


@pytest.mark.parametrize(
    ("kappa", "expected"),
    [
        (0.95, ("almost perfect", True)),
        (0.81, ("almost perfect", True)),
        (0.80, ("substantial", True)),
        (0.61, ("substantial", True)),
        (0.60, ("moderate", False)),
        (0.41, ("moderate", False)),
        (0.40, ("fair or worse", False)),
        (0.0, ("fair or worse", False)),
        (-0.2, ("fair or worse", False)),
    ],
)
def test_bands_follow_the_protocol_table(kappa: float, expected: tuple[str, bool]) -> None:
    assert band(kappa) == expected


# ------------------------------------------------------------------ catalogue


def test_the_catalogue_loads_with_the_protocols_dimensions() -> None:
    rubrics = load_rubrics(RUBRICS)

    assert set(rubrics) == {"plan", "grounding", "recovery", "escalation"}
    assert all(rubric.top == 4 for rubric in rubrics.values())


def test_no_shipped_dimension_gates_before_calibration() -> None:
    """The protocol gates on measured kappa. None has been measured, so none gates."""
    rubrics = load_rubrics(RUBRICS)

    assert [name for name, rubric in rubrics.items() if rubric.gates] == []
    assert json.loads(RUBRICS.read_text(encoding="utf-8"))["note"]


def test_a_rubric_with_a_gap_in_its_levels_is_rejected(tmp_path: Path) -> None:
    broken = {
        "rubrics": [
            {
                "dimension": "plan",
                "levels": {"4": "a", "2": "b", "1": "c"},
                "threshold": 3,
            }
        ]
    }
    path = tmp_path / "rubrics.json"
    path.write_text(json.dumps(broken), encoding="utf-8")

    with pytest.raises(ValueError, match="levels"):
        load_rubrics(path)


def test_a_threshold_outside_the_levels_is_rejected(tmp_path: Path) -> None:
    broken = {
        "rubrics": [
            {"dimension": "plan", "levels": {"2": "a", "1": "b"}, "threshold": 3}
        ]
    }
    path = tmp_path / "rubrics.json"
    path.write_text(json.dumps(broken), encoding="utf-8")

    with pytest.raises(ValueError, match="threshold"):
        load_rubrics(path)


# ------------------------------------------------------------------- evidence


def test_evidence_is_trajectory_facts_only() -> None:
    rendered = render_evidence(case())

    assert rendered.startswith("Task: Container checkout-api is unhealthy")
    assert "tool: inspect_containers -> executed" in rendered
    assert "policy: read_logs allow" in rendered
    assert "outcome: completed" in rendered
    assert "answer: checkout-api is unhealthy" in rendered


def test_evidence_is_bounded_so_a_huge_trajectory_cannot_overflow_the_judge() -> None:
    loaded = case()
    object.__setattr__(loaded, "answer", "x" * 50_000)

    rendered = render_evidence(loaded, limit=1_000)

    assert len(rendered.encode("utf-8")) <= 1_000
    assert "bytes omitted" in rendered


# --------------------------------------------------------------- judged grades


def test_a_score_at_threshold_passes_and_gates(rubric: Rubric) -> None:
    gating = Rubric(
        dimension=rubric.dimension,
        version=rubric.version,
        levels=rubric.levels,
        threshold=rubric.threshold,
        gates=True,
        question=rubric.question,
    )
    grades = judge_case(
        case(), ["plan"], {"plan": gating}, ScriptedJudge({"plan": Verdict(3, "sound")})
    )

    assert grades[0].passed is True
    assert grades[0].gating is True
    assert grades[0].grader == "rubric.plan"
    assert "score 3/4" in grades[0].detail


def test_a_score_below_threshold_fails(rubric: Rubric) -> None:
    grades = judge_case(
        case(), ["plan"], {"plan": rubric}, ScriptedJudge({"plan": Verdict(2, "trial and error")})
    )

    assert grades[0].passed is False


def test_a_report_only_dimension_does_not_gate(rubric: Rubric) -> None:
    report_only = load_rubrics(RUBRICS)["recovery"]
    grades = judge_case(
        case(),
        ["recovery"],
        {"recovery": report_only},
        ScriptedJudge({"recovery": Verdict(1, "ignored the failure")}),
    )

    assert grades[0].passed is False
    assert grades[0].gating is False, "an uncalibrated dimension must not fail a run"
    assert "report only" in grades[0].detail


def test_an_unknown_dimension_fails_rather_than_being_skipped(rubric: Rubric) -> None:
    grades = judge_case(case(), ["charisma"], {"plan": rubric}, ScriptedJudge({}))

    assert grades[0].passed is False
    assert "no rubric" in grades[0].detail


def test_an_unreachable_judge_fails_the_grade() -> None:
    class Down:
        def score(self, rubric: Rubric, evidence: str) -> Verdict:
            raise JudgeUnavailable("gateway timeout")

    grades = judge_case(case(), ["plan"], load_rubrics(RUBRICS), Down())

    assert grades[0].passed is False
    assert "gateway timeout" in grades[0].detail


# --------------------------------------------------------------------- runner


def test_the_deterministic_runner_stays_offline_by_default() -> None:
    grades = runner.run(DATASET)

    assert grades, "the golden set must produce grades"
    assert not any(item.grader.startswith("rubric.") for item in grades)


def test_a_judge_adds_grades_for_the_cases_that_ask_for_them() -> None:
    judge = ScriptedJudge(
        {
            "plan": Verdict(4, "direct"),
            "grounding": Verdict(4, "traced"),
            "escalation": Verdict(3, "escalates with next step"),
            "recovery": Verdict(1, "no recovery narrative"),
        }
    )

    grades = runner.run(DATASET, judge=judge)
    judged = [item for item in grades if item.grader.startswith("rubric.")]

    assert {item.grader for item in judged} == {
        "rubric.plan",
        "rubric.grounding",
        "rubric.escalation",
        "rubric.recovery",
    }
    assert all(item.passed for item in judged if item.gating)
    assert any(not item.passed for item in judged if not item.gating)


def test_a_report_only_failure_leaves_the_exit_code_alone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    judge = ScriptedJudge(
        {
            "plan": Verdict(4, "direct"),
            "grounding": Verdict(4, "traced"),
            "escalation": Verdict(4, "escalates"),
            "recovery": Verdict(1, "flat"),
        }
    )
    monkeypatch.setattr(runner, "_judge_from_env", lambda alias, url: judge)

    code = runner.main([str(DATASET), "--judge", "auto/best-fast"])

    assert code == 0, "a report-only dimension must not fail the run"


def test_a_gating_failure_changes_the_exit_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    catalogue = json.loads(RUBRICS.read_text(encoding="utf-8"))
    for entry in catalogue["rubrics"]:
        entry["gates"] = True
    rubrics_path = tmp_path / "gating.json"
    rubrics_path.write_text(json.dumps(catalogue), encoding="utf-8")

    judge = ScriptedJudge(
        {
            "plan": Verdict(1, "contradicts evidence"),
            "grounding": Verdict(4, "traced"),
            "escalation": Verdict(4, "escalates"),
            "recovery": Verdict(4, "recovers"),
        }
    )
    monkeypatch.setattr(runner, "_judge_from_env", lambda alias, url: judge)

    code = runner.main(
        [str(DATASET), "--judge", "auto/best-fast", "--rubrics", str(rubrics_path)]
    )

    assert code == 1


# --------------------------------------------------------------------- schema


def test_a_judged_case_without_an_answer_is_a_dataset_error(tmp_path: Path) -> None:
    data = json.loads(DATASET.read_text(encoding="utf-8"))
    del data["cases"][0]["answer"]
    path = tmp_path / "broken.json"
    path.write_text(json.dumps(data), encoding="utf-8")

    with pytest.raises(DatasetError, match="need an answer"):
        load_cases(path)
