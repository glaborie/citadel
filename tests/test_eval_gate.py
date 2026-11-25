"""A gate that cannot fail is decoration.

RT-EVAL-01 asks whether a worse trajectory is stopped. These two assertions are
the whole test: the committed golden set passes the gate, and a degraded copy of
one case does not.
"""

from __future__ import annotations

from pathlib import Path

from citadel.evals import runner

GOLDEN = Path(__file__).parents[1] / "evals" / "golden"


def test_the_committed_golden_set_passes_the_gate() -> None:
    assert runner.main([str(GOLDEN / "golden.json")]) == 0


def test_the_gate_rejects_a_degraded_trajectory() -> None:
    grades = runner.run(GOLDEN / "degraded.json")
    failed = [grade for grade in grades if not grade.passed]

    assert failed, "the degraded dataset passed every grader"
    assert any("forbidden" in grade.detail for grade in failed), [g.detail for g in failed]
    assert runner.main([str(GOLDEN / "degraded.json")]) == 1
