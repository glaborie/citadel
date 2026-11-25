"""Kappa script contract: the worked example must produce 0.6 exactly.

Raters over ten binary items:
    human 1 1 0 0 1 1 0 0 1 0
    judge 1 1 1 0 0 1 0 0 1 0
Eight agreements, both raters positive 50% and 40% of the time, so
po = 0.8, pe = 0.5, kappa = 0.6 (Landis & Koch: moderate, not gating).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import cast

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "cohens_kappa.py"


def run_script(payload: dict[str, object]) -> tuple[int, dict[str, object]]:
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as handle:
        json.dump(payload, handle)
        path = handle.name
    completed = subprocess.run(
        [sys.executable, str(SCRIPT), path, "--json"],
        capture_output=True,
        text=True,
        check=False,
    )
    Path(path).unlink(missing_ok=True)
    parsed = json.loads(completed.stdout)
    return completed.returncode, cast(dict[str, object], parsed)


def test_worked_example_is_point_six() -> None:
    human = [1, 1, 0, 0, 1, 1, 0, 0, 1, 0]
    judge = [1, 1, 1, 0, 0, 1, 0, 0, 1, 0]
    items = [
        {"id": f"t-{index:03d}", "human": h, "judge": j}
        for index, (h, j) in enumerate(zip(human, judge, strict=True))
    ]
    code, result = run_script({"items": items})
    assert result["n"] == 10
    assert result["observed_agreement"] == pytest.approx(0.8)
    assert result["expected_agreement"] == pytest.approx(0.5)
    assert result["kappa"] == pytest.approx(0.6)
    assert result["band"] == "moderate"
    assert result["gating_allowed"] is False
    assert code == 2
    assert result["confusions"] == {"0->1": 1, "1->0": 1}


def test_perfect_agreement_is_gating() -> None:
    items = [{"id": str(i), "human": v, "judge": v} for i, v in enumerate([1, 2, 3, 2, 1] * 6)]
    code, result = run_script({"items": items})
    value = result["kappa"]
    assert isinstance(value, float)
    assert value == pytest.approx(1.0)
    assert result["gating_allowed"] is True
    assert code == 0


def test_string_labels_are_supported() -> None:
    items = [
        {"id": str(i), "human": label, "judge": label}
        for i, label in enumerate(["grounded", "thin", "grounded", "unsupported"] * 6)
    ]
    code, result = run_script({"items": items})
    value = result["kappa"]
    assert isinstance(value, float)
    assert value == pytest.approx(1.0)
    assert code == 0
