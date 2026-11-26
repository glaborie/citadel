"""The baseline table: what the suite scored, and what it was scored against.

A grader change is otherwise judged against memory. This module makes the comparison
explicit: a row is keyed by everything that can move the numbers - the dataset version,
the prompt-pack versions the trajectories were recorded under, the model aliases, and
the judge - so a new model or a new case **adds** a row instead of rewriting the old one.

The gate only speaks for dimensions that can fail. Judged rubrics stay report-only,
because a dimension with no measured kappa has no business failing a build (see #93).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from citadel.evals.graders import Grade
from citadel.evals.schema import Case, DatasetError

SCHEMA = 1
DEFAULT_BASELINE = Path("evals/baseline.json")
OFFLINE = "offline"


@dataclass(frozen=True)
class Key:
    """Everything that can move the numbers. A change to any part is a new row."""

    dataset: str
    prompts: str
    model: str
    judge: str = OFFLINE

    def label(self) -> str:
        return f"{self.dataset} · {self.prompts} · {self.model} · judge={self.judge}"

    def as_dict(self) -> dict[str, str]:
        return {
            "dataset": self.dataset,
            "prompts": self.prompts,
            "model": self.model,
            "judge": self.judge,
        }


@dataclass(frozen=True)
class Score:
    """Passed over total, plus whether this grader is allowed to fail a build."""

    passed: int
    total: int
    gating: bool = True

    @property
    def rate(self) -> float:
        return self.passed / self.total if self.total else 1.0


@dataclass(frozen=True)
class Row:
    key: Key
    scores: dict[str, Score]
    recorded: str


def dataset_version(path: Path) -> str:
    """The dataset's own version, which the loader does not carry into a Case."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DatasetError(f"{path}: {exc}") from exc
    version = raw.get("dataset_version") if isinstance(raw, dict) else None
    if not isinstance(version, int):
        raise DatasetError(f"{path}: no dataset_version, so a baseline cannot be keyed")
    return f"v{version}"


def key_for(cases: Iterable[Case], *, dataset: str, judge: str = OFFLINE) -> Key:
    """What the trajectories say they were recorded under, not what we assume."""
    packs: set[str] = set()
    models: set[str] = set()
    for case in cases:
        for event in case.events:
            if event.get("type") == "run.start":
                packs.add(str(event.get("prompt_pack_version") or "unknown"))
                models.add(str(event.get("model_alias") or "unknown"))
    return Key(
        dataset=dataset,
        prompts="+".join(sorted(packs)) or "none",
        model="+".join(sorted(models)) or "none",
        judge=judge,
    )


def summarise(grades: Iterable[Grade]) -> dict[str, Score]:
    """One line per grader: how many checks passed, and whether any of them gate."""
    counts: dict[str, list[int]] = {}
    gating: dict[str, bool] = {}
    for item in grades:
        bucket = counts.setdefault(item.grader, [0, 0])
        bucket[0] += 1 if item.passed else 0
        bucket[1] += 1
        gating[item.grader] = gating.get(item.grader, True) and item.gating
    return {name: Score(counts[name][0], counts[name][1], gating[name]) for name in sorted(counts)}


def load(path: Path = DEFAULT_BASELINE) -> list[Row]:
    """The recorded rows; a missing file is no rows, not an error."""
    if not path.exists():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise DatasetError(f"{path}: {exc}") from exc
    rows = raw.get("baselines") if isinstance(raw, dict) else None
    if not isinstance(rows, list):
        raise DatasetError(f"{path}: expected an object with a 'baselines' array")
    return [_row(item, path) for item in rows]


def _row(raw: object, source: Path) -> Row:
    if not isinstance(raw, dict):
        raise DatasetError(f"{source}: every baseline must be an object")
    key = Key(**{field: str(raw[field]) for field in ("dataset", "prompts", "model")},
              judge=str(raw.get("judge", OFFLINE)))
    scores = {
        name: Score(int(values["passed"]), int(values["total"]), bool(values.get("gating", True)))
        for name, values in dict(raw.get("scores", {})).items()
    }
    return Row(key=key, scores=scores, recorded=str(raw.get("recorded", "unknown")))


def compare(current: dict[str, Score], row: Row) -> list[str]:
    """Every way this run is worse than the row it is being judged against.

    A grader that stopped appearing is a regression too: it may not have got worse,
    it stopped being measured, and a build that cannot see a dimension has not passed
    it.
    """
    problems: list[str] = []
    for name, was in sorted(row.scores.items()):
        now = current.get(name)
        if now is None:
            problems.append(f"{name}: no longer graded (baseline {was.passed}/{was.total})")
        elif now.rate < was.rate:
            problems.append(
                f"{name}: {now.passed}/{now.total} ({now.rate:.3f}) is below the baseline "
                f"{was.passed}/{was.total} ({was.rate:.3f}) for {row.key.label()}"
            )
    return problems


NOTE = (
    "Recorded by `python -m citadel.evals --record`. A row is keyed by dataset version, "
    "prompt-pack versions, model aliases and judge; a change to any of them adds a row "
    "rather than rewriting one."
)


def record(path: Path, row: Row) -> str:
    """Add `row`, or confirm it. A changed score for a known key is refused, not merged.

    Overwriting would let "the numbers moved" pass as "the numbers are recorded", and the
    old row is the only evidence of what the suite used to do.
    """
    rows = load(path)
    existing = next((item for item in rows if item.key == row.key), None)
    if existing is not None:
        return _confirm(path, existing, row)
    flush(path, _payload(rows + [row]))
    return f"recorded: {row.key.label()}"


def _confirm(path: Path, existing: Row, row: Row) -> str:
    if existing.scores == row.scores:
        return f"unchanged: {row.key.label()} is already recorded"
    was = {name: f"{score.passed}/{score.total}" for name, score in existing.scores.items()}
    raise DatasetError(
        f"{path}: {row.key.label()} is recorded as {was} - a score change is a regression"
        " or a fix, not a new baseline; edit the row deliberately if it is intended"
    )


def _payload(rows: list[Row]) -> dict[str, object]:
    return {"schema": SCHEMA, "note": NOTE, "baselines": [_row_payload(item) for item in rows]}


def _row_payload(item: Row) -> dict[str, object]:
    return {
        **item.key.as_dict(),
        "recorded": item.recorded,
        "scores": {
            name: {"passed": score.passed, "total": score.total, "gating": score.gating}
            for name, score in item.scores.items()
        },
    }


def flush(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _columns(rows: list[Row], current: Row | None) -> list[tuple[str, dict[str, Score]]]:
    columns = [(f"baseline {item.key.label()}", item.scores) for item in rows]
    return columns + ([("this run", current.scores)] if current is not None else [])


def render(rows: list[Row], current: Row | None = None) -> str:
    """A markdown table: one column per baseline row, plus this run when given."""
    columns = _columns(rows, current)
    names = sorted({name for _, scores in columns for name in scores})
    head = "| Grader | " + " | ".join(label for label, _ in columns) + " |"
    lines = [head, "|---" * (len(columns) + 1) + "|"]
    lines.extend(
        f"| {name} | " + " | ".join(_cell(scores.get(name)) for _, scores in columns) + " |"
        for name in names
    )
    return "\n".join(lines + _footnote(columns))


def _footnote(columns: list[tuple[str, dict[str, Score]]]) -> list[str]:
    report_only = sorted(
        {name for _, scores in columns for name, score in scores.items() if not score.gating}
    )
    if not report_only:
        return []
    return ["", f"`*` report-only (no measured kappa, so no gate): {', '.join(report_only)}"]


def _cell(score: Score | None) -> str:
    if score is None:
        return "-"
    mark = "" if score.gating else "*"
    return f"{score.passed}/{score.total} ({score.rate:.0%}){mark}"


def today() -> str:
    return date.today().isoformat()
