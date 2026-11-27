#!/usr/bin/env python3
"""Join the human labels to the judge's scores, in the shape cohens_kappa.py reads.

The human labels come from the sheet itself - the file the rater filled in - because that
is the artifact that was actually labelled. Parsing it here means the numbers cannot drift
from what was signed, and a half-filled sheet fails instead of producing a kappa over the
items someone got to.

Usage:
    python scripts/label-merge.py                     # write the kappa inputs
    python scripts/label-merge.py --check             # both inputs exist and are complete
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).parents[1]
SHEET = ROOT / "docs" / "evals" / "calibration-sheet-v1.md"


def artifact_paths(version: int) -> tuple[Path, Path, Path, Path, Path]:
    """The five artifacts of one rubric version: sheet, key, judge, human, per-dimension.

    Version 1 keeps the bare `labels/` directory because that measurement is signed
    evidence; later versions get their own, so a re-measurement cannot overwrite it.
    """
    calibration = ROOT / "evals" / "calibration"
    labels = calibration / "labels" if version == 1 else calibration / f"labels-v{version}"
    return (
        ROOT / "docs" / "evals" / f"calibration-sheet-v{version}.md",
        calibration / f"label-key-v{version}.json",
        calibration / f"judge-scores-v{version}.json",
        calibration / f"labels-human-v{version}.json",
        labels,
    )


HUMAN = ROOT / "evals" / "calibration" / "labels-human-v1.json"
LABELS = ROOT / "evals" / "calibration" / "labels"
DIMENSIONS = ("plan", "grounding", "recovery", "escalation")
SCORE = re.compile(r"score: (.*)")


def parse_sheet(text: str) -> dict[str, dict[str, int]]:
    """{item-01: {plan: 3, ...}} from the sheet the rater filled, or a loud failure."""
    scores: dict[str, dict[str, int]] = {}
    item = ""
    for line in text.splitlines():
        if line.startswith("## item-"):
            item = line[3:].strip()
        elif (found := SCORE.search(line)) and item:
            values: dict[str, int] = {}
            for pair in found.group(1).split():
                name, _, raw = pair.partition("=")
                if not raw:
                    continue
                if not raw.isdigit() or not 1 <= int(raw) <= 4:
                    raise ValueError(f"{item}: {name}={raw!r} is not a score from 1 to 4")
                values[name] = int(raw)
            scores[item] = values
    return scores


def _complete(scores: dict[str, dict[str, int]]) -> list[str]:
    problems = []
    for item in sorted(scores):
        missing = [name for name in DIMENSIONS if name not in scores[item]]
        if missing:
            problems.append(f"{item}: unscored {', '.join(missing)}")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join human labels and judge scores")
    parser.add_argument("--check", action="store_true", help="verify the merged inputs")
    parser.add_argument(
        "--version",
        type=int,
        default=1,
        help="rubric version whose sheet, key, scores and labels to pair",
    )
    args = parser.parse_args(argv)
    sheet_path, key_path, judge_path, human_path, labels_dir = artifact_paths(args.version)

    sheet = parse_sheet(sheet_path.read_text(encoding="utf-8"))
    key = json.loads(key_path.read_text(encoding="utf-8"))
    problems = _complete(sheet)
    if set(sheet) != set(key["items"]):
        problems.append(f"sheet covers {len(sheet)} items, the key covers {len(key['items'])}")
    if problems:
        for problem in problems:
            print(f"labels: {problem}", file=sys.stderr)
        return 1

    human_path.write_text(
        json.dumps(
            {
                "sheet": f"docs/evals/calibration-sheet-v{args.version}.md",
                "items": [
                    {"id": item, "sample_id": key["items"][item], **sheet[item]}
                    for item in sorted(sheet)
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    if args.check:
        print(f"labels: {len(sheet)} items, four dimensions each")
        return 0

    judged: dict[tuple[str, str], int] = {}
    if judge_path.exists():
        payload = json.loads(judge_path.read_text(encoding="utf-8"))
        judged = {
            (item["id"], item["dimension"]): int(item["score"])
            for item in payload["items"]
            if "score" in item
        }

    labels_dir.mkdir(parents=True, exist_ok=True)
    for dimension in DIMENSIONS:
        rows = [
            {
                # The sample id, not the sheet id: this file is joined against the judge
                # scores, and a reader should not need the key to know which item it is.
                "id": key["items"][item],
                "human": values[dimension],
                "judge": judged[(key["items"][item], dimension)],
            }
            for item, values in sorted(sheet.items())
            if (key["items"][item], dimension) in judged
        ]
        missing = [item for item in sorted(sheet) if (key["items"][item], dimension) not in judged]
        if not rows:
            print(
                f"labels: {dimension} has no judge scores; run scripts/judge-sample.py first",
                file=sys.stderr,
            )
            return 1
        if missing:
            # Not a failure to hide: a judged item the judge could not read is an item
            # without a second rating, and the kappa has to say how many it lost.
            print(
                f"labels: {dimension}: {len(missing)} item(s) unjudged "
                f"({', '.join(missing)}) - kappa will use n={len(rows)}",
                file=sys.stderr,
            )
        (labels_dir / f"{dimension}.json").write_text(
            json.dumps({"items": rows}, indent=2) + "\n", encoding="utf-8"
        )
        print(f"labels: {dimension} -> {len(rows)} paired items")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
