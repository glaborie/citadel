#!/usr/bin/env python3
"""Turn the calibration sample into a blind labelling sheet for a human rater.

The rater must not see the band, the mutation, or the judge's score: a sheet that says
"this one is a near-miss" measures the rater's agreement with the answer key, not with the
judge. So item ids are renumbered by a hash of the sample id, and the mapping lives in
`evals/calibration/label-key.json` - committed, because the labels have to be joined back
to the items, and named so that opening it early is a visible choice.

Usage:
    python scripts/label-sheet.py            # write the sheet and the key
    python scripts/label-sheet.py --check    # the committed sheet matches the sample
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from citadel.evals.rubric import render_evidence
from citadel.evals.schema import load_cases

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "evals" / "calibration" / "sample-v1.json"
KEY = ROOT / "evals" / "calibration" / "label-key-v1.json"  # the labelled artifact
RUBRICS = ROOT / "evals" / "golden" / "rubrics.json"
SHEET = ROOT / "docs" / "evals" / "calibration-sheet-v1.md"  # the labelled artifact
DIMENSIONS = ("plan", "grounding", "recovery", "escalation")


def sheet_path(version: int) -> Path:
    """One sheet per rubric version: the filled one is evidence, not a template."""
    return ROOT / "docs" / "evals" / f"calibration-sheet-v{version}.md"


def key_path(version: int) -> Path:
    return ROOT / "evals" / "calibration" / f"label-key-v{version}.json"


# No field list here on purpose: the sheet renders `render_evidence(case)`, the exact text
# the judge is given. A rater cannot then be shown less than the judge, and a field added to
# the record reaches both or neither.


def blind_ids(sample: dict[str, Any]) -> dict[str, str]:
    """A stable, non-alphabetical numbering, so an id cannot hint at the band."""

    def digest(case: dict[str, Any]) -> str:
        return hashlib.sha256(case["id"].encode()).hexdigest()

    ordered = sorted(sample["cases"], key=digest)
    return {case["id"]: f"item-{index:02d}" for index, case in enumerate(ordered, start=1)}


def _anchors(rubrics: dict[str, Any]) -> str:
    blocks = []
    for entry in rubrics["rubrics"]:
        levels = "\n".join(
            f"  - **{level}** — {text}"
            for level, text in sorted(entry["levels"].items(), reverse=True)
        )
        blocks.append(f"**{entry['dimension']}** — {entry['question']}\n{levels}")
    return "\n\n".join(blocks)


def _carried_scores(path: Path | None) -> dict[str, str]:
    """Scores already on the sheet, by blind id.

    Re-rendering the evidence corrects what a rater was shown; it is not a reason to throw
    away the labels they wrote, and item ids do not move when the rendering changes.
    """
    if path is None:
        return {}
    found: dict[str, str] = {}
    item = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## item-"):
            item = line[3:].strip()
        elif item and line.startswith("score: ") and any(c in "1234" for c in line[7:]):
            found[item] = line[len("score: ") :]
    return found


def render(sample: dict[str, Any], rubrics: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    ids = blind_ids(sample)
    by_blind = {ids[case["id"]]: case for case in sample["cases"]}
    by_case = {case.id: case for case in load_cases(SAMPLE)}
    carried = _carried_scores(SHEET if SHEET.exists() else None)

    head = f"""# Judge calibration sheet — sample v1, rubric v{rubrics["rubric_version"]}

Thirty trajectories. Score each one yourself, on all four dimensions, with a whole number
from 1 to 4, before you look at anything the judge said. Roughly 25 minutes; there is no
order to it, and stopping halfway is worse than not starting, because kappa needs every
item scored by both raters.

You are scoring the **answer against the record**, not the writing: a fluent answer that
claims something the events do not contain is a low grounding score, not a good one.

Write your numbers on the `score:` line under each item, like
`score: plan=3 grounding=4 recovery=2 escalation=3`.

**Do not open `evals/calibration/label-key.json` before you finish.** It holds the band and
the mutation for each item, and reading it would turn this into a test of the answer key.

## Rubric v{rubrics["rubric_version"]}

{_anchors(rubrics)}
"""

    blocks = [head]
    for blind in sorted(by_blind):
        case = by_blind[blind]
        evidence = render_evidence(by_case[case["id"]])
        blocks.append(
            f"""

## {blind}

```text
{evidence}
```

score: {carried.get(blind, "plan= grounding= recovery= escalation=")}
"""
        )
    key = {
        "sheet_version": 1,
        "sample": "evals/calibration/sample-v1.json",
        "note": (
            "Join key for the labels. Reading this before labelling measures the answer "
            "key, not the judge."
        ),
        "items": {blind: case["id"] for blind, case in by_blind.items()},
        "bands": {blind: case["provenance"]["band"] for blind, case in by_blind.items()},
    }
    return "".join(blocks), key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write the blind labelling sheet")
    parser.add_argument("--check", action="store_true", help="compare the committed sheet")
    parser.add_argument(
        "--version",
        type=int,
        default=None,
        help="sheet version; defaults to the rubric version in evals/golden/rubrics.json",
    )
    args = parser.parse_args(argv)

    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    rubrics = json.loads(RUBRICS.read_text(encoding="utf-8"))
    version = args.version if args.version is not None else int(rubrics["rubric_version"])
    target, keyfile = sheet_path(version), key_path(version)
    sheet, key = render(sample, rubrics)

    if args.check:
        problems = []

        # The committed sheet is the one a human filled in, so the `score:` lines are
        # expected to differ. Everything else - items, order, requests, events, answers,
        # anchors - must be exactly what this script would write today.
        def form(text: str) -> str:
            return "\n".join(
                "score:" if line.startswith("score:") else line for line in text.splitlines()
            )

        if form(target.read_text(encoding="utf-8")) != form(sheet):
            problems.append(f"{target.relative_to(ROOT)} is stale: run scripts/label-sheet.py")
        if json.loads(keyfile.read_text(encoding="utf-8")) != key:
            problems.append(f"{keyfile.relative_to(ROOT)} is stale: run scripts/label-sheet.py")
        for problem in problems:
            print(f"sheet: {problem}", file=sys.stderr)
        return 1 if problems else 0

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(sheet, encoding="utf-8")
    keyfile.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    print(f"sheet: {len(key['items'])} items -> {target.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
