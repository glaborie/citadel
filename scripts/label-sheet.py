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

ROOT = Path(__file__).parents[1]
SAMPLE = ROOT / "evals" / "calibration" / "sample-v1.json"
KEY = ROOT / "evals" / "calibration" / "label-key.json"
RUBRICS = ROOT / "evals" / "golden" / "rubrics.json"
SHEET = ROOT / "docs" / "evals" / "calibration-sheet-v1.md"
DIMENSIONS = ("plan", "grounding", "recovery", "escalation")

# The fields that identify an event to a reader; everything else is noise on the sheet.
EVENT_FIELDS = (
    "type",
    "agent_id",
    "risk_tier",
    "tool",
    "arguments",
    "tier",
    "status",
    "decision",
    "rule_id",
    "surface",
    "action",
    "categories",
    "outcome",
    "strategy",
    "citation_ids",
    "safety_flags",
    "tool_name",
    "source_uris",
    "top_k",
)


def blind_ids(sample: dict[str, Any]) -> dict[str, str]:
    """A stable, non-alphabetical numbering, so an id cannot hint at the band."""
    def digest(case: dict[str, Any]) -> str:
        return hashlib.sha256(case["id"].encode()).hexdigest()

    ordered = sorted(sample["cases"], key=digest)
    return {case["id"]: f"item-{index:02d}" for index, case in enumerate(ordered, start=1)}


def _events(case: dict[str, Any]) -> str:
    lines = []
    for event in case["events"]:
        parts = [f"{key}={event[key]}" for key in EVENT_FIELDS if key in event]
        lines.append("- " + " · ".join(parts))
    return "\n".join(lines)


def _anchors(rubrics: dict[str, Any]) -> str:
    blocks = []
    for entry in rubrics["rubrics"]:
        levels = "\n".join(
            f"  - **{level}** — {text}"
            for level, text in sorted(entry["levels"].items(), reverse=True)
        )
        blocks.append(f"**{entry['dimension']}** — {entry['question']}\n{levels}")
    return "\n\n".join(blocks)


def render(sample: dict[str, Any], rubrics: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    ids = blind_ids(sample)
    by_blind = {ids[case["id"]]: case for case in sample["cases"]}

    head = f"""# Judge calibration sheet — sample v1

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

## Rubric v{rubrics['rubric_version']}

{_anchors(rubrics)}
"""

    blocks = [head]
    for blind in sorted(by_blind):
        case = by_blind[blind]
        blocks.append(
            f"""

## {blind}

**Request:** {case['prompt']}

**Events**

{_events(case)}

**Answer**

> {case['answer']}

score: plan= grounding= recovery= escalation=
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
    args = parser.parse_args(argv)

    sample = json.loads(SAMPLE.read_text(encoding="utf-8"))
    rubrics = json.loads(RUBRICS.read_text(encoding="utf-8"))
    sheet, key = render(sample, rubrics)

    if args.check:
        problems = []
        if SHEET.read_text(encoding="utf-8") != sheet:
            problems.append(f"{SHEET.relative_to(ROOT)} is stale: run scripts/label-sheet.py")
        if json.loads(KEY.read_text(encoding="utf-8")) != key:
            problems.append(f"{KEY.relative_to(ROOT)} is stale: run scripts/label-sheet.py")
        for problem in problems:
            print(f"sheet: {problem}", file=sys.stderr)
        return 1 if problems else 0

    SHEET.parent.mkdir(parents=True, exist_ok=True)
    SHEET.write_text(sheet, encoding="utf-8")
    KEY.write_text(json.dumps(key, indent=2) + "\n", encoding="utf-8")
    print(f"sheet: {len(key['items'])} items -> {SHEET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
