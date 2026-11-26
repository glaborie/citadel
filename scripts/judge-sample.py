#!/usr/bin/env python3
"""Run the judge over the calibration sample and record its ordinal scores.

`judge_case` reports pass/fail against a threshold, which is what a gate needs. A kappa
needs the number underneath: two raters agreeing on "3" is a different measurement from
both of them reaching the same side of a line. So this script calls `judge.score` directly
and writes the score, per item and dimension, with the rationale that produced it.

A dimension the judge could not read is recorded as an error and makes the run exit
non-zero - an unread verdict is not a low score, and a calibration that filled the gap with
a default would produce a kappa about the default.

Usage:
    OMNIROUTE_URL=http://127.0.0.1:20128/v1 python scripts/judge-sample.py \\
        --alias auto/best-reasoning --analyzer http://172.27.0.4:3000
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import date
from pathlib import Path
from typing import Any

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))

SAMPLE = ROOT / "evals" / "calibration" / "sample-v1.json"
RUBRICS = ROOT / "evals" / "golden" / "rubrics.json"


def scores_path(version: int) -> Path:
    """One file per rubric version: a score belongs to the anchors it was read against."""
    return ROOT / "evals" / "calibration" / f"judge-scores-v{version}.json"


def _judge(alias: str, analyzer: str) -> Any:
    from citadel.env import optional_secret
    from citadel.evals.rubric import OmniJudge
    from citadel.model import OmniRouteClient

    client = OmniRouteClient(
        base_url=os.environ.get("OMNIROUTE_URL", "http://omniroute:20128/v1"),
        api_key=optional_secret("OMNIROUTE_API_KEY"),
        analyzer_url=analyzer,
        alias=alias,
        dlp_surface="record",
    )
    # The judge reads rendered ledger events, so its prompt is gated as `record`:
    # a fixture that trips the PERSON detector must not make an item ungradeable,
    # while a credential still blocks (see `OmniRouteClient.dlp_surface`).
    return OmniJudge(client, alias=alias)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Judge the calibration sample")
    parser.add_argument(
        "--version",
        type=int,
        default=1,
        help="rubric version whose score file to write",
    )
    parser.add_argument("--alias", required=True, help="model alias, as the gateway knows it")
    parser.add_argument(
        "--analyzer",
        default=os.environ.get("PRESIDIO_URL", "http://presidio:3000"),
        help="DLP analyzer the model client uses before any prompt leaves",
    )
    parser.add_argument("--out", type=Path, default=None, help="defaults to scores_path(version)")
    args = parser.parse_args(argv)
    out = args.out or scores_path(args.version)

    from citadel.evals.rubric import JudgeMisread, JudgeUnavailable, load_rubrics, render_evidence
    from citadel.evals.schema import load_cases

    rubrics = load_rubrics(RUBRICS)
    sample = load_cases(SAMPLE)
    judge = _judge(args.alias, args.analyzer)

    items: list[dict[str, Any]] = []
    problems = 0
    for case in sample:
        evidence = render_evidence(case)
        for dimension in case.judge:
            rubric = rubrics.get(dimension)
            if rubric is None:
                items.append({"id": case.id, "dimension": dimension, "error": "no rubric"})
                problems += 1
                continue
            try:
                verdict = judge.score(rubric, evidence)
            except (JudgeMisread, JudgeUnavailable) as exc:
                items.append({"id": case.id, "dimension": dimension, "error": str(exc)})
                problems += 1
                continue
            items.append(
                {
                    "id": case.id,
                    "dimension": dimension,
                    "score": verdict.score,
                    "rationale": verdict.rationale,
                }
            )

    payload = {
        "sample": "evals/calibration/sample-v1.json",
        "alias": args.alias,
        "rubric_version": json.loads(RUBRICS.read_text(encoding="utf-8"))["rubric_version"],
        "recorded": date.today().isoformat(),
        "items": items,
    }
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    scored = sum(1 for item in items if "score" in item)
    print(f"judge: {scored}/{len(items)} dimension scores from {args.alias} -> {args.out.name}")
    if problems:
        print(f"judge: {problems} dimension(s) unreadable; a gap is not a pass", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
