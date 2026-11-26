"""Judge the soft dimensions, without letting an unread verdict look like a pass."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from citadel.env import optional_secret
from citadel.evals import baseline
from citadel.evals.graders import Grade, grade
from citadel.evals.rubric import Judge, OmniJudge, judge_case, load_rubrics
from citadel.evals.schema import DatasetError, load_cases

DEFAULT_DATASET = Path("evals/golden/golden.json")
DEFAULT_RUBRICS = Path("evals/golden/rubrics.json")


def run(
    dataset: Path,
    *,
    judge: Judge | None = None,
    rubrics_path: Path = DEFAULT_RUBRICS,
) -> list[Grade]:
    """Deterministic grades always; judged rubrics only when a judge is supplied.

    The default path stays offline and reproducible: CI runs the deterministic
    suite, and the judged one is opted into explicitly.
    """
    cases = load_cases(dataset)
    rubrics = load_rubrics(rubrics_path) if judge is not None else {}
    results: list[Grade] = []
    for case in cases:
        results.extend(grade(case))
        if judge is not None and case.judge:
            results.extend(judge_case(case, case.judge, rubrics, judge))
    return results


def _judge_from_env(alias: str, analyzer_url: str) -> Judge:
    from citadel.model import OmniRouteClient

    client = OmniRouteClient(
        base_url=os.environ.get("OMNIROUTE_URL", "http://omniroute:20128/v1"),
        api_key=optional_secret("OMNIROUTE_API_KEY"),
        analyzer_url=analyzer_url,
        alias=alias or "auto/best-fast",
    )
    return OmniJudge(client, alias=alias)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade recorded Citadel trajectories")
    parser.add_argument("dataset", nargs="?", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    parser.add_argument(
        "--judge",
        metavar="ALIAS",
        help="also run judged rubrics through this model alias (needs the gateway)",
    )
    parser.add_argument(
        "--rubrics",
        type=Path,
        default=DEFAULT_RUBRICS,
        help="rubric catalogue for judged dimensions",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=baseline.DEFAULT_BASELINE,
        help="recorded baselines to compare against",
    )
    parser.add_argument(
        "--table", action="store_true", help="print the baseline table as markdown on stdout"
    )
    parser.add_argument(
        "--record", action="store_true", help="record this run as a baseline row (stderr)"
    )
    parser.add_argument(
        "--gate", action="store_true", help="fail when a grader is below its baseline"
    )
    args = parser.parse_args(argv)

    judge = _judge_from_env(args.judge, "http://presidio:3000") if args.judge else None
    try:
        grades = run(args.dataset, judge=judge, rubrics_path=args.rubrics)
    except DatasetError as exc:
        print(f"dataset error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in grades], indent=2))
    else:
        for item in grades:
            if item.passed:
                continue
            label = "FAIL" if item.gating else "NOTE"
            print(f"{label} {item.case_id} {item.grader}: {item.detail}")
        passed = sum(1 for item in grades if item.passed)
        cases = len({item.case_id for item in grades})
        # Under --table, stdout is markdown and nothing else: a step summary that
        # starts with a sentence is a step summary that renders as broken markdown.
        summary_stream = sys.stderr if args.table else sys.stdout
        print(f"{passed}/{len(grades)} checks passed across {cases} cases", file=summary_stream)

    row = _baseline_row(args, grades)
    if args.record:
        print(baseline.record(args.baseline, row), file=sys.stderr)
    if args.table:
        print(baseline.render(baseline.load(args.baseline), row))
    problems = _gate(args, row) if args.gate else []
    for problem in problems:
        print(f"gate: {problem}", file=sys.stderr)
    if args.gate and not problems:
        gating = [score for score in row.scores.values() if score.gating]
        print(f"gate: {len(gating)} gating graders at or above baseline", file=sys.stderr)

    # A report-only dimension cannot fail the run; that is the whole point of
    # gating=false in the rubric catalogue.
    ungraded = [
        f"{item.case_id} {item.grader}" for item in grades if item.gating and not item.passed
    ]
    return 1 if problems or ungraded else 0


def _baseline_row(args: argparse.Namespace, grades: list[Grade]) -> baseline.Row:
    """This run as a row: the scores, and what the trajectories say they ran under."""
    cases = load_cases(args.dataset)
    key = baseline.key_for(
        cases,
        dataset=baseline.dataset_version(args.dataset),
        judge=args.judge or baseline.OFFLINE,
    )
    return baseline.Row(key=key, scores=baseline.summarise(grades), recorded=baseline.today())


def _gate(args: argparse.Namespace, row: baseline.Row) -> list[str]:
    """What is below the row with this exact key. An empty list is a pass."""
    rows = [item for item in baseline.load(args.baseline) if item.key == row.key]
    if not rows:
        return [f"no baseline row for {row.key.label()} - record one with --record"]
    return baseline.compare(row.scores, rows[0])


if __name__ == "__main__":
    raise SystemExit(main())
