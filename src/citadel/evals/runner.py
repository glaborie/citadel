"""Run the offline eval suite and print one result table."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from citadel.evals.graders import Grade, grade
from citadel.evals.schema import DatasetError, load_cases

DEFAULT_DATASET = Path("evals/golden/golden.json")


def run(dataset: Path) -> list[Grade]:
    return [result for case in load_cases(dataset) for result in grade(case)]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Grade recorded Citadel trajectories")
    parser.add_argument("dataset", nargs="?", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--json", action="store_true", help="emit results as JSON")
    args = parser.parse_args(argv)

    try:
        grades = run(args.dataset)
    except DatasetError as exc:
        print(f"dataset error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps([asdict(item) for item in grades], indent=2))
    else:
        for item in grades:
            if not item.passed:
                print(f"FAIL {item.case_id} {item.grader}: {item.detail}")
        passed = sum(1 for item in grades if item.passed)
        cases = len({item.case_id for item in grades})
        print(f"{passed}/{len(grades)} checks passed across {cases} cases")

    return 0 if all(item.passed for item in grades) else 1


if __name__ == "__main__":
    raise SystemExit(main())
