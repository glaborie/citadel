#!/usr/bin/env python3
"""Cohen's kappa for judge calibration.

The judge is a measuring instrument. Before its scores may gate a merge, it has
to agree with a human rater at a level you can defend. This script computes
nominal kappa between two raters over the same labelled items and prints the
interpretation band used in `docs/evals/judge-calibration.md`.

Input (JSON):
    {"items": [{"id": "t-001", "human": 3, "judge": 3}, ...]}

Output:
    {"n": 30, "observed_agreement": 0.83, "expected_agreement": 0.41,
     "kappa": 0.71, "band": "substantial", "gating_allowed": true,
     "confusions": {"3->2": 3}}

Usage:
    python scripts/cohens_kappa.py labels.json
    python scripts/cohens_kappa.py labels.json --json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def kappa(pairs: list[tuple[object, object]]) -> dict[str, object]:
    """Nominal kappa over paired labels. Labels may be ints or strings."""
    if not pairs:
        raise ValueError("no paired labels")
    n = len(pairs)
    observed = sum(1 for human, judge in pairs if human == judge) / n
    human_counts = Counter(human for human, _ in pairs)
    judge_counts = Counter(judge for _, judge in pairs)
    expected = sum(
        (human_counts[label] / n) * (judge_counts[label] / n)
        for label in set(human_counts) | set(judge_counts)
    )
    value = 0.0 if expected == 1 else (observed - expected) / (1 - expected)
    return {
        "n": n,
        "observed_agreement": round(observed, 4),
        "expected_agreement": round(expected, 4),
        "kappa": round(value, 4),
    }


def band(value: float) -> tuple[str, bool]:
    """Landis & Koch bands, with a gating decision attached."""
    if value < 0.0:
        return "poor", False
    if value < 0.21:
        return "slight", False
    if value < 0.41:
        return "fair", False
    if value < 0.61:
        return "moderate", False
    if value < 0.81:
        return "substantial", True
    return "almost perfect", True


def confusions(pairs: list[tuple[object, object]]) -> dict[str, int]:
    counts = Counter(f"{human}->{judge}" for human, judge in pairs if human != judge)
    return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="JSON file with items[]")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)

    payload = json.loads(args.input.read_text(encoding="utf-8"))
    items = payload["items"]
    if len(items) < 20:
        print(
            f"warning: {len(items)} items; kappa is unstable below 20 and misleading below 10",
            file=sys.stderr,
        )
    pairs = [(item["human"], item["judge"]) for item in items]
    result = kappa(pairs)
    name, allowed = band(float(result["kappa"]))
    result["band"] = name
    result["gating_allowed"] = allowed
    result["confusions"] = confusions(pairs)

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"items              {result['n']}")
        print(f"observed agreement {result['observed_agreement']}")
        print(f"expected agreement {result['expected_agreement']}")
        print(f"kappa              {result['kappa']}  ({name})")
        print(f"judge may gate     {'yes' if allowed else 'no'}")
        if not allowed:
            print("action             tighten the rubric or add few-shot anchors")
        for pair, count in result["confusions"].items():
            print(f"  disagreement     {pair}: {count}")
    return 0 if allowed else 2


if __name__ == "__main__":
    raise SystemExit(main())
