"""Write the red-team report after a run, when asked to.

``CITADEL_REDTEAM_REPORT=1 pytest -m redteam`` regenerates
``docs/evals/red-team-report.md`` from what actually executed. The file is
generated, never edited: a report that can be produced without running the
cases is a document, not evidence.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tests.redteam import harness

REPORT = Path(__file__).parents[2] / "docs" / "evals" / "red-team-report.md"

BANNER = {
    "pass": "pass",
    "fail": "FAIL",
    "gap": "GAP",
    "pending": "pending",
}


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if not os.environ.get("CITADEL_REDTEAM_REPORT"):
        return

    harness.COLLECTED.update(harness.LIVE)
    cases = harness.load_cases()
    rows: list[str] = []
    counts = {"pass": 0, "fail": 0, "gap": 0, "pending": 0, "not run": 0}
    for case in cases:
        status, detail = harness.COLLECTED.get(case.id, ("not run", "not collected"))
        counts[status] = counts.get(status, 0) + 1
        rows.append(
            f"| {case.id} | {BANNER.get(status, status)} | {case.verdict} | "
            f"{case.category} | {detail.replace('|', '/')[:70]} |"
        )

    total = len(cases)
    executed = counts["pass"] + counts["fail"] + counts["gap"]
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    body = "\n".join(
        [
            "# Red-team report",
            "",
            f"Generated {stamp} from `pytest -m redteam`. Do not edit by hand.",
            "",
            f"**{counts['pass']} of {total} blocked or denied as specified** · "
            f"{counts['fail']} failing · {counts['gap']} known gaps · "
            f"{counts['pending']} pending · {counts['not run']} not run · "
            f"{executed} executed in this run.",
            "",
            "A pending case has no executor yet, which usually means it needs the",
            "live stack (Temporal, Postgres, the stub tool server). A gap is a case",
            "that runs and fails for a documented reason; the expectation is not",
            "lowered to make it green. Neither pending nor gap counts as passing.",
            "",
            "| Case | Status | Expected | Category | Observed |",
            "|---|---|---|---|---|",
            *rows,
            "",
            "## Known gaps in the pack",
            "",
            *[
                f"- **{case.id}** — {case.known_gap}"
                for case in cases
                if case.known_gap is not None
            ],
            "",
        ]
    )
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    REPORT.write_text(body, encoding="utf-8")
    print(f"\nred-team report written to {REPORT}")
