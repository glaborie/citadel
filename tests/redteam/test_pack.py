"""The pack as a test run: one test per case, pending cases named as pending.

A case is executed only if ``harness.EXECUTORS`` has an implementation. The
rest are reported as pending with the reason, because a suite that silently
skips two thirds of its cases and prints "green" is the failure mode this whole
pack exists to prevent.
"""

from __future__ import annotations

import pytest

from citadel import __version__
from tests.redteam import harness

pytestmark = pytest.mark.redteam

CASES = harness.load_cases()
BY_ID = {case.id: case for case in CASES}


def _ids(case: harness.Case) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_case(case: harness.Case) -> None:
    if case.id not in harness.EXECUTORS:
        if case.live is not None:
            # Covered elsewhere: say where, so "pending" cannot hide a case that
            # nobody runs at all.
            harness.COLLECTED[case.id] = ("pending", f"live-only: {case.live}")
            pytest.skip(f"{case.id} runs in the live suite: {case.live}")
        harness.COLLECTED[case.id] = ("pending", f"not implemented; owner {case.owner}")
        pytest.skip(f"{case.id} has no executor yet (owner {case.owner}): {case.evidence}")
    outcome = harness.run(case)
    if not outcome.passed and case.known_gap is not None:
        harness.COLLECTED[case.id] = ("gap", outcome.detail)
        pytest.xfail(f"{case.id} known gap: {case.known_gap} ({outcome.detail})")
    harness.COLLECTED[case.id] = ("pass" if outcome.passed else "fail", outcome.detail)
    assert outcome.passed, (
        f"{case.id} expected {case.verdict!r} ({case.evidence}), got {outcome.detail}"
    )


def test_every_executor_maps_to_a_case() -> None:
    orphans = sorted(set(harness.EXECUTORS) - set(BY_ID))
    assert not orphans, f"executors without a case in cases.json: {orphans}"


CURRENT = harness.current_milestone(__version__)


def test_every_case_is_executed_or_declared() -> None:
    """No case may be quietly unimplemented: executed, live-covered, or owned.

    The accepted-milestone set used to include the one being shipped, so a case
    pending today passed the check that was supposed to catch it. `declaration_gaps`
    fails closed instead, and `tests/test_pack_guard.py` proves it rejects each way a
    case can go missing.
    """
    gaps = harness.declaration_gaps(CASES, current=CURRENT)
    assert not gaps, "the pack declares cases nobody executes:\n" + "\n".join(gaps)


def test_the_shipped_milestone_is_read_from_the_package() -> None:
    assert f"v{'.'.join(__version__.split('.')[:2])}" == CURRENT
    assert any(case.milestone == CURRENT for case in CASES), "the pack ships no case for today"
