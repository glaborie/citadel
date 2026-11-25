"""The pack as a test run: one test per case, pending cases named as pending.

A case is executed only if ``harness.EXECUTORS`` has an implementation. The
rest are reported as pending with the reason, because a suite that silently
skips two thirds of its cases and prints "green" is the failure mode this whole
pack exists to prevent.
"""

from __future__ import annotations

import pytest

from tests.redteam import harness

pytestmark = pytest.mark.redteam

CASES = harness.load_cases()
BY_ID = {case.id: case for case in CASES}


def _ids(case: harness.Case) -> str:
    return case.id


@pytest.mark.parametrize("case", CASES, ids=_ids)
def test_case(case: harness.Case) -> None:
    if case.id not in harness.EXECUTORS:
        harness.COLLECTED[case.id] = ("pending", "no executor: needs the live stack")
        pytest.skip(f"{case.id} has no executor yet: {case.evidence}")
    outcome = harness.run(case)
    harness.COLLECTED[case.id] = ("pass" if outcome.passed else "fail", outcome.detail)
    assert outcome.passed, (
        f"{case.id} expected {case.verdict!r} ({case.evidence}), got {outcome.detail}"
    )


def test_every_executor_maps_to_a_case() -> None:
    orphans = sorted(set(harness.EXECUTORS) - set(BY_ID))
    assert not orphans, f"executors without a case in cases.json: {orphans}"


def test_pending_cases_are_declared_by_milestone() -> None:
    """Anything without an executor must be beyond today's milestone."""
    pending = {case.id for case in CASES if case.id not in harness.EXECUTORS}
    implemented = {case.id for case in CASES if case.id in harness.EXECUTORS}
    assert not (pending & implemented)
    for case_id in pending:
        assert BY_ID[case_id].milestone in {"v0.1", "v0.2", "v0.3", "v0.4"}
