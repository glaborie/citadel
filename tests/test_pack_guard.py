"""The coverage guard is a control too, so it gets tests that fail when it is wrong.

Each test feeds ``declaration_gaps`` one way a case can go missing. The version
this replaces accepted any case whose milestone was in ``{v0.1..v0.4}`` - which is
every case - so it reported the pack instead of constraining it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.redteam import harness


def _case(
    case_id: str, *, milestone: str, live: str | None = None, owner: str | None = None
) -> harness.Case:
    return harness.Case(
        id=case_id,
        title="synthetic",
        category="dlp",
        tier="T0",
        surface="api",
        fixture=None,
        verdict="blocked",
        evidence="synthetic",
        side_effects="none",
        controls=("x",),
        milestone=milestone,
        known_gap=None,
        live=live,
        owner=owner,
    )


@pytest.fixture
def live_dir(tmp_path: Path) -> Path:
    (tmp_path / "live").mkdir()
    (tmp_path / "live" / "test_synthetic.py").write_text("RT-SYN-01\n", encoding="utf-8")
    return tmp_path


def test_a_case_pending_at_the_shipped_milestone_is_a_gap() -> None:
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.1")], current="v0.1"
    )
    assert any("shipped milestone" in gap for gap in gaps), gaps


def test_a_case_pending_beyond_the_shipped_milestone_needs_an_owner() -> None:
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.2")], current="v0.1"
    )
    assert gaps == ["RT-SYN-01: pending with no owner"]


def test_an_owned_case_beyond_the_shipped_milestone_is_accepted() -> None:
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.2", owner="#96")], current="v0.1"
    )
    assert gaps == []


def test_a_live_declaration_must_point_at_a_real_test(live_dir: Path) -> None:
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.1", live="live/test_missing.py")],
        current="v0.1",
        root=live_dir,
    )
    assert any("does not exist" in gap for gap in gaps), gaps


def test_a_live_declaration_must_name_the_case(live_dir: Path) -> None:
    """A path that no longer mentions the case is a comment, not coverage."""
    (live_dir / "live" / "test_synthetic.py").write_text("nothing here\n", encoding="utf-8")
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.1", live="live/test_synthetic.py")],
        current="v0.1",
        root=live_dir,
    )
    assert gaps == ["RT-SYN-01: live/test_synthetic.py never names the case"]


def test_live_coverage_at_the_shipped_milestone_is_accepted(live_dir: Path) -> None:
    gaps = harness.declaration_gaps(
        [_case("RT-SYN-01", milestone="v0.1", live="live/test_synthetic.py")],
        current="v0.1",
        root=live_dir,
    )
    assert gaps == []


def test_a_case_with_a_live_declaration_and_no_executor_is_not_double_counted(
    live_dir: Path,
) -> None:
    """Declaring both would make the offline run claim a live case as its own."""
    harness.EXECUTORS["RT-SYN-99"] = harness.exec_cross_specialist
    try:
        gaps = harness.declaration_gaps(
            [_case("RT-SYN-99", milestone="v0.1", live="live/test_synthetic.py")],
            current="v0.1",
            root=live_dir,
        )
    finally:
        del harness.EXECUTORS["RT-SYN-99"]
    assert gaps == ["RT-SYN-99: has an executor and a live declaration"]


def test_the_shipped_pack_has_no_gaps() -> None:
    from citadel import __version__

    cases = harness.load_cases()
    current = harness.current_milestone(__version__)
    assert harness.declaration_gaps(cases, current=current) == []
