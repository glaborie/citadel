"""The operator's file for a PR body: derived name, closed permissions, removed."""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from citadel.tools import pr_text


@pytest.fixture(autouse=True)
def text_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv(pr_text.DIRECTORY_ENV, str(tmp_path / "pr-text"))
    return tmp_path / "pr-text"


def test_the_name_is_derived_so_a_caller_cannot_choose_it() -> None:
    first = pr_text.path_for("open_remediation_pr", "run-1")
    assert first == pr_text.path_for("open_remediation_pr", "run-1")
    assert first != pr_text.path_for("open_remediation_pr", "run-2")
    assert first.suffix == ".txt"
    assert pr_text.directory() in first.parents


def test_the_body_is_written_verbatim(text_dir: Path) -> None:
    """It is content, not a path: ellipses, ranges and fenced blocks survive."""
    body = "Fixes 0.1..0.2\n\n```\ngh pr diff\n```\n"
    path = pr_text.write(tool="open_remediation_pr", run_id="run-1", body=body)

    assert path.read_text(encoding="utf-8") == body
    assert path.parent == text_dir


def test_the_file_is_closed_to_everyone_else(text_dir: Path) -> None:
    """A body may quote the incident that caused it."""
    path = pr_text.write(tool="open_remediation_pr", run_id="run-1", body="x")

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, oct(mode)
    directory_mode = stat.S_IMODE(text_dir.stat().st_mode)
    assert directory_mode == 0o700, oct(directory_mode)


def test_nothing_half_written_is_left_behind(text_dir: Path) -> None:
    pr_text.write(tool="open_remediation_pr", run_id="run-1", body="x")

    written = pr_text.path_for("open_remediation_pr", "run-1")
    assert [entry.name for entry in text_dir.iterdir()] == [written.name]


def test_a_second_write_replaces_the_first(text_dir: Path) -> None:
    """Same run, same name: an approval cannot half-publish two bodies."""
    pr_text.write(tool="open_remediation_pr", run_id="run-1", body="first")
    path = pr_text.write(tool="open_remediation_pr", run_id="run-1", body="second")

    assert path.read_text(encoding="utf-8") == "second"
    assert len(list(text_dir.iterdir())) == 1


def test_discard_removes_it_and_is_idempotent() -> None:
    path = pr_text.write(tool="open_remediation_pr", run_id="run-1", body="x")

    pr_text.discard(path)
    assert not path.exists()
    pr_text.discard(path)


def test_a_failed_replace_leaves_no_part_file_across(
    text_dir: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The write goes through a temporary name, so a crash cannot publish half."""

    def boom(*_: object, **__: object) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        pr_text.write(tool="open_remediation_pr", run_id="run-1", body="x")

    monkeypatch.undo()
    assert list(text_dir.iterdir()) == []
