"""The retention command: what it prints, and the exit codes an operator gates on."""

from __future__ import annotations

import importlib.util
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "tool-outputs-purge.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("tool_outputs_purge_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load()


class FakeConn:
    def __init__(self, deleted: list[str]) -> None:
        self.deleted = deleted
        self.seen: list[tuple[str, tuple[Any, ...]]] = []

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any:
        self.seen.append((sql, params))
        rows = self.deleted

        class _Cursor:
            def fetchall(self) -> list[tuple[str]]:
                return [(digest,) for digest in rows]

        return _Cursor()


def _runner(conn: FakeConn) -> Any:
    @contextmanager
    def connect(_dsn: str) -> Iterator[FakeConn]:
        yield conn

    return connect


@pytest.fixture(autouse=True)
def dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CITADEL_OUTPUT_PURGE_DSN", "postgres://owner@db/citadel")
    monkeypatch.delenv("CITADEL_DB_DSN", raising=False)


def test_it_reports_what_the_delete_returned(capsys: pytest.CaptureFixture[str]) -> None:
    conn = FakeConn(["a", "b"])
    assert cli.main(["tool-outputs-purge.py"], connect=_runner(conn)) == 0
    out = capsys.readouterr().out
    assert "deleted 2 stored tool output body/bodies older than 90 days" in out
    assert conn.seen[-1][1] == (90,)


def test_the_period_can_be_passed(capsys: pytest.CaptureFixture[str]) -> None:
    conn = FakeConn([])
    assert cli.main(["tool-outputs-purge.py", "30"], connect=_runner(conn)) == 0
    assert conn.seen[-1][1] == (30,)
    assert "older than 30 days" in capsys.readouterr().out


def test_a_non_numeric_period_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tool-outputs-purge.py", "soon"], connect=_runner(FakeConn([]))) == 2
    assert "usage:" in capsys.readouterr().err


def test_a_zero_day_period_is_refused(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["tool-outputs-purge.py", "0"], connect=_runner(FakeConn([]))) == 2
    assert "zero days" in capsys.readouterr().err


def test_a_missing_dsn_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CITADEL_OUTPUT_PURGE_DSN")
    assert cli.main(["tool-outputs-purge.py"], connect=_runner(FakeConn([]))) == 2
    assert "CITADEL_OUTPUT_PURGE_DSN" in capsys.readouterr().err


def test_it_prefers_the_purge_dsn_over_the_app_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The app role cannot see every tenant under RLS, so the job needs its own grant."""
    monkeypatch.setenv("CITADEL_DB_DSN", "postgres://app@db/citadel")
    used: list[str] = []

    @contextmanager
    def connect(dsn: str) -> Iterator[FakeConn]:
        used.append(dsn)
        yield FakeConn([])

    assert cli.main(["tool-outputs-purge.py"], connect=connect) == 0
    assert used == ["postgres://owner@db/citadel"]
