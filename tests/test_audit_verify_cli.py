"""The audit verification command: exit codes an operator can rely on.

A checker whose failure is a printed word is a checker nobody gates on.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "audit-verify.py"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("audit_verify_cli", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load()


class FakeLedger:
    def __init__(self, *, ok: bool = True, gaps: list[str] | None = None) -> None:
        self.ok = ok
        self.gaps = gaps or []
        self.asked: list[str] = []

    def verify(self, tenant_id: str) -> tuple[bool, int]:
        self.asked.append(tenant_id)
        return self.ok, 3

    def unaudited(self, tenant_id: str) -> list[str]:
        return self.gaps


@pytest.fixture(autouse=True)
def dsn(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CITADEL_DB_DSN", "postgres://fake")


def _run(argv: list[str], ledger: FakeLedger) -> int:
    code: int = cli.main(argv, open_ledger=lambda _dsn: ledger)
    return code


def test_an_intact_tenant_exits_zero(capsys: pytest.CaptureFixture[str]) -> None:
    ledger = FakeLedger()
    assert _run(["audit-verify.py", "lab-a"], ledger) == 0
    assert "lab-a: chain intact over 3 event(s), 0 unaudited call(s)" in capsys.readouterr().out
    assert ledger.asked == ["lab-a"]


def test_a_broken_chain_exits_non_zero() -> None:
    assert _run(["audit-verify.py", "lab-a"], FakeLedger(ok=False)) == 1


def test_an_unaudited_call_exits_non_zero_and_names_the_key(
    capsys: pytest.CaptureFixture[str],
) -> None:
    ledger = FakeLedger(gaps=["lab-a:restart_service"])
    assert _run(["audit-verify.py", "lab-a"], ledger) == 1
    assert "unaudited: lab-a:restart_service" in capsys.readouterr().out


def test_each_tenant_is_checked(capsys: pytest.CaptureFixture[str]) -> None:
    ledger = FakeLedger()
    assert _run(["audit-verify.py", "lab-a", "lab-b"], ledger) == 0
    assert ledger.asked == ["lab-a", "lab-b"]
    assert "lab-b: chain intact" in capsys.readouterr().out


def test_naming_no_tenant_is_a_usage_error(capsys: pytest.CaptureFixture[str]) -> None:
    assert _run(["audit-verify.py"], FakeLedger()) == 2
    assert "usage:" in capsys.readouterr().err


def test_a_missing_dsn_is_a_usage_error(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CITADEL_DB_DSN")
    assert _run(["audit-verify.py", "lab-a"], FakeLedger()) == 2
    assert "CITADEL_DB_DSN is not set" in capsys.readouterr().err
