"""The gap the hash chain cannot see: a tool that ran with no event behind it.

Removing a row breaks no hash, and a missing event is not an edit. So the
question "did every executed tool call leave an audit event?" has to be asked
explicitly, and that query is the control under test here.
"""

from __future__ import annotations

from typing import Any

import pytest

from citadel import audit
from citadel.audit import AuditLedger


class _Result:
    def __init__(self, rows: list[tuple[str, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[str, ...]]:
        return self._rows

    def fetchone(self) -> tuple[str, ...] | None:
        return self._rows[0] if self._rows else None

    def __enter__(self) -> _Result:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _Conn:
    def __init__(self, rows: list[tuple[str, ...]]) -> None:
        self.rows = rows
        self.sql = ""
        self.params: Any = None

    def execute(self, sql: str, params: Any = None) -> _Result:
        self.sql = " ".join(sql.split())
        self.params = params
        return _Result(self.rows)

    def __enter__(self) -> _Conn:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def test_unaudited_returns_the_keys_the_query_found(monkeypatch: pytest.MonkeyPatch) -> None:
    conn = _Conn([("run-1:restart_service",), ("run-2:read_logs",)])
    monkeypatch.setattr(audit, "tenant_connection", lambda dsn, tenant: conn)

    keys = AuditLedger("postgres://fake").unaudited("lab-a")

    assert keys == ["run-1:restart_service", "run-2:read_logs"]
    assert conn.params == ("lab-a",)


def test_the_gap_query_only_counts_calls_that_claim_to_have_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    conn = _Conn([])
    monkeypatch.setattr(audit, "tenant_connection", lambda dsn, tenant: conn)

    AuditLedger("postgres://fake").unaudited("lab-a")

    assert "tool_calls" in conn.sql
    assert "status IN ('executed', 'sent')" in conn.sql
    # The join key is the idempotency key: a tool.call event carries it, and it
    # is unique per (run, tool, arguments) rather than merely per tool.
    assert "ae.payload->>'idempotency_key' = tc.idempotency_key" in conn.sql
    assert "NOT EXISTS" in conn.sql
