"""The row-level security GUC is the control; nothing asserted it was set.

Deleting the ``set_config`` call used to leave the whole suite green. This test
records the statements a connection receives, so removing the call - or changing
it to a session-level setting that leaks across pooled connections - fails.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from citadel import db


class _Transaction:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: Any) -> None:
        return None


class _Connection:
    def __init__(self, seen: list[tuple[str, Any]]) -> None:
        self.seen = seen

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction()

    def execute(self, statement: str, params: Any = None) -> None:
        self.seen.append((statement, params))


@pytest.fixture
def seen(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, Any]]:
    recorded: list[tuple[str, Any]] = []

    def connect(_dsn: str) -> _Connection:
        return _Connection(recorded)

    monkeypatch.setattr(psycopg, "connect", connect)
    return recorded


def test_the_tenant_is_set_as_a_local_variable(seen: list[tuple[str, Any]]) -> None:
    """Local, not session: a pooled connection would otherwise keep the last tenant."""
    with db.tenant_connection("postgres://fake", "lab-a") as conn:
        conn.execute("SELECT 1")

    assert seen[0][0] == "SELECT set_config('app.tenant_id', %s, true)"
    assert seen[0][1] == ("lab-a",)
    assert "SELECT 1" in [statement for statement, _ in seen]


def test_a_connection_without_a_tenant_is_refused(seen: list[tuple[str, Any]]) -> None:
    """An empty claim must not open a connection that sees every tenant."""
    with pytest.raises(ValueError, match="without a tenant"), db.tenant_connection(
        "postgres://fake", ""
    ):
        pass
