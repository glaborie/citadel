"""Tool activity retry semantics: what a repeated attempt may do.

The risky case is a write that was already handed to the operator before the
worker died. Temporal retries the activity, so the activity itself has to
decide whether re-running is safe. These tests drive that decision with a fake
connection; no database is needed.
"""

from __future__ import annotations

import json
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, cast

import pytest

from citadel.workflows import activities
from citadel.workflows.activities import ToolActivities, idempotency_key
from citadel.workflows.types import ToolCall, ToolResult


class _Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class FakeDB:
    """Just enough of tool_calls: claim, mark sent, finish, read back."""

    def __init__(self, rows: dict[str, dict[str, Any]] | None = None) -> None:
        self.rows: dict[str, dict[str, Any]] = rows or {}

    @contextmanager
    def connect(self, _dsn: str, _tenant: str) -> Iterator[FakeConn]:
        yield FakeConn(self)


class FakeConn:
    def __init__(self, db: FakeDB) -> None:
        self._db = db

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _Cursor:
        statement = " ".join(sql.split())
        if statement.startswith("INSERT INTO tool_calls"):
            key = str(params[0])
            if key in self._db.rows:
                return _Cursor(None)
            self._db.rows[key] = {"status": "started", "result": None}
            return _Cursor(("id",))
        if statement.startswith("SELECT status, result"):
            row = self._db.rows.get(str(params[0]))
            return _Cursor((row["status"], row["result"]) if row else None)
        if statement == "UPDATE tool_calls SET status = 'sent' WHERE idempotency_key = %s":
            self._db.rows[str(params[0])]["status"] = "sent"
            return _Cursor(None)
        if statement.startswith("UPDATE tool_calls SET status = %s"):
            status, result, key = params
            self._db.rows[str(key)] = {"status": status, "result": json.loads(result)}
            return _Cursor(None)
        raise AssertionError(f"unexpected SQL: {statement}")


def call(tool: str) -> ToolCall:
    return ToolCall(
        run_id="11111111-1111-1111-1111-111111111111",
        tenant_id="lab-a",
        user_id="user-alice",
        agent_id="docker" if tool == "restart_service" else "github",
        tool=tool,
        arguments={"service": "checkout-api"} if tool == "restart_service" else {"repo": "a/b"},
    )


def build(monkeypatch: pytest.MonkeyPatch, db: FakeDB, invoke: Any) -> ToolActivities:
    monkeypatch.setattr(activities, "tenant_connection", db.connect)
    impl = ToolActivities(
        checker=cast(Any, None),
        run_store=cast(Any, None),
        dsn="unused",
        runner_url="http://runner",
        operator_url="http://operator",
    )
    monkeypatch.setattr(impl, "_invoke", invoke)
    return impl


def recorder(invoked: list[ToolCall]) -> Any:
    def invoke(item: ToolCall) -> ToolResult:
        invoked.append(item)
        return executed(item)

    return invoke


def executed(item: ToolCall) -> ToolResult:
    return ToolResult(
        status="executed",
        tool=item.tool,
        rule_id="tool.executed",
        detail="stub ran",
        output={"ok": 1},
    )


def test_the_call_is_marked_sent_before_it_leaves_the_process(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The marker is what a retry reads to decide that it must not repeat."""
    db = FakeDB()
    seen: list[str] = []

    def invoke(item: ToolCall) -> ToolResult:
        seen.append(db.rows[idempotency_key(item)]["status"])
        return executed(item)

    impl = build(monkeypatch, db, invoke)
    result = impl.execute_tool(call("read_logs"))

    assert seen == ["sent"], "a crash mid-call must find the row already marked sent"
    assert result.status == "executed"
    assert db.rows[idempotency_key(call("read_logs"))]["status"] == "executed"


def test_transport_failure_propagates_so_temporal_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = FakeDB()

    def invoke(_item: ToolCall) -> ToolResult:
        raise urllib.error.URLError("connection refused")

    impl = build(monkeypatch, db, invoke)
    with pytest.raises(urllib.error.URLError):
        impl.execute_tool(call("read_logs"))

    row = db.rows[idempotency_key(call("read_logs"))]
    assert row["status"] == "sent", "the attempt must stay visible to the retry"


def test_a_write_that_was_sent_is_never_repeated(monkeypatch: pytest.MonkeyPatch) -> None:
    """The one genuinely unknown outcome: report it, do not guess."""
    item = call("restart_service")
    db = FakeDB({idempotency_key(item): {"status": "sent", "result": None}})
    invoked: list[ToolCall] = []

    impl = build(monkeypatch, db, recorder(invoked))
    result = impl.execute_tool(item)

    assert invoked == []
    assert result.status == "failed"
    assert result.rule_id == "tool.possibly_executed"


def test_a_read_that_was_sent_is_attempted_again(monkeypatch: pytest.MonkeyPatch) -> None:
    item = call("read_logs")
    db = FakeDB({idempotency_key(item): {"status": "sent", "result": None}})
    invoked: list[ToolCall] = []

    impl = build(monkeypatch, db, recorder(invoked))
    result = impl.execute_tool(item)

    assert len(invoked) == 1
    assert result.status == "executed"


def test_a_finished_call_replays_its_stored_output(monkeypatch: pytest.MonkeyPatch) -> None:
    item = call("read_logs")
    db = FakeDB({idempotency_key(item): {"status": "executed", "result": {"stdout": "hi"}}})
    invoked: list[ToolCall] = []

    impl = build(monkeypatch, db, recorder(invoked))
    result = impl.execute_tool(item)

    assert invoked == []
    assert result.status == "replayed"
    assert result.output == {"stdout": "hi"}


def test_a_refusal_is_terminal_and_recorded(monkeypatch: pytest.MonkeyPatch) -> None:
    item = call("read_logs")
    db = FakeDB()

    def invoke(_item: ToolCall) -> ToolResult:
        return ToolResult(status="failed", tool="read_logs", rule_id="tool.refused", detail="403")

    impl = build(monkeypatch, db, invoke)
    result = impl.execute_tool(item)

    assert result.status == "failed"
    assert db.rows[idempotency_key(item)]["status"] == "failed"
