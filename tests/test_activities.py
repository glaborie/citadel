"""Tool activity retry semantics: what a repeated attempt may do.

The risky case is a write that was already handed to the operator before the
worker died. Temporal retries the activity, so the activity itself has to
decide whether re-running is safe. These tests drive that decision with a fake
connection; no database is needed.
"""

from __future__ import annotations

import io
import json
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from types import SimpleNamespace
from typing import Any, cast

import pytest

from citadel.hashing import arguments_hash
from citadel.policy import Decision
from citadel.workflows import activities
from citadel.workflows.activities import RunActivities, ToolActivities, idempotency_key
from citadel.workflows.types import RunEnd, ToolCall, ToolResult


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


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> SimpleNamespace:
        self.events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(self.events)}")


def build(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, invoke: Any, audit: Any = None
) -> ToolActivities:
    monkeypatch.setattr(activities, "tenant_connection", db.connect)
    impl = ToolActivities(
        checker=cast(Any, None),
        run_store=cast(Any, None),
        dsn="unused",
        runner_url="http://runner",
        operator_url="http://operator",
        audit=cast(Any, audit or FakeAudit()),
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


class Reply:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def test_dlp_reports_on_a_successful_call_reach_the_ledger(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pass has to be recorded too: it is the proof the control ran."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    report = {"surface": "input", "action": "pass", "categories": [], "findings": []}

    def urlopen(_request: Any, timeout: Any = None) -> Reply:
        return Reply({"allowlist_id": "docker.ps", "dlp": [report]})

    monkeypatch.setattr(activities, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    assert result.status == "executed"
    assert [event["event_type"] for event in ledger.events] == ["dlp.event"]
    assert ledger.events[0]["payload"]["surface"] == "input"
    assert ledger.events[0]["payload"]["run_id"] == call("read_logs").run_id


def test_a_dlp_block_is_audited_and_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    report = {"surface": "input", "action": "block", "categories": ["GITHUB_TOKEN"]}
    body = json.dumps({"detail": {"reason": "dlp_blocked", "dlp": [report]}}).encode()

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        raise urllib.error.HTTPError(
            request.full_url, 403, "Forbidden", Message(), io.BytesIO(body)
        )

    monkeypatch.setattr(activities, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    assert (result.status, result.rule_id) == ("failed", "dlp.blocked")
    assert ledger.events[0]["payload"]["categories"] == ["GITHUB_TOKEN"]
    assert "GITHUB_TOKEN" not in result.detail, "the ledger holds the detail, not a result"


def test_an_unavailable_detector_is_reported_as_such(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    body = json.dumps(
        {"detail": {"reason": "dlp_unavailable", "dlp": [{"surface": "input", "action": "block"}]}}
    ).encode()

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        raise urllib.error.HTTPError(
            request.full_url, 503, "Unavailable", Message(), io.BytesIO(body)
        )

    monkeypatch.setattr(activities, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    assert result.rule_id == "dlp.unavailable"
    assert len(ledger.events) == 1


def test_policy_decision_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    decision = Decision("allow", "policy.allowed", "allowed", "T0")
    monkeypatch.setattr(activities, "authorize", lambda *args, **kwargs: decision)

    impl.authorize_tool(call("read_logs"))

    event = ledger.events[0]
    assert event["event_type"] == "policy.decision"
    assert event["payload"]["run_id"] == call("read_logs").run_id
    assert event["payload"]["subject"] == "user-alice"
    assert event["payload"]["args_hash"] == arguments_hash(call("read_logs").arguments)
    assert event["payload"]["decision"] == "allow"


def test_tool_call_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)

    impl.execute_tool(call("read_logs"))

    tool_events = [event for event in ledger.events if event["event_type"] == "tool.call"]
    assert len(tool_events) == 1
    payload = tool_events[0]["payload"]
    assert payload["status"] == "executed"
    assert payload["tier"] == "T0"
    assert payload["args_hash"] == arguments_hash(call("read_logs").arguments)
    assert payload["idempotency_key"] == idempotency_key(call("read_logs"))


def test_a_replayed_call_is_audited(monkeypatch: pytest.MonkeyPatch) -> None:
    item = call("read_logs")
    db = FakeDB({idempotency_key(item): {"status": "executed", "result": {"stdout": "hi"}}})
    ledger = FakeAudit()
    impl = build(monkeypatch, db, recorder([]), ledger)

    impl.execute_tool(item)

    payload = ledger.events[0]["payload"]
    assert payload["status"] == "replayed"
    assert payload["idempotency_key"] == idempotency_key(item)


def test_tool_call_emits_a_span_with_the_audit_id(monkeypatch: pytest.MonkeyPatch) -> None:
    impl = build(monkeypatch, FakeDB(), recorder([]), FakeAudit())
    spans: list[tuple[str, dict[str, Any]]] = []

    def record(name: str, **kwargs: Any) -> None:
        spans.append((name, kwargs))

    monkeypatch.setattr(activities, "record_span", record)
    impl.execute_tool(call("read_logs"))

    assert spans[0][0] == "tool.call"
    assert spans[0][1]["audit_id"] == "audit-1"
    assert spans[0][1]["run_id"] == call("read_logs").run_id


class RunFakeDB:
    def __init__(self, ended: bool) -> None:
        self.ended = ended
        self.status: str | None = None

    @contextmanager
    def connect(self, _dsn: str, _tenant: str) -> Iterator[RunFakeConn]:
        yield RunFakeConn(self)


class RunFakeConn:
    def __init__(self, db: RunFakeDB) -> None:
        self._db = db

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> _Cursor:
        statement = " ".join(sql.split())
        if statement.startswith("UPDATE runs SET status = %s"):
            self._db.status = str(params[0])
            return _Cursor(None)
        if statement.startswith("SELECT 1 FROM audit_events"):
            return _Cursor((1,) if self._db.ended else None)
        raise AssertionError(f"unexpected SQL: {statement}")


def test_finish_run_writes_the_end_event(monkeypatch: pytest.MonkeyPatch) -> None:
    db = RunFakeDB(ended=False)
    ledger = FakeAudit()
    monkeypatch.setattr(activities, "tenant_connection", db.connect)

    RunActivities(dsn="unused", audit=cast(Any, ledger)).finish_run(
        RunEnd(run_id="run-1", tenant_id="lab-a", outcome="completed")
    )

    assert db.status == "completed"
    assert [event["event_type"] for event in ledger.events] == ["run.end"]
    assert ledger.events[0]["payload"]["outcome"] == "completed"


def test_finish_run_does_not_fork_an_existing_end(monkeypatch: pytest.MonkeyPatch) -> None:
    db = RunFakeDB(ended=True)
    ledger = FakeAudit()
    monkeypatch.setattr(activities, "tenant_connection", db.connect)

    RunActivities(dsn="unused", audit=cast(Any, ledger)).finish_run(
        RunEnd(run_id="run-1", tenant_id="lab-a", outcome="denied")
    )

    assert db.status == "denied"
    assert ledger.events == []
