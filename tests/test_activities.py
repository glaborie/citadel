"""Tool activity retry semantics: what a repeated attempt may do.

The risky case is a write that was already handed to the operator before the
worker died. Temporal retries the activity, so the activity itself has to
decide whether re-running is safe. These tests drive that decision with a fake
connection; no database is needed.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import urllib.error
from collections.abc import Iterator
from contextlib import contextmanager
from email.message import Message
from types import SimpleNamespace
from typing import Any, cast

import pytest

from citadel import approval_requests, dlp, net
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
        self.approvals: list[tuple[Any, ...]] = []
        # (tenant_id, digest) -> gzipped body, as tool_outputs stores it.
        self.outputs: dict[tuple[str, str], bytes] = {}

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
        if statement.startswith("INSERT INTO approval_requests"):
            self._db.approvals.append(params)
            return _Cursor(None)
        if statement.startswith("INSERT INTO tool_outputs"):
            tenant_id, digest, _run_id, _tool, _stream, body, _size = params
            self._db.outputs.setdefault((tenant_id, digest), body)
            return _Cursor(None)
        if statement.startswith("SELECT body FROM tool_outputs"):
            body = self._db.outputs.get(("lab-a", str(params[0])))
            return _Cursor((body,) if body is not None else None)
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
    monkeypatch.setattr(approval_requests, "tenant_connection", db.connect)
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


def test_the_event_is_written_before_the_row_settles(monkeypatch: pytest.MonkeyPatch) -> None:
    """Crash between the two writes: `sent` with an event, never `executed` without.

    The v0.1 exit review counted nine rows in the other order's window. The
    durable state a retry now finds says the call may have run, and the ledger
    already knows it did.
    """
    db = FakeDB()
    ledger = FakeAudit()
    impl = build(monkeypatch, db, recorder([]), ledger)
    _detector(monkeypatch)

    class Died(Exception):
        pass

    def execute(sql: str, params: tuple[Any, ...] = ()) -> Any:
        if " ".join(sql.split()).startswith("UPDATE tool_calls SET status = %s"):
            raise Died
        return FakeConn(db).execute(sql, params)

    @contextmanager
    def connect(_dsn: str, _tenant: str) -> Iterator[Any]:
        conn = FakeConn(db)
        conn.execute = execute  # type: ignore[method-assign]
        yield conn

    monkeypatch.setattr(activities, "tenant_connection", connect)

    with pytest.raises(Died):
        impl.execute_tool(call("read_logs"))

    key = idempotency_key(call("read_logs"))
    assert db.rows[key]["status"] == "sent", "an unrecorded execution must not claim to be done"
    assert [event["event_type"] for event in ledger.events] == ["tool.call"]
    assert ledger.events[0]["payload"]["status"] == "executed"
    assert ledger.events[0]["payload"]["idempotency_key"] == key


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

    monkeypatch.setattr(net, "urlopen", urlopen)
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

    monkeypatch.setattr(net, "urlopen", urlopen)
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

    monkeypatch.setattr(net, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    assert result.rule_id == "dlp.unavailable"
    assert len(ledger.events) == 1


def test_the_sandbox_call_presents_the_run_token(monkeypatch: pytest.MonkeyPatch) -> None:
    impl = build(monkeypatch, FakeDB(), recorder([]))
    seen: dict[str, Any] = {}

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        seen["authorization"] = request.get_header("Authorization")
        return Reply({"allowlist_id": "docker.ps", "dlp": []})

    monkeypatch.setattr(net, "urlopen", urlopen)
    item = call("read_logs")
    item.run_token = "run-token"
    result = impl._invoke_sandbox(item)

    assert result.status == "executed"
    assert seen["authorization"] == "Bearer run-token"


def test_an_unauthenticated_sandbox_refusal_is_a_refusal(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """No token in the call is refused by the runner; report it as a refusal."""
    impl = build(monkeypatch, FakeDB(), recorder([]))

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", Message(), io.BytesIO(b"")
        )

    monkeypatch.setattr(net, "urlopen", urlopen)
    result = impl._invoke_sandbox(call("read_logs"))

    assert (result.status, result.rule_id) == ("failed", "tool.refused")


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


def _detector(monkeypatch: pytest.MonkeyPatch, body: bytes = b"[]") -> None:
    class Reply:
        def read(self) -> bytes:
            return body

        def __enter__(self) -> Reply:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    monkeypatch.setattr(dlp, "urlopen", lambda _r, timeout=None: Reply())


def test_a_t1_request_is_recorded_for_the_console(monkeypatch: pytest.MonkeyPatch) -> None:
    db = FakeDB()
    impl = build(monkeypatch, db, recorder([]), FakeAudit())
    decision = Decision("requires_approval", "policy.tier_requires_approval", "approve it", "T1")
    monkeypatch.setattr(activities, "authorize", lambda *args, **kwargs: decision)
    _detector(monkeypatch)

    item = call("restart_service")
    item.workflow_id = f"run-{item.run_id}-1-restart_service"
    outcome = impl.authorize_tool(item)

    assert outcome.outcome == "requires_approval"
    assert len(db.approvals) == 1
    tenant, run_id, tool, agent, arguments, tier, rule_id, requested_by, workflow_id = db.approvals[
        0
    ]
    assert (tenant, run_id, tool, agent, tier, rule_id, requested_by) == (
        "lab-a",
        call("restart_service").run_id,
        "restart_service",
        "docker",
        "T1",
        "policy.tier_requires_approval",
        "user-alice",
    )
    assert workflow_id == item.workflow_id, "the row must carry the child's own id"
    assert json.loads(arguments) == {"service": "checkout-api"}


def test_a_secret_in_t1_arguments_denies_before_recording(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    db = FakeDB()
    ledger = FakeAudit()
    impl = build(monkeypatch, db, recorder([]), ledger)
    decision = Decision("requires_approval", "policy.tier_requires_approval", "approve it", "T1")
    monkeypatch.setattr(activities, "authorize", lambda *args, **kwargs: decision)
    _detector(monkeypatch)
    item = call("restart_service")
    item.arguments = {"service": "ghp_" + "a" * 36}

    outcome = impl.authorize_tool(item)

    assert outcome.outcome == "deny"
    assert outcome.rule_id == "dlp.blocked"
    assert db.approvals == []
    assert [event["event_type"] for event in ledger.events] == ["policy.decision", "dlp.event"]


def test_a_dead_detector_denies_before_recording(monkeypatch: pytest.MonkeyPatch) -> None:
    db = FakeDB()
    impl = build(monkeypatch, db, recorder([]), FakeAudit())
    decision = Decision("requires_approval", "policy.tier_requires_approval", "approve it", "T1")
    monkeypatch.setattr(activities, "authorize", lambda *args, **kwargs: decision)

    def down(_request: Any, timeout: Any = None) -> Any:
        raise OSError("detector down")

    monkeypatch.setattr(dlp, "urlopen", down)

    outcome = impl.authorize_tool(call("restart_service"))

    assert outcome.outcome == "deny"
    assert outcome.rule_id == "dlp.unavailable"
    assert db.approvals == []


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


def test_the_record_carries_the_argument_values_a_grader_asserts_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A digest proves two argument sets are equal, not which values they held."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    _detector(monkeypatch)
    item = call("restart_service")

    impl.execute_tool(item)

    payload = ledger.events[0]["payload"]
    assert payload["arguments"] == {"service": "checkout-api"}
    assert payload["args_hash"] == arguments_hash(item.arguments)


def test_pii_in_the_arguments_is_redacted_before_the_record_keeps_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ledger never expires, so it takes the same gate as an output body."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    item = call("read_logs")
    item.arguments = {"owner": "Alice Smith"}
    text = json.dumps(item.arguments, ensure_ascii=False)
    start = text.index("Alice")
    span = {
        "entity_type": "PERSON",
        "start": start,
        "end": start + len("Alice Smith"),
        "score": 0.9,
    }
    _detector(monkeypatch, json.dumps([span]).encode())

    impl.execute_tool(item)

    payload = ledger.events[0]["payload"]
    assert payload["arguments"] == {"owner": "<PERSON>"}
    gated = [event for event in ledger.events if event["event_type"] == "dlp.event"]
    # The output now takes the same gate, so this asserts the argument surface rather
    # than the exact set of events - and the values above are the real claim.
    assert ("record", "redact") in [
        (event["payload"]["surface"], event["payload"]["action"]) for event in gated
    ]


def test_a_secret_in_the_arguments_keeps_the_digest_and_no_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An append-only ledger cannot take a token back, so the value never enters."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    _detector(monkeypatch)
    item = call("restart_service")
    item.arguments = {"service": "ghp_" + "a" * 36}

    impl.execute_tool(item)

    payload = ledger.events[0]["payload"]
    assert "arguments" not in payload
    assert payload["args_hash"] == arguments_hash(item.arguments)
    gated = [event for event in ledger.events if event["event_type"] == "dlp.event"]
    assert ("record", "block") in [
        (event["payload"]["surface"], event["payload"]["action"]) for event in gated
    ]


def test_a_dead_detector_withholds_the_values_and_keeps_the_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The effect already happened; an unchecked argument is what must not persist."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)

    def down(_request: Any, timeout: Any = None) -> Any:
        raise OSError("detector down")

    monkeypatch.setattr(dlp, "urlopen", down)

    impl.execute_tool(call("read_logs"))

    payload = ledger.events[0]["payload"]
    assert "arguments" not in payload
    assert payload["status"] == "executed"
    assert ledger.events[1]["payload"]["action"] == "block"


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
        RunEnd(
            run_id="run-1",
            tenant_id="lab-a",
            outcome="completed",
            answer="two containers are running",
        )
    )

    assert db.status == "completed"
    assert [event["event_type"] for event in ledger.events] == ["run.end"]
    assert ledger.events[0]["payload"]["outcome"] == "completed"
    assert ledger.events[0]["payload"]["answer"] == "two containers are running"


def test_finish_run_does_not_fork_an_existing_end(monkeypatch: pytest.MonkeyPatch) -> None:
    db = RunFakeDB(ended=True)
    ledger = FakeAudit()
    monkeypatch.setattr(activities, "tenant_connection", db.connect)

    RunActivities(dsn="unused", audit=cast(Any, ledger)).finish_run(
        RunEnd(run_id="run-1", tenant_id="lab-a", outcome="denied")
    )

    assert db.status == "denied"
    assert ledger.events == []


def test_a_large_tool_result_is_capped_before_it_enters_the_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 64 KB body is 64 KB of event history per call; the cap is the control."""
    body = "HEAD\n" + ("a" * 60_000) + "\nEND\n"
    impl = build(monkeypatch, FakeDB(), recorder([]), FakeAudit())

    def urlopen(_request: Any, timeout: Any = None) -> Reply:
        return Reply(
            {"allowlist_id": "docker.logs", "stdout": body, "stderr": "", "truncated": False}
        )

    monkeypatch.setattr(net, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    assert len(result.output["stdout"].encode("utf-8")) <= activities.EVENT_OUTPUT_LIMIT
    assert result.output["stdout"].startswith("HEAD")
    assert result.output["stdout"].rstrip().endswith("END")
    assert result.output_sha256 == hashlib.sha256(body.encode()).hexdigest()
    assert result.output_bytes == len(body.encode())
    assert result.output_truncated is True


def test_the_capped_bytes_are_kept_where_the_digest_points(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The record proves the bytes existed; the store is how a reviewer reads them.

    Without this, a 100 KB diff could only be reviewed by running the tool again,
    which for a T1 write means repeating the side effect.
    """
    body = "HEAD\n" + ("b" * 60_000) + "\nEND\n"
    db = FakeDB()
    impl = build(monkeypatch, db, recorder([]), FakeAudit())

    def urlopen(_request: Any, timeout: Any = None) -> Reply:
        return Reply(
            {"allowlist_id": "docker.logs", "stdout": body, "stderr": "", "truncated": False}
        )

    monkeypatch.setattr(net, "urlopen", urlopen)
    result = impl._post("http://runner/execute", b"{}", call("read_logs"))

    digest = hashlib.sha256(body.encode()).hexdigest()
    assert result.output_ref == digest
    assert result.output_stored is True
    assert ("lab-a", digest) in db.outputs, "the body was not kept"
    stored = gzip.decompress(db.outputs[("lab-a", digest)]).decode()
    assert stored == body, "the store must hold the text the runner returned, not the cap"


OUTPUT_FIELDS = ("output_sha256", "output_bytes", "output_truncated", "output_ref", "output_stored")

BIG = "HEAD\n" + ("c" * 60_000) + "\nEND\n"


def _serving(body: str) -> Any:
    def urlopen(_request: Any, timeout: Any = None) -> Reply:
        return Reply(
            {"allowlist_id": "docker.logs", "stdout": body, "stderr": "", "truncated": False}
        )

    return urlopen


def _through_the_real_invoker(
    monkeypatch: pytest.MonkeyPatch, db: FakeDB, ledger: Any, body: str
) -> ToolActivities:
    """`execute_tool` with the sandbox path intact, so the cap actually runs."""
    impl = build(monkeypatch, db, recorder([]), ledger)
    _detector(monkeypatch)
    monkeypatch.setattr(impl, "_invoke", impl._invoke_sandbox)
    monkeypatch.setattr(net, "urlopen", _serving(body))
    return impl


def test_a_capped_call_reports_the_cap_in_its_own_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rebuild after invoke copied the fields it knew about and dropped the rest.

    `_post` set `output_sha256`, `output_bytes`, `output_truncated`, `output_ref` and
    `output_stored`; `execute_tool` then built a fresh ToolResult from six of them, so
    the audit event for a capped call said no cap had been applied and the caller
    could not read the output back.
    """
    ledger = FakeAudit()
    impl = _through_the_real_invoker(monkeypatch, FakeDB(), ledger, BIG)

    result = impl.execute_tool(call("read_logs"))

    digest = hashlib.sha256(BIG.encode()).hexdigest()
    assert result.output_sha256 == digest
    assert result.output_bytes == len(BIG.encode())
    assert result.output_truncated is True
    assert result.output_ref == digest
    assert result.output_stored is True

    payload = ledger.events[-1]["payload"]
    assert payload["output_sha256"] == digest
    assert payload["output_ref"] == digest
    assert payload["output_truncated"] is True


def test_a_replay_reports_the_same_fields_as_the_first_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The acceptance criterion: field by field, replay equals first execution."""
    ledger = FakeAudit()
    db = FakeDB()
    impl = _through_the_real_invoker(monkeypatch, db, ledger, BIG)
    item = call("read_logs")

    first = impl.execute_tool(item)
    second = impl.execute_tool(item)

    assert second.status == "replayed"
    assert second.replayed is True
    for name in OUTPUT_FIELDS:
        assert getattr(second, name) == getattr(first, name), name
    assert second.output == first.output

    # The audit event a consumer reads says the same thing as the result.
    payload = ledger.events[-1]["payload"]
    assert payload["status"] == "replayed"
    assert payload["output_ref"] == first.output_ref
    assert payload["output_sha256"] == first.output_sha256
    assert payload["output_bytes"] == first.output_bytes
    assert payload["output_truncated"] is True


def test_a_replay_of_a_call_that_stored_nothing_still_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The equality is the contract, not the non-emptiness."""
    impl = _through_the_real_invoker(monkeypatch, FakeDB(), FakeAudit(), "short\n")
    item = call("read_logs")

    first = impl.execute_tool(item)
    second = impl.execute_tool(item)

    # A short output still reports its digest: the cap is not the only reason to
    # know what was returned.
    assert first.output_sha256 == hashlib.sha256(b"short\n").hexdigest()
    assert first.output_truncated is False
    assert first.output_stored is False
    for name in OUTPUT_FIELDS:
        assert getattr(second, name) == getattr(first, name), name


def test_a_replay_of_a_legacy_row_invents_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    """A row written before the fields existed must not gain a fabricated digest."""
    item = call("read_logs")
    db = FakeDB({idempotency_key(item): {"status": "executed", "result": {"stdout": "hi"}}})
    impl = build(monkeypatch, db, recorder([]))
    result = impl.execute_tool(item)

    assert result.status == "replayed"
    assert result.output == {"stdout": "hi"}
    assert result.output_sha256 == ""
    assert result.output_bytes == 0
    assert result.output_truncated is False
    assert result.output_ref == ""
    assert result.output_stored is False


def test_the_audit_record_states_that_a_cap_was_applied(monkeypatch: pytest.MonkeyPatch) -> None:
    """A silence is not evidence: the event carries the digest of what it hid."""
    ledger = FakeAudit()
    impl = build(monkeypatch, FakeDB(), recorder([]), ledger)
    _detector(monkeypatch)
    result = ToolResult(
        status="executed",
        tool="read_logs",
        rule_id="tool.executed",
        detail="executed",
        output_sha256="ab" * 32,
        output_bytes=60_000,
        output_truncated=True,
    )

    impl._audit_tool(call("read_logs"), result, args_hash="h", key="k", tier="T0")

    payload = ledger.events[-1]["payload"]
    assert payload["output_truncated"] is True
    assert payload["output_bytes"] == 60_000
    assert payload["output_sha256"] == "ab" * 32


def test_what_the_sandbox_threw_away_reaches_the_record() -> None:
    """A 10 MB log cut to 64 KB in the sandbox must not report 64 KB as the size."""
    received = "H" + ("a" * 63_999)
    bounded = activities.bounded_payload(
        {
            "stdout": received,
            "stderr": "",
            "original_bytes": 10_000_000,
            "omitted_bytes": 10_000_000 - len(received.encode()),
            "truncated": True,
        }
    )

    assert bounded.payload["discarded_bytes"] == 10_000_000 - len(received.encode())
    assert bounded.payload["original_bytes"] == 10_000_000
    assert bounded.payload["truncated"] is True


def test_a_stream_the_sandbox_cut_entirely_is_still_a_cap() -> None:
    bounded = activities.bounded_payload(
        {"stdout": "short", "stderr": "", "omitted_bytes": 5_000, "truncated": True}
    )

    assert bounded.payload["discarded_bytes"] == 5_000
    assert bounded.payload["truncated"] is True
    assert bounded.payload["original_bytes"] == len("short") + 5_000


def test_a_payload_without_the_runner_numbers_is_unchanged() -> None:
    """Every stub in this suite sends no counts; the fallback must stay silent."""
    bounded = activities.bounded_payload({"stdout": "hi", "stderr": ""})

    assert bounded.payload["discarded_bytes"] == 0
    assert bounded.payload["original_bytes"] == len("hi")
    assert bounded.payload["truncated"] is False
