"""Fakes shared by the red-team executors that need more than a pure function.

Two shapes only, both taken from the project's own test doubles:

* ``FakeDB`` — the four statements the tool activity issues against
  ``tool_calls``, plus the ``approval_tokens`` insert the operator uses.
* ``stub_executor`` — counts what would have run, so a test can assert the
  number of real effects rather than the number of attempts.

Nothing here reaches Docker, GitHub, Postgres or the network.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any
from urllib.request import Request

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from citadel.workflows.types import ToolCall, ToolResult


class Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class FakeDB:
    def __init__(self) -> None:
        self.rows: dict[str, dict[str, Any]] = {}
        self.approvals: list[tuple[Any, ...]] = []
        self.used_jti: set[str] = set()
        # Who owns the run the API is asked to approve.
        self.run_owner: tuple[str, ...] = ("user-alice",)

    @contextmanager
    def connect(self, _dsn: str, _tenant: str) -> Iterator[FakeConn]:
        yield FakeConn(self)


class FakeConn:
    def __init__(self, db: FakeDB) -> None:
        self._db = db

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Cursor:
        statement = " ".join(sql.split())

        if statement.startswith("INSERT INTO tool_calls"):
            key = str(params[0])
            if key in self._db.rows:
                return Cursor(None)
            self._db.rows[key] = {"status": "started", "result": None}
            return Cursor(("id",))

        if statement.startswith("SELECT status, result"):
            row = self._db.rows.get(str(params[0]))
            return Cursor((row["status"], row["result"]) if row else None)

        if statement == "UPDATE tool_calls SET status = 'sent' WHERE idempotency_key = %s":
            self._db.rows[str(params[0])]["status"] = "sent"
            return Cursor(None)

        if statement.startswith("UPDATE tool_calls SET status = %s"):
            status, result, key = params
            self._db.rows[str(key)] = {"status": status, "result": json.loads(result)}
            return Cursor(None)

        if statement.startswith("INSERT INTO approval_tokens"):
            jti = str(params[0])
            if jti in self._db.used_jti:
                return Cursor(None)
            self._db.used_jti.add(jti)
            return Cursor((jti,))

        if statement.startswith("UPDATE approval_requests"):
            self._db.approvals.append(params)
            return Cursor(None)

        if statement.startswith("SELECT user_id FROM runs"):
            return Cursor(self._db.run_owner)

        raise AssertionError(f"unexpected SQL: {statement}")


@dataclass(frozen=True)
class FakeAuditRef:
    """The tracer reads audit_id off the append result, so the fake returns one."""

    audit_id: str
    tenant_id: str
    seq: int
    hash: str = "0" * 64


class FakeAudit:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> FakeAuditRef:
        self.events.append(kwargs)
        return FakeAuditRef(
            audit_id=f"audit-{len(self.events)}",
            tenant_id=str(kwargs.get("tenant_id", "lab-a")),
            seq=len(self.events),
        )


class StubExecutor:
    """Stands in for the operator or sandbox transport; counts real effects."""

    def __init__(self) -> None:
        self.calls: list[Any] = []

    def run(self, argv: list[str]) -> Any:
        self.calls.append(argv)
        return SimpleResult(returncode=0, stdout="ok", stderr="")


class SimpleResult:
    def __init__(self, returncode: int, stdout: str, stderr: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def public_key_env(private: Ed25519PrivateKey) -> str:
    der = private.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


class DetectorStub:
    """Minimal stand-in for the DLP opener so no detector is required."""

    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def __call__(self, _request: Request, timeout: Any = None) -> DetectorStub:
        return self

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> DetectorStub:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


class StubTool:
    """Counts real effects, so a test can assert one call and not three."""

    def __init__(self) -> None:
        self.count = 0

    def invoke(self, call: ToolCall) -> ToolResult:
        self.count += 1
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="stub.executed",
            detail="stub ran once",
            output={"service": call.arguments.get("service")},
        )
