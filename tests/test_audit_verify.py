"""`AuditLedger.verify()` had no test and no caller: tamper evidence nobody checks.

The chain is built with the production hash function, then altered one way at a
time and driven through the real ``tenant_connection``, so the test exercises the
ledger's own code path rather than a substitute for it.
"""

from __future__ import annotations

from typing import Any

import psycopg
import pytest

from citadel import audit

TENANT = "lab-a"


def _chain(events: list[tuple[str, dict[str, Any]]]) -> list[tuple[Any, ...]]:
    prev = audit.GENESIS
    rows: list[tuple[Any, ...]] = []
    for seq, (event_type, payload) in enumerate(events, start=1):
        digest = audit.event_hash(
            prev_hash=prev,
            tenant_id=TENANT,
            seq=seq,
            event_type=event_type,
            actor_type="user",
            actor_id="u1",
            body=audit.canonical(payload),
        )
        rows.append((seq, event_type, "user", "u1", payload, prev, digest))
        prev = digest
    return rows


EVENTS = [
    ("run.start", {"run_id": "r1"}),
    ("approval.decision", {"run_id": "r1", "decision": "approved"}),
]


class _Result:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self._rows = rows

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class _Transaction:
    def __enter__(self) -> None:
        return None

    def __exit__(self, *_: Any) -> None:
        return None


class _Connection:
    def __init__(self, rows: list[tuple[Any, ...]]) -> None:
        self.rows = rows

    def __enter__(self) -> _Connection:
        return self

    def __exit__(self, *_: Any) -> None:
        return None

    def transaction(self) -> _Transaction:
        return _Transaction()

    def execute(self, _statement: str, _params: Any = None) -> _Result:
        return _Result(self.rows)


@pytest.fixture
def verify(monkeypatch: pytest.MonkeyPatch) -> Any:
    """Serve the given rows to the ledger through the real tenant_connection."""
    connection = _Connection([])

    def connect(_dsn: str) -> _Connection:
        return connection

    monkeypatch.setattr(psycopg, "connect", connect)

    def run(rows: list[tuple[Any, ...]]) -> tuple[bool, int]:
        connection.rows = rows
        return audit.AuditLedger("postgres://fake").verify(TENANT)

    return run


def test_an_intact_chain_verifies(verify: Any) -> None:
    assert verify(_chain(EVENTS)) == (True, 2)


def test_an_empty_ledger_is_intact_with_nothing_checked(verify: Any) -> None:
    assert verify([]) == (True, 0)


def test_an_edited_payload_is_detected(verify: Any) -> None:
    rows = _chain(EVENTS)
    seq, event_type, actor_type, actor_id, _payload, prev, digest = rows[1]
    rows[1] = (seq, event_type, actor_type, actor_id, {"decision": "denied"}, prev, digest)
    assert verify(rows) == (False, 2)


def test_a_rewritten_hash_is_detected(verify: Any) -> None:
    """Editing the row and recomputing its own hash still breaks the link before it."""
    rows = _chain(EVENTS)
    _seq, event_type, actor_type, actor_id, _payload, prev, _digest = rows[0]
    forged = audit.event_hash(
        prev_hash=prev,
        tenant_id=TENANT,
        seq=1,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        body=audit.canonical({"run_id": "forged"}),
    )
    rows[0] = (1, event_type, actor_type, actor_id, {"run_id": "forged"}, prev, forged)
    assert verify(rows) == (False, 2)


def test_a_missing_row_is_detected_by_the_sequence_number(verify: Any) -> None:
    assert verify(_chain(EVENTS)[1:]) == (False, 1)


def test_a_reordered_pair_is_detected(verify: Any) -> None:
    rows = _chain(EVENTS)
    assert verify([rows[1], rows[0]]) == (False, 2)


def test_every_event_in_the_chain_is_counted(verify: Any) -> None:
    """The count is evidence too: a chain of one row verifies but proves little."""
    assert verify(_chain(EVENTS + [("run.end", {"run_id": "r1", "outcome": "ok"})])) == (True, 3)
