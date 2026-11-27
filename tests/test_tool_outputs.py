"""Offloaded output: what is kept, under which key, and who may read it back."""

from __future__ import annotations

import gzip
import hashlib
from typing import Any

import pytest

from citadel import tool_outputs
from citadel.tool_outputs import MAX_STORED_BYTES, digest_of, fetch, store


class Cursor:
    def __init__(
        self, row: tuple[Any, ...] | None, rows: list[tuple[Any, ...]] | None = None
    ) -> None:
        self._row = row
        self._rows = rows or ([] if row is None else [row])

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row

    def fetchall(self) -> list[tuple[Any, ...]]:
        return self._rows


class Conn:
    """Just enough of a connection: one insert, one select, RLS simulated by key."""

    def __init__(self, tenant: str = "lab-a") -> None:
        self.tenant = tenant
        self.rows: dict[tuple[str, str], bytes] = {}
        self.statements: list[str] = []
        # Digest -> age in days. Stands in for `created_at < now() - ttl days`,
        # which is the one thing a fake connection cannot compute.
        self.age_days: dict[str, int] = {}

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Cursor:
        statement = " ".join(sql.split())
        self.statements.append(statement)
        if statement.startswith("INSERT INTO tool_outputs"):
            tenant_id, digest, _run, _tool, _stream, body, _bytes = params
            self.rows.setdefault((tenant_id, digest), body)
            return Cursor(None)
        if statement.startswith("SELECT body FROM tool_outputs"):
            body = self.rows.get((self.tenant, str(params[0])))
            return Cursor((body,) if body is not None else None)
        if statement.startswith("DELETE FROM tool_outputs WHERE created_at <"):
            ttl = int(params[0])
            gone = [key for key in self.rows if self.age_days.get(key[1], 0) > ttl]
            for key in gone:
                del self.rows[key]
            return Cursor(None, [(key[1],) for key in gone])
        raise AssertionError(f"unexpected SQL: {statement}")


def put(
    conn: Conn, text: str, *, tenant: str = "lab-a", stream: str = "stdout", age_days: int = 0
) -> Any:
    stored = store(
        conn,
        tenant_id=tenant,
        run_id="11111111-1111-1111-1111-111111111111",
        tool="read_logs",
        stream=stream,
        text=text,
    )
    conn.age_days[stored.digest] = age_days
    return stored


def test_the_digest_is_the_sha256_of_the_text() -> None:
    assert digest_of("hello") == hashlib.sha256(b"hello").hexdigest()


def test_a_stored_body_comes_back_byte_identical() -> None:
    conn = Conn()
    text = "line one\nline two\n" + ("x" * 4096)

    kept = put(conn, text)
    read_back = fetch(conn, digest=kept.digest)

    assert kept.stored is True
    assert kept.bytes == len(text.encode("utf-8"))
    assert read_back == text


def test_the_body_is_compressed_on_the_way_in() -> None:
    """Not a control, but a 64 KB log should not cost 64 KB of table."""
    conn = Conn()
    text = "a" * 60_000

    kept = put(conn, text)
    raw = conn.rows[("lab-a", kept.digest)]

    assert len(raw) < len(text.encode("utf-8")) // 10
    assert gzip.decompress(raw).decode() == text


def test_storing_the_same_digest_twice_keeps_one_row() -> None:
    conn = Conn()
    text = "the same bytes"

    first = put(conn, text)
    second = put(conn, text)

    assert first.digest == second.digest
    assert len(conn.rows) == 1


def test_a_body_over_the_limit_is_refused_but_still_has_a_digest() -> None:
    """Refusing is honest: the record keeps the digest, so the absence is visible."""
    conn = Conn()
    text = "z" * (MAX_STORED_BYTES + 1)

    kept = put(conn, text)

    assert kept.stored is False
    assert kept.digest == digest_of(text)
    assert conn.rows == {}, "an oversized body must not be written"
    assert not any("INSERT" in sql for sql in conn.statements)


def test_a_missing_digest_reads_as_none_not_an_error() -> None:
    assert fetch(Conn(), digest=digest_of("never stored")) is None


def test_one_tenant_cannot_read_another_tenants_row() -> None:
    """`(tenant_id, digest)` is the key: identical bytes are still two rows."""
    alice = Conn(tenant="lab-a")
    text = "shared bytes"
    kept = put(alice, text, tenant="lab-a")

    bob = Conn(tenant="lab-b")
    bob.rows = alice.rows  # the same table, reached with a different tenant

    assert fetch(bob, digest=kept.digest) is None


def test_a_stream_name_is_recorded_so_stdout_and_stderr_stay_apart() -> None:
    conn = Conn()
    out = put(conn, "out", stream="stdout")
    err = put(conn, "err", stream="stderr")

    assert out.digest != err.digest
    assert fetch(conn, digest=out.digest) == "out"
    assert fetch(conn, digest=err.digest) == "err"


def test_the_limit_is_configurable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tool_outputs, "MAX_STORED_BYTES", 10)
    conn = Conn()

    assert put(conn, "x" * 11).stored is False
    assert put(conn, "x" * 10).stored is True


def test_a_body_past_the_ttl_is_deleted_and_a_fresh_one_survives() -> None:
    """A retention job that deletes nothing and exits 0 is the failure to avoid."""
    conn = Conn()
    old = put(conn, "an old stream", age_days=120)
    fresh = put(conn, "a recent stream", age_days=1)

    deleted = tool_outputs.purge(conn, days=90)

    assert deleted == 1
    assert fetch(conn, digest=old.digest) is None
    assert fetch(conn, digest=fresh.digest) == "a recent stream"


def test_the_default_retention_is_ninety_days() -> None:
    assert tool_outputs.TTL_DAYS == 90
    conn = Conn()
    put(conn, "eighty-nine", age_days=89)
    put(conn, "ninety-one", age_days=91)

    assert tool_outputs.purge(conn) == 1
    assert conn.statements[-1].startswith("DELETE FROM tool_outputs")


def test_the_retention_period_is_a_parameter() -> None:
    conn = Conn()
    put(conn, "ten days", age_days=10)

    assert tool_outputs.purge(conn, days=7) == 1


def test_a_zero_day_retention_is_refused_before_it_runs() -> None:
    """Zero would delete every body, including the one being investigated."""
    conn = Conn()
    put(conn, "anything", age_days=1)

    with pytest.raises(ValueError, match="zero days"):
        tool_outputs.purge(conn, days=0)

    assert not any(statement.startswith("DELETE") for statement in conn.statements)


def test_an_expired_body_reads_as_missing_not_as_an_error() -> None:
    """The read-back route already answers 404: retention changes nothing for a caller."""
    conn = Conn()
    old = put(conn, "gone soon", age_days=200)
    tool_outputs.purge(conn, days=90)

    assert fetch(conn, digest=old.digest) is None


def test_only_the_body_table_is_touched() -> None:
    """The ledger is the record: retention must never rewrite it."""
    conn = Conn()
    put(conn, "old", age_days=400)
    tool_outputs.purge(conn, days=90)

    assert all("audit_events" not in statement for statement in conn.statements)
    assert all("tool_outputs" in statement for statement in conn.statements)
