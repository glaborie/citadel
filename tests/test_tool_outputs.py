"""Offloaded output: what is kept, under which key, and who may read it back."""

from __future__ import annotations

import gzip
import hashlib
from typing import Any

import pytest

from citadel import tool_outputs
from citadel.tool_outputs import MAX_STORED_BYTES, digest_of, fetch, store


class Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class Conn:
    """Just enough of a connection: one insert, one select, RLS simulated by key."""

    def __init__(self, tenant: str = "lab-a") -> None:
        self.tenant = tenant
        self.rows: dict[tuple[str, str], bytes] = {}
        self.statements: list[str] = []

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
        raise AssertionError(f"unexpected SQL: {statement}")


def put(conn: Conn, text: str, *, tenant: str = "lab-a", stream: str = "stdout") -> Any:
    return store(
        conn,
        tenant_id=tenant,
        run_id="11111111-1111-1111-1111-111111111111",
        tool="read_logs",
        stream=stream,
        text=text,
    )


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
