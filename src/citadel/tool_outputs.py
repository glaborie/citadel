"""Offloaded tool output: the bytes the record proves but cannot show.

An activity result becomes event history, so a tool's output is capped there: 8 KB
of head and tail per stream plus the sha256 of the whole thing. That digest is
evidence that bytes existed, and nothing more - reading the rest back meant running
the tool again, which for a T1 write means repeating the side effect.

This module keeps the text behind that digest. Two properties matter:

* what is stored is the **redacted** text the tool service returned, so the store
  cannot become a way around the output gate;
* the key is `(tenant_id, digest)`, and RLS is what separates tenants, not the
  digest. A shared content-addressed key would let one tenant's row satisfy
  another's lookup for identical bytes, which is a leak with a plausible excuse.

Compression is not a control here - it makes a 64 KB log cost a few KB.
"""

from __future__ import annotations

import gzip
import hashlib
import os
from dataclasses import dataclass
from typing import Any

MAX_STORED_BYTES = int(os.environ.get("CITADEL_OUTPUT_STORE_MAX_BYTES", 1_048_576))

# The run history is the account of what happened; a body here is the working copy
# of it. 90 days is long enough to investigate a quarter's incidents and short
# enough that an unlucky DLP miss does not become a permanent archive of tool
# output. Override per deployment, not per call.
TTL_DAYS = int(os.environ.get("CITADEL_OUTPUT_STORE_TTL_DAYS", 90))

# RETURNING, not a row count: the caller gets the number of bodies actually
# deleted, which is what a retention job should report.
PURGE_SQL = (
    "DELETE FROM tool_outputs"
    " WHERE created_at < now() - (%s * interval '1 day')"
    " RETURNING digest"
)


@dataclass(frozen=True)
class StoredOutput:
    digest: str
    bytes: int
    stored: bool


def digest_of(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def store(
    conn: Any,  # noqa: ANN401 - psycopg connection, untyped at this boundary
    *,
    tenant_id: str,
    run_id: str,
    tool: str,
    stream: str,
    text: str,
) -> StoredOutput:
    """Keep `text` under its own digest. Idempotent: the same digest is one row."""
    digest = digest_of(text)
    size = len(text.encode("utf-8"))
    if size > MAX_STORED_BYTES:
        # Refusing is honest: the record still carries the digest, so a reader knows
        # bytes existed and this store chose not to hold them.
        return StoredOutput(digest=digest, bytes=size, stored=False)

    conn.execute(
        "INSERT INTO tool_outputs (tenant_id, digest, run_id, tool, stream, body, bytes)"
        " VALUES (%s, %s, %s, %s, %s, %s, %s)"
        " ON CONFLICT (tenant_id, digest) DO NOTHING",
        (tenant_id, digest, run_id, tool, stream, gzip.compress(text.encode("utf-8")), size),
    )
    return StoredOutput(digest=digest, bytes=size, stored=True)


def fetch(conn: Any, *, digest: str) -> str | None:  # noqa: ANN401 - as above
    """Read a stored stream back. RLS restricts this to the caller's tenant."""
    row = conn.execute(
        "SELECT body FROM tool_outputs WHERE digest = %s", (digest,)
    ).fetchone()
    if row is None:
        return None
    return str(gzip.decompress(bytes(row[0])).decode("utf-8"))


def purge(conn: Any, *, days: int | None = None) -> int:  # noqa: ANN401 - as above
    """Delete bodies past the retention period; return how many went.

    Only the body expires. `tool.call` keeps the digest, the byte count and the
    stream, so the record still says bytes existed and this store no longer has
    them - the read-back route already answers 404 for a digest it cannot serve, so
    an expired body looks like one refused for size. The caller learns "not
    available", never "never existed".

    Run this as a role that sees every tenant (the table owner, or a role with
    BYPASSRLS). The app role is tenant-scoped, so under RLS it would delete nothing
    and exit 0 - a retention job that reports success while retaining everything is
    the same failure this module exists to avoid, one layer up.
    """
    ttl = TTL_DAYS if days is None else days
    if ttl <= 0:
        raise ValueError("a retention period of zero days would delete every body")
    deleted = conn.execute(PURGE_SQL, (ttl,)).fetchall()
    return len(deleted)
