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
