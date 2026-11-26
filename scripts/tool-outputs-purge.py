"""Delete stored tool output past its retention period.

`tool_outputs` holds the bytes the event history could not carry. The history is the
record; these bodies are a working copy, and a working copy that is never deleted is
a growing archive of tool output - some of it one DLP miss away from sensitive.

    CITADEL_OUTPUT_PURGE_DSN=postgres://owner@… python scripts/tool-outputs-purge.py
    make outputs-purge                 # 90 days by default
    make outputs-purge DAYS=30

Use the owner (or a BYPASSRLS) DSN: the app role is tenant-scoped, so under RLS this
deletes nothing and still exits 0. Exit codes: 0 done, 2 bad usage or missing DSN.
Nothing is reported as deleted that was not returned by the DELETE.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any, Protocol

from citadel import tool_outputs


class Connection(Protocol):
    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Any: ...


@contextmanager
def _connect(dsn: str) -> Iterator[Connection]:
    import psycopg

    with psycopg.connect(dsn) as conn:
        yield conn


def main(
    argv: list[str],
    *,
    connect: Callable[[str], Any] = _connect,
) -> int:
    days: int | None = None
    if len(argv) > 1:
        try:
            days = int(argv[1])
        except ValueError:
            print(f"usage: tool-outputs-purge.py [DAYS] (got {argv[1]!r})", file=sys.stderr)
            return 2

    dsn = os.environ.get("CITADEL_OUTPUT_PURGE_DSN") or os.environ.get("CITADEL_DB_DSN")
    if not dsn:
        print(
            "CITADEL_OUTPUT_PURGE_DSN (or CITADEL_DB_DSN) is not set",
            file=sys.stderr,
        )
        return 2

    try:
        with connect(dsn) as conn:
            deleted = tool_outputs.purge(conn, days=days)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    print(
        f"deleted {deleted} stored tool output body/bodies older than "
        f"{days if days is not None else tool_outputs.TTL_DAYS} days"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
