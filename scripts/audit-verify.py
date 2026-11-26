"""Verify a tenant's audit chain and report tool calls that left no event.

``AuditLedger.verify()`` and ``.unaudited()`` are the two controls the red-team
pack leans on for tamper evidence and completeness. Both existed, neither had a
caller outside the tests, which made them documentation. This is the operator
entry point: before an export, after a restore, or from cron.

    CITADEL_DB_DSN=postgres://… python scripts/audit-verify.py lab-a lab-b

Exit codes: 0 intact and fully audited, 1 a broken chain or an unaudited call,
2 bad usage. A non-zero exit is the point - a verification nobody acts on is the
same as no verification.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from typing import Protocol


class Ledger(Protocol):
    def verify(self, tenant_id: str) -> tuple[bool, int]: ...

    def unaudited(self, tenant_id: str) -> list[str]: ...


def main(argv: list[str], *, open_ledger: Callable[[str], Ledger] | None = None) -> int:
    from citadel.audit import AuditLedger

    tenants = argv[1:]
    if not tenants:
        print("usage: audit-verify.py TENANT [TENANT ...]", file=sys.stderr)
        return 2
    dsn = os.environ.get("CITADEL_DB_DSN")
    if not dsn:
        print("CITADEL_DB_DSN is not set", file=sys.stderr)
        return 2

    factory = open_ledger or AuditLedger
    ledger = factory(dsn)
    problems = 0
    for tenant in tenants:
        ok, events = ledger.verify(tenant)
        gaps = ledger.unaudited(tenant)
        print(
            f"{tenant}: chain {'intact' if ok else 'BROKEN'} over {events} event(s), "
            f"{len(gaps)} unaudited call(s)"
        )
        for key in gaps:
            # The key names the tool call, not what it did: enough to find it.
            print(f"  unaudited: {key}")
        problems += 0 if ok else 1
        problems += 1 if gaps else 0
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
