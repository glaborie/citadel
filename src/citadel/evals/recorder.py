"""Export a recorded run from the audit ledger as a trajectory.

The ledger is the source of truth: a span that was not audited was not
recorded, and export refuses to hand the grader an incomplete trajectory.

    python -m citadel.evals.recorder --tenant lab-a --run <run-id> --out run.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from citadel.db import tenant_connection
from citadel.evals.schema import EVENT_FIELDS, check_events

# The audit row id is the event id the schema wants for these spans.
AUDITED = frozenset(
    {
        "model.call",
        "retrieval.query",
        "policy.decision",
        "dlp.event",
        "approval.decision",
        "tool.call",
        "cache.lookup",
    }
)


def rows_to_events(rows: list[tuple[Any, ...]]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for row in rows:
        row_id, event_type, payload = row[0], str(row[1]), row[2]
        if event_type not in EVENT_FIELDS:
            # Audit-only events are not trajectory spans and must not break it.
            continue
        body = payload if isinstance(payload, dict) else json.loads(str(payload))
        event: dict[str, Any] = {**body, "type": event_type}
        if event_type in AUDITED:
            event.setdefault("audit_id", str(row_id))
        events.append(event)
    return events


def export_run(*, dsn: str, tenant_id: str, run_id: str) -> list[dict[str, Any]]:
    with tenant_connection(dsn, tenant_id) as conn:
        rows = conn.execute(
            "SELECT id, event_type, payload FROM audit_events"
            " WHERE tenant_id = %s AND payload->>'run_id' = %s ORDER BY seq",
            (tenant_id, run_id),
        ).fetchall()
    return rows_to_events(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a recorded run as a trajectory")
    parser.add_argument("--tenant", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--dsn", default=os.environ.get("CITADEL_DB_DSN", ""))
    parser.add_argument("--out", type=Path)
    args = parser.parse_args(argv)

    if not args.dsn:
        print("CITADEL_DB_DSN is not set", file=sys.stderr)
        return 2

    events = export_run(dsn=args.dsn, tenant_id=args.tenant, run_id=args.run)
    problems = check_events(events, tenant=args.tenant)
    if problems:
        print("incomplete trajectory: " + "; ".join(problems), file=sys.stderr)
        return 1

    text = json.dumps(events, indent=2)
    if args.out is not None:
        args.out.write_text(text + "\n")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
