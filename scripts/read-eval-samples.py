"""Read sampled runs back out of the MLflow eval dataset.

The sampler records a dataset id on each `eval.sample` audit event because MLflow 3.18
answers `{}` to every `/api/3.0/mlflow/datasets/search` filter - a name cannot be resolved
back to an id. This reads the same ledger row, then the rows it points at.

    make eval-samples              # everything, five rows
    make eval-samples ARGS="--limit 20 --replay"

Runs inside the compose network, where both the database and MLflow are reachable.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.request
from typing import Any

from citadel.db import tenant_connection
from citadel.env import optional_secret
from citadel.evals import online

LEDGER_SQL = (
    "SELECT payload FROM audit_events WHERE tenant_id = %s"
    " AND event_type = 'eval.sample' ORDER BY seq DESC"
)


def dataset_ids(dsn: str, tenant_id: str) -> list[str]:
    """Every dataset id this tenant's samples named, newest first, without repeats."""
    with tenant_connection(dsn, tenant_id) as conn:
        rows = conn.execute(LEDGER_SQL, (tenant_id,)).fetchall()
    seen: list[str] = []
    for (payload,) in rows:
        body = payload if isinstance(payload, dict) else json.loads(str(payload))
        found = body.get("dataset_id")
        if isinstance(found, str) and found and found not in seen:
            seen.append(found)
    return seen


def records(tracking_uri: str, dataset_id: str) -> list[dict[str, Any]]:
    url = f"{tracking_uri.rstrip('/')}/api/3.0/mlflow/datasets/{dataset_id}/records"
    with urllib.request.urlopen(url, timeout=15) as response:
        payload = dict(json.loads(response.read()))
    body = payload.get("records", [])
    return json.loads(body) if isinstance(body, str) else body


def _summary(row: dict[str, Any], *, replay: bool) -> str:
    inputs = row.get("inputs", {})
    events = row.get("outputs", {}).get("trajectory", [])
    end = next((event for event in events if event.get("type") == "run.end"), {})
    line = (
        f"{inputs.get('run_id', '?')[:8]}  {end.get('outcome', '?'):<10}"
        f" {str(inputs.get('dataset_version', '?')):>3}  {len(events):>3} events"
        f"  {inputs.get('model_alias', '?')}  {inputs.get('prompt_pack_version', '?')}"
    )
    if not replay:
        return line
    failed = [item.grader for item in online.replay(row) if not item.passed]
    return line + "  graders: " + ("all pass" if not failed else "FAIL " + ", ".join(failed))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read sampled runs from the eval dataset")
    parser.add_argument("--tenant", default=os.environ.get("CITADEL_TENANT", "lab-a"))
    parser.add_argument("--dsn", default="")
    parser.add_argument(
        "--tracking-uri", default=os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000")
    )
    parser.add_argument("--dataset", help="a dataset id, instead of the one the ledger names")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--replay", action="store_true", help="grade each row as it prints")
    parser.add_argument("--json", action="store_true", help="print the rows, not a table")
    args = parser.parse_args(argv)

    # In the compose network the DSN arrives as a mounted secret
    # (`CITADEL_DB_DSN_FILE`), which is how the app reads it too.
    dsn = args.dsn or optional_secret("CITADEL_DB_DSN")
    if not dsn:
        print("CITADEL_DB_DSN is not set", file=sys.stderr)
        return 2

    ids = [args.dataset] if args.dataset else dataset_ids(dsn, args.tenant)
    if not ids:
        print(f"no eval.sample events for tenant {args.tenant}: nothing was sampled yet")
        return 0

    rows: list[dict[str, Any]] = []
    for dataset_id in ids:
        try:
            rows.extend(records(args.tracking_uri, dataset_id))
        except (OSError, ValueError) as exc:
            print(f"{dataset_id}: {exc}", file=sys.stderr)
            return 1
        if len(rows) >= args.limit:
            break

    rows = rows[: args.limit]
    if args.json:
        print(json.dumps(rows, indent=2))
        return 0
    print(f"{len(rows)} row(s) in {len(ids)} dataset(s)")
    for row in rows:
        print("  " + _summary(row, replay=args.replay))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
