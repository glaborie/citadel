"""Read sampled runs back out of the MLflow eval dataset.

The dataset is found by name. A filtered search resolves it
(`filter_string="name = ..."` plus an explicit `order_by`); filtering by `experiment_ids`
returns nothing for datasets created through this API, which is a trap worth knowing. The
`eval.sample` audit events remain the fallback, for datasets created before a name was
recorded or after the name changed.

    make eval-samples              # everything, five rows
    make eval-samples ARGS="--limit 20 --replay"

Runs inside the compose network, where both the database and MLflow are reachable.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from citadel.db import tenant_connection
from citadel.env import optional_secret
from citadel.evals import online

LEDGER_SQL = (
    "SELECT payload FROM audit_events WHERE tenant_id = %s"
    " AND event_type = 'eval.sample' ORDER BY seq DESC"
)


LEVELS = {
    "run.start": "start",
    "run.end": "end",
    "model.call": "model",
    "tool.call": "tool",
    "policy.decision": "policy",
    "dlp.event": "dlp",
    "retrieval.query": "retrieval",
    "retrieval.result": "retrieval",
    "approval.decision": "approval",
    "recovery": "recovery",
}

REDACTION = re.compile(r"&lt;([A-Z][A-Z0-9_ ]{1,24})&gt;")


def _escape(value: Any) -> str:
    return html.escape(str(value), quote=False)


def _answer(text: str) -> str:
    """Show a kept answer, with what the detector removed visibly marked."""

    def mark(match: re.Match[str]) -> str:
        return f'<span class="redacted">&lt;{match.group(1)}&gt;</span>'

    return REDACTION.sub(mark, _escape(text))


def _facts(event: dict[str, Any]) -> str:
    """The fields a reader needs, and nothing that repeats the header."""
    skip = {"type", "run_id", "tenant_id", "answer", "output", "findings"}
    facts = [
        f'<span class="fact"><b>{_escape(key)}</b> {_escape(value)}</span>'
        for key, value in event.items()
        if key not in skip and not isinstance(value, (dict, list))
    ]
    return "".join(facts)


def _body(event: dict[str, Any]) -> str:
    kind = event.get("type", "?")
    parts = []
    if isinstance(event.get("answer"), str):
        parts.append(f'<p class="answer">{_answer(event["answer"])}</p>')
    if isinstance(event.get("output"), dict):
        pretty = json.dumps(event["output"], indent=2, ensure_ascii=False)[:1200]
        parts.append(f"<pre>{_escape(pretty)}</pre>")
    if isinstance(event.get("findings"), list) and event["findings"]:
        kinds = sorted({str(item.get("category", item)) for item in event["findings"]})
        parts.append(f'<p class="note">findings: {_escape(", ".join(kinds))}</p>')
    if kind == "tool.call" and event.get("output_redacted"):
        parts.append('<p class="note">the tool answer was withheld by the detector</p>')
    return "".join(parts)


def render_html(rows: list[dict[str, Any]], *, graded: dict[str, list[str]] | None = None) -> str:
    """One page a human can read: the trajectory in order, redactions marked."""
    cards = []
    for row in rows:
        inputs = row.get("inputs", {})
        events = row.get("outputs", {}).get("trajectory", [])
        run_id = str(inputs.get("run_id", "?"))
        failed = (graded or {}).get(run_id, [])
        badge = (
            '<span class="ok">graders pass</span>'
            if graded is not None and not failed
            else f'<span class="bad">{len(failed)} failed</span>'
            if failed
            else ""
        )
        steps = "".join(
            f'<li class="step {LEVELS.get(str(e.get("type")), "other")}">'
            f'<div class="head"><span class="kind">{_escape(e.get("type", "?"))}</span>'
            f"{_facts(e)}</div>{_body(e)}</li>"
            for e in events
        )
        alias = _escape(inputs.get("model_alias", "?"))
        pack = _escape(inputs.get("prompt_pack_version", "?"))
        version = _escape(inputs.get("dataset_version", "?"))
        subtitle = f"{alias} · {pack} · dataset v{version} · {len(events)} events"
        cards.append(
            f'<section class="run"><h2>{_escape(run_id[:8])} '
            f'<span class="muted">{subtitle}</span> {badge}</h2>'
            f'<ol class="timeline">{steps}</ol></section>'
        )
    return _PAGE.format(body="".join(cards), count=len(rows))


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sampled runs</title><style>
:root {{ color-scheme: light dark; --bg: #fff; --fg: #111; --muted: #666; --line: #e3e3e3;
         --card: #fafafa; --accent: #2b6cb0; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg: #16181c; --fg: #e8e8e8; --muted: #9aa0a6; --line: #2c3038; --card: #1d2025;
           --accent: #7ab7ff; }}
}}
body {{ background: var(--bg); color: var(--fg); margin: 0; padding: 24px;
        font: 14px/1.5 ui-sans-serif, system-ui, sans-serif; }}
h1 {{ font-size: 18px; margin: 0 0 4px; }}
h2 {{ font-size: 15px; margin: 0 0 12px; font-weight: 600; }}
.muted {{ color: var(--muted); font-weight: 400; }}
.run {{ border-top: 1px solid var(--line); padding: 18px 0; }}
.timeline {{ list-style: none; margin: 0; padding: 0 0 0 14px;
              border-left: 2px solid var(--line); }}
.step {{ position: relative; margin: 0 0 10px; padding: 8px 12px; background: var(--card);
         border: 1px solid var(--line); border-radius: 8px; }}
.step::before {{ content: ""; position: absolute; left: -21px; top: 14px; width: 9px; height: 9px;
                 border-radius: 50%; background: var(--muted); }}
.step.start::before, .step.end::before {{ background: var(--accent); }}
.step.dlp::before {{ background: #d9822b; }}
.step.tool::before {{ background: #2f855a; }}
.head {{ display: flex; flex-wrap: wrap; gap: 4px 12px; align-items: baseline; }}
.kind {{ font-weight: 600; font-variant-numeric: tabular-nums; }}
.fact {{ color: var(--muted); font-size: 12.5px; }}
.fact b {{ color: var(--fg); font-weight: 500; }}
.answer {{ margin: 8px 0 0; white-space: pre-wrap; }}
pre {{ margin: 8px 0 0; padding: 8px; overflow-x: auto; background: var(--bg);
       border: 1px solid var(--line); border-radius: 6px; font-size: 12.5px; }}
.note {{ margin: 8px 0 0; color: var(--muted); font-size: 12.5px; }}
.redacted {{ background: rgba(217, 130, 43, .18); border-radius: 3px; padding: 0 2px; }}
.ok {{ color: #2f855a; font-size: 12px; border: 1px solid currentColor; border-radius: 10px;
       padding: 1px 8px; }}
.bad {{ color: #c53030; font-size: 12px; border: 1px solid currentColor; border-radius: 10px;
        padding: 1px 8px; }}
</style></head><body>
<h1>Sampled runs</h1>
<p class="muted">{count} row(s) from the eval dataset. Orange marks what the detector removed.</p>
{body}
</body></html>
"""


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


def base_url(tracking_uri: str) -> str:
    """http(s) only, and only the origin.

    The dataset id comes from the ledger and the tracking URI from the environment, so
    neither may steer where this reads: `file://` would read the disk, and a path in the
    base would silently retarget the request. Both are refused here, which is also why the
    URL is not interpolated into a bare `urlopen(url)` call.
    """
    parts = urllib.parse.urlsplit(tracking_uri)
    if parts.scheme not in {"http", "https"} or not parts.netloc:
        raise ValueError(f"tracking uri must be http(s), got {tracking_uri!r}")
    return f"{parts.scheme}://{parts.netloc}"


def fetch(request: urllib.request.Request) -> dict[str, Any]:
    """The only call site that opens a connection, so there is one thing to justify.

    The rule's premise is an actor-controlled URL. These are not: the host is the
    operator's tracking URI, constrained to http(s) by base_url(), and the dataset id -
    the one value that comes from data - is percent-escaped into the path.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    """
    with urllib.request.urlopen(request, timeout=15) as response:
        return dict(json.loads(response.read()))


def find_by_name(tracking_uri: str, name: str) -> str | None:
    """The id for a dataset name, or None when this server has no such dataset."""
    body = {
        "filter_string": f'name = "{name}"',
        "max_results": 2,
        "order_by": ["created_time DESC"],
    }
    request = urllib.request.Request(
        f"{base_url(tracking_uri)}/api/3.0/mlflow/datasets/search",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"},
    )
    found = fetch(request).get("datasets") or []
    return str(found[0]["dataset_id"]) if found else None


def records(tracking_uri: str, dataset_id: str) -> list[dict[str, Any]]:
    path = f"/api/3.0/mlflow/datasets/{urllib.parse.quote(dataset_id, safe='')}/records"
    body = fetch(urllib.request.Request(f"{base_url(tracking_uri)}{path}")).get("records", [])
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
    parser.add_argument("--name", default="citadel-online-samples", help="dataset to read")
    parser.add_argument("--dataset", help="an exact dataset id, instead of the name")
    parser.add_argument("--limit", type=int, default=5)
    parser.add_argument("--replay", action="store_true", help="grade each row as it prints")
    parser.add_argument("--json", action="store_true", help="print the rows, not a table")
    parser.add_argument("--html", type=Path, help="write a readable page instead of a table")
    args = parser.parse_args(argv)

    # In the compose network the DSN arrives as a mounted secret
    # (`CITADEL_DB_DSN_FILE`), which is how the app reads it too.
    dsn = args.dsn or optional_secret("CITADEL_DB_DSN")
    if not dsn:
        print("CITADEL_DB_DSN is not set", file=sys.stderr)
        return 2

    named = None if args.dataset else find_by_name(args.tracking_uri, args.name)
    ids = [args.dataset] if args.dataset else [named] if named else dataset_ids(dsn, args.tenant)
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
    if args.html is not None:
        graded = None
        if args.replay:
            graded = {
                str(row.get("inputs", {}).get("run_id", "?")): [
                    item.grader for item in online.replay(row) if not item.passed
                ]
                for row in rows
            }
        args.html.write_text(render_html(rows, graded=graded), encoding="utf-8")
        print(f"{len(rows)} row(s) written to {args.html}")
        return 0
    print(f"{len(rows)} row(s) in {len(ids)} dataset(s)")
    for row in rows:
        print("  " + _summary(row, replay=args.replay))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
