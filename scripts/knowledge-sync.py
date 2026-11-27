#!/usr/bin/env python3
"""Make a tenant's index match its corpus, in one command.

Three faults are possible and this script is about the third:

1. the corpus is empty                       -> retrieval returns nothing, honestly
2. the corpus is stale                       -> the *content* is wrong, and only a human fixes it
3. the index holds documents the corpus lost -> the index serves evidence for hosts that no
                                                longer exist (issue #216)

(3) is mechanical, so it is scripted. The inventory is generated from the live daemon because a
hand-written one goes stale silently; everything curated (`knowledge/runbooks/*`, ownership,
escalation) stays a human document.

    scripts/knowledge-sync.py                  # regenerate, ingest, prune
    scripts/knowledge-sync.py --dry-run        # show the document, change nothing
    scripts/knowledge-sync.py --tenant lab-a --skip-ingest
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INVENTORY = ROOT / "knowledge" / "topology" / "host-inventory.md"


def containers(ps_output: str) -> list[tuple[str, str]]:
    """`docker ps --format '{{.Names}}|{{.Status}}'` output, as (name, status) pairs."""
    rows: list[tuple[str, str]] = []
    for line in ps_output.splitlines():
        name, _, status = line.strip().partition("|")
        if name:
            rows.append((name, status.strip() or "unknown"))
    return rows


def project(name: str) -> str:
    """The compose project a container belongs to, by its naming convention.

    Every container here is `<project>-<service>-<index>`, so the first segment is the project.
    Three projects share this daemon - citadel, bastion, freellmapi - which is why "a container"
    is never a complete answer on this host.
    """
    return name.split("-", 1)[0]


def render(rows: list[tuple[str, str]], generated_at: str, command: str) -> str:
    """The inventory, as a document a retrieval chunk can stand alone in."""
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for name, status in rows:
        grouped[project(name)].append((name, status))

    lines = [
        "# This host's containers, grouped by the project that owns them",
        "",
        f"{len(rows)} containers across {len(grouped)} projects on one Docker daemon. "
        '"A container" is therefore never a complete answer: name the project as well.',
        "",
    ]
    for name, entries in sorted(grouped.items()):
        lines += [f"## {name}", "", f"{len(entries)} containers.", ""]
        lines += [f"- `{container}` - {status}" for container, status in sorted(entries)]
        lines.append("")
    lines += [
        "## Provenance",
        "",
        f"generated: {generated_at} from `{command}`. Regenerate after every compose change:",
        "`make knowledge-sync`. A container missing from this list has been removed; the sync",
        "prunes its chunks from the index, so a stale document cannot be served as evidence.",
        "",
    ]
    return "\n".join(lines)


def docker_ps() -> str:
    if shutil.which("docker") is None:
        raise SystemExit("docker is not on PATH; the inventory is generated from the live daemon")
    result = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}|{{.Status}}"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise SystemExit(f"docker ps failed: {result.stderr.strip()}")
    return result.stdout


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Regenerate, ingest and prune a tenant's corpus")
    parser.add_argument("--tenant", default="lab-a")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--skip-ingest", action="store_true")
    args = parser.parse_args(argv)

    from datetime import UTC, datetime

    command = "docker ps --format '{{.Names}}|{{.Status}}'"
    document = render(
        containers(docker_ps()), datetime.now(UTC).isoformat(timespec="seconds"), command
    )

    if args.dry_run:
        print(document)
        return 0

    INVENTORY.parent.mkdir(parents=True, exist_ok=True)
    INVENTORY.write_text(document, encoding="utf-8")
    print(f"regenerated {INVENTORY.relative_to(ROOT)}")

    if args.skip_ingest:
        return 0

    print(f"ingesting knowledge/ into {args.tenant} and pruning documents it no longer has")
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--profile",
            "tools",
            "run",
            "--rm",
            "ingest",
            "--tenant",
            args.tenant,
            "--prune",
        ],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
