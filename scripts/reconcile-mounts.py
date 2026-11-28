#!/usr/bin/env python3
"""Recreate the project's containers when they were created from another checkout.

Compose resolves a relative file secret (`secrets/db_dsn` and friends) against
the directory it runs in and stores the resolved path in the container. A stack
started in a worktree therefore keeps that worktree's paths, and once the tree
is pruned, starting those containers fails at container init with ENOENT on the
bind source. `docker compose up` aborts on the first one, so the rest of the
stack never starts either (issue #271).

This retires the containers that would fail — created elsewhere and not running
— so compose recreates them from this checkout. A running container is left
alone: its mount already resolved, and it carries no stale source the next time
compose recreates it.

    scripts/reconcile-mounts.py [--dry-run]
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

WORKING_DIR = "com.docker.compose.project.working_dir"
SERVICE = "com.docker.compose.service"


def _docker(*args: str) -> str:
    done = subprocess.run(["docker", *args], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise SystemExit(f"docker {' '.join(args)} failed: {done.stderr.strip()}")
    return done.stdout


def _labels(container: dict[str, Any]) -> dict[str, str]:
    return (container.get("Config") or {}).get("Labels") or {}


def stale_containers(items: list[dict[str, Any]], here: Path) -> list[dict[str, Any]]:
    """Containers that cannot be started from `here`, because their mounts point
    at a directory that no longer holds this checkout's secrets."""
    stale: list[dict[str, Any]] = []
    for container in items:
        if (container.get("State") or {}).get("Running"):
            # The mount already resolved; a restart would be a recreation.
            continue
        created_in = _labels(container).get(WORKING_DIR)
        if created_in and Path(created_in).is_dir() and Path(created_in).resolve() == here:
            continue
        stale.append(container)
    return stale


def main(argv: list[str]) -> int:
    dry_run = "--dry-run" in argv[1:]
    here = Path.cwd().resolve()
    ids = _docker("compose", "ps", "-aq").split()
    if not ids:
        return 0
    items = json.loads(_docker("inspect", *ids))
    for container in stale_containers(items, here):
        name = str(container.get("Name", "")).lstrip("/")
        labels = _labels(container)
        created_in = labels.get(WORKING_DIR) or "an unknown directory"
        if dry_run:
            print(f"{name}: would recreate (created in {created_in})")
            continue
        _docker("compose", "rm", "-sf", labels[SERVICE])
        print(f"{name}: removed, compose will recreate it (created in {created_in})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
