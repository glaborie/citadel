"""Issue #271: `make up` must not abort on containers from a pruned worktree.

Compose stores the directory it ran in as a label, and a relative file secret is
resolved against it. After `make worktree-prune`, a stopped container created
there cannot start: the daemon fails the bind mount before the process exists,
and `docker compose up` aborts, leaving the rest of the stack on its old
containers. The script decides from the label and the container state, so these
tests drive it with a fake `docker` and no daemon.
"""

from __future__ import annotations

import json
import os
import pathlib
import stat
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "reconcile-mounts.py"

FAKE_DOCKER = """#!/usr/bin/env bash
set -euo pipefail
case "${1:-}" in
  inspect) cat "$FAKE_DOCKER_INSPECT" ;;
  compose)
    case "${2:-}" in
      ps) echo "$FAKE_DOCKER_IDS" ;;
      rm) echo "${4:-}" >> "$FAKE_DOCKER_REMOVED" ;;
    esac ;;
esac
"""


def _container(
    name: str, service: str, working_dir: str | None, *, running: bool
) -> dict[str, object]:
    labels = {"com.docker.compose.service": service}
    if working_dir is not None:
        labels["com.docker.compose.project.working_dir"] = working_dir
    return {"Name": f"/{name}", "State": {"Running": running}, "Config": {"Labels": labels}}


def _run(tmp_path: pathlib.Path, containers: list[dict[str, object]], *args: str) -> str:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    fake = bin_dir / "docker"
    fake.write_text(FAKE_DOCKER, encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    inspect = tmp_path / "inspect.json"
    inspect.write_text(json.dumps(containers), encoding="utf-8")
    removed = tmp_path / "removed.log"
    removed.write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "FAKE_DOCKER_INSPECT": str(inspect),
        "FAKE_DOCKER_IDS": " ".join(f"id{index}" for index in range(len(containers))),
        "FAKE_DOCKER_REMOVED": str(removed),
    }
    # Through the interpreter, not the exec bit: this test is about the decision,
    # and tests/test_script_modes.py already guards that the script is executable.
    done = subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout + removed.read_text(encoding="utf-8")


def test_a_container_from_a_pruned_worktree_is_retired(tmp_path: pathlib.Path) -> None:
    gone = str(tmp_path / "gone")
    output = _run(
        tmp_path, [_container("citadel-openfga-migrate-1", "openfga-migrate", gone, running=False)]
    )
    assert "removed" in output, output
    assert "openfga-migrate" in output, "compose rm must name the service, not the container"


def test_a_container_from_this_checkout_is_left_alone(tmp_path: pathlib.Path) -> None:
    output = _run(
        tmp_path, [_container("citadel-api-1", "api", str(tmp_path), running=False)]
    )
    assert output.strip() == "", output


def test_a_running_container_from_another_checkout_is_left_alone(tmp_path: pathlib.Path) -> None:
    """Its mount already resolved: restarting it is compose's decision, not ours."""
    output = _run(
        tmp_path,
        [_container("citadel-api-1", "api", str(tmp_path / "gone"), running=True)],
    )
    assert output.strip() == "", output


def test_dry_run_reports_without_removing(tmp_path: pathlib.Path) -> None:
    output = _run(
        tmp_path,
        [_container("citadel-postgres-1", "postgres", str(tmp_path / "gone"), running=False)],
        "--dry-run",
    )
    assert "would recreate" in output, output
    assert "removed" not in output, output


def test_no_containers_is_not_an_error(tmp_path: pathlib.Path) -> None:
    assert _run(tmp_path, []).strip() == ""
