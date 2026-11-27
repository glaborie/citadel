"""#228: the ADR-012 baseline covers the infrastructure tier, not just the sandbox.

`no-new-privileges` and a pid ceiling change nothing for a healthy service and
remove two whole failure classes: a setuid binary raising itself after a
dependency is exploited, and one container exhausting the host's pid table for
every other service. The sandbox and the workers carry them through `x-app`;
this test keeps the third-party infrastructure from quietly losing them again.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.yaml"
ARCHITECTURE_DOC = ROOT / "docs/architecture.md"

# Below this, a service that legitimately spawns threads (a JVM, a database, a
# query engine) would hit the ceiling under normal load; far above it, the limit
# stops bounding anything worth bounding.
MIN_PIDS = 64
MAX_PIDS = 4096

# Roles that count threads, not processes: they need real headroom.
THREAD_HEAVY = ("postgres", "keycloak", "temporal", "qdrant")


def _compose() -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Split compose.yaml into YAML aliases (`&name`) and services.

    Anchors are keyed by their alias, because that is what `<<: *name` refs.
    """
    anchors: dict[str, list[str]] = {}
    services: dict[str, list[str]] = {}
    mode: str | None = None
    current: list[str] | None = None

    for line in COMPOSE_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            anchor = re.match(r"^(x-[a-z0-9_-]+): &([a-z0-9_-]+)", line)
            if anchor:
                mode = "anchors"
                current = anchors.setdefault(anchor.group(2), [])
            elif line.startswith("services:"):
                mode = "services"
                current = None
            else:
                mode = None
                current = None
            continue
        if mode == "anchors" and current is not None:
            current.append(line)
        elif mode == "services":
            service = re.match(r"^  ([a-z0-9_-]+):", line)
            if service:
                current = services.setdefault(service.group(1), [])
            elif current is not None:
                current.append(line)

    return anchors, services


def _effective(block: list[str], anchors: dict[str, list[str]]) -> str:
    """A service's text with every `<<: *alias` it references inlined."""
    text = "\n".join(block)
    inherited = [
        line
        for alias in re.findall(r"^\s*<<: \*([a-z0-9_-]+)$", text, re.MULTILINE)
        for line in anchors[alias]
    ]
    return "\n".join(inherited + block)


def _pids(text: str) -> int | None:
    match = re.search(r"^\s*pids_limit: (\d+)\s*$", text, re.MULTILINE)
    return int(match.group(1)) if match else None


def test_the_shared_anchors_carry_both_flags() -> None:
    anchors, _ = _compose()
    for alias in ("app", "infra"):
        assert alias in anchors, f"&{alias} is how a new service inherits the baseline"
        text = "\n".join(anchors[alias])
        assert "- no-new-privileges:true" in text, f"&{alias} lost no-new-privileges"
        assert _pids(text) is not None, f"&{alias} lost its pid ceiling"


def test_every_service_restricts_new_privileges_and_its_pid_count() -> None:
    anchors, services = _compose()
    assert len(services) > 20, "the service parser is asleep; it found almost nothing"

    for name, block in services.items():
        text = _effective(block, anchors)
        assert "- no-new-privileges:true" in text, (
            f"{name} can still gain privileges: a setuid binary inside it escalates"
        )
        pids = _pids(text)
        assert pids is not None, (
            f"{name} has no pids_limit, so a fork bomb in it takes the host's pid "
            "table down for every other service"
        )
        assert MIN_PIDS <= pids <= MAX_PIDS, (
            f"{name} pids_limit={pids} is outside {MIN_PIDS}-{MAX_PIDS}: either it "
            "starves a healthy service or it bounds nothing"
        )

    for name in THREAD_HEAVY:
        heavy = _pids(_effective(services[name], anchors))
        assert heavy is not None and heavy >= 256, (
            f"{name} counts threads, not just processes; its ceiling is too tight"
        )


def _docker_runs(text: str) -> list[str]:
    """Every `docker run` in a file, with its line continuations joined back."""
    joined = re.sub(r"\\\n\s*", " ", text)
    return [line.strip() for line in joined.splitlines() if "docker run" in line]


def test_the_loopback_sidecars_get_the_same_baseline() -> None:
    """`make grafana-ui` and `make mlflow-ui` create their own citadel-* containers.

    They live outside compose.yaml, so no anchor reaches them, but the bench lists
    them like any other container and a fork bomb in one still hits the host.
    """
    for path in (ROOT / "scripts/mlflow-ui.sh", ROOT / "Makefile"):
        runs = [run for run in _docker_runs(path.read_text(encoding="utf-8")) if "--name" in run]
        assert len(runs) == 1, f"{path.name}: expected one sidecar launch, found {len(runs)}"
        run = runs[0]
        assert "--pids-limit" in run, f"{path.name} starts a sidecar with no pid ceiling"
        assert "--security-opt no-new-privileges" in run, (
            f"{path.name} starts a sidecar that can gain privileges"
        )


def test_the_baseline_is_documented_as_stack_wide() -> None:
    doc = ARCHITECTURE_DOC.read_text(encoding="utf-8")
    assert "pids_limit" in doc, "an operator reading §7 would not know this exists"
    assert "x-infra" in doc, "the anchor new services inherit must be named"
    assert "no-new-privileges" in doc
