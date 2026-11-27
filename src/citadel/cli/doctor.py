"""`citadel doctor`: does each dependency answer, and what would fix the ones that do not.

The point is the hint. "mlflow: down" is a fact; "make mlflow-ui" is the next action, and an
agent that gets neither has to guess. Probes are parameters so the rules can be tested
without a stack.
"""

from __future__ import annotations

import os
import subprocess
import urllib.error
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Final

from citadel.cli import EXIT_OK, EXIT_UNAVAILABLE, emit
from citadel.cli.http import reachable

if TYPE_CHECKING:
    from collections.abc import Callable, Sequence

OK: Final = "ok"
DOWN: Final = "down"
SKIP: Final = "skip"


@dataclass(frozen=True)
class Check:
    name: str
    status: str
    detail: str
    hint: str = ""


@dataclass(frozen=True)
class Report:
    checks: list[Check] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        return not any(check.status == DOWN for check in self.checks)

    def as_dict(self) -> dict[str, object]:
        return {
            "healthy": self.healthy,
            "checks": [
                {"name": c.name, "status": c.status, "detail": c.detail, "hint": c.hint}
                for c in self.checks
            ],
        }


def _compose_services() -> Check:
    """Which Citadel containers are running, from docker rather than from hope."""
    try:
        finished = subprocess.run(
            ["docker", "ps", "--format", "{{.Names}}\t{{.State}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return Check("compose", DOWN, f"docker unavailable: {exc}", "is Docker running?")
    rows = [
        line.split("\t")
        for line in finished.stdout.splitlines()
        if line.startswith("citadel-") or line.startswith("bastion-")
    ]
    running = [name for name, state in rows if state == "running"]
    if not rows:
        return Check("compose", DOWN, "no Citadel containers", "make up")
    return Check("compose", OK, f"{len(running)}/{len(rows)} running")


def _http_check(name: str, url: str, hint: str) -> Check:
    """Whether it answers at all. The status is the answer; the body is not inspected."""
    try:
        status = reachable(url)
    except urllib.error.HTTPError as exc:
        return Check(name, DOWN, f"{url} -> HTTP {exc.code}", hint)
    except (urllib.error.URLError, OSError) as exc:
        return Check(name, DOWN, f"{url} -> {type(exc).__name__}", hint)
    return Check(name, OK, f"{url} -> HTTP {status}")


def _mlflow() -> Check:
    url = os.environ.get("CITADEL_MLFLOW_URL", "http://localhost:5000")
    return _http_check("mlflow", f"{url}/health", "make mlflow-ui (the UI is loopback-only)")


def _api() -> Check:
    url = os.environ.get("CITADEL_API_URL", "http://127.0.0.1:18000")
    return _http_check("api", f"{url}/healthz", "make up")


def _keycloak() -> Check:
    base = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://localhost:18081")
    realm = os.environ.get("KEYCLOAK_REALM", "citadel")
    return _http_check(
        "keycloak",
        f"{base}/realms/{realm}/.well-known/openid-configuration",
        "make up, then scripts/bootstrap-identity.py",
    )


def _temporal_ui() -> Check:
    return _http_check("temporal-ui", "http://localhost:18080", "make up")


PROBES: tuple[Callable[[], Check], ...] = (
    _compose_services,
    _api,
    _mlflow,
    _keycloak,
    _temporal_ui,
)


def run_checks(probes: Sequence[Callable[[], Check]] | None = None) -> Report:
    return Report(checks=[probe() for probe in (probes or PROBES)])


def _line(check: Check) -> str:
    mark = {OK: "ok  ", DOWN: "DOWN", SKIP: "skip"}[check.status]
    line = f"  {mark}  {check.name:<12} {check.detail}"
    return line + (f"\n        -> {check.hint}" if check.status == DOWN and check.hint else "")


def render(report: Report) -> str:
    lines = [_line(check) for check in report.checks]
    verdict = "healthy" if report.healthy else "not healthy"
    return "\n".join([f"citadel doctor: {verdict}", *lines]) + "\n"


def run(*, as_json: bool = False) -> int:
    report = run_checks()
    emit(report.as_dict(), as_json=as_json, text=render(report))
    return EXIT_OK if report.healthy else EXIT_UNAVAILABLE
