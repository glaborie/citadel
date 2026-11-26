"""Live checks: the socket proxy only forwards Citadel's own containers.

Since #110 the proxy fronts the host daemon but accepts only containers named
``citadel-*``; ids and containers from other projects are denied.

    CITADEL_LIVE_TESTS=1 uv run pytest tests/test_socket_proxy_scope_live.py
"""

from __future__ import annotations

import os
import subprocess

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 with the Compose stack running",
)

RUNNER = "citadel-tool-runner-1"
PROXY = "http://docker-socket-proxy:2375"

# Runs inside the sandbox, which is the only network that reaches the proxy.
_PROBE = """
import sys, urllib.error, urllib.request
try:
    with urllib.request.urlopen(sys.argv[1], timeout=5) as response:
        print(response.status)
except urllib.error.HTTPError as error:
    print(error.code)
"""


def proxy_status(path: str) -> str:
    result = subprocess.run(
        ["docker", "exec", RUNNER, "python", "-c", _PROBE, f"{PROXY}{path}"],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def container_names() -> list[str]:
    raw = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], check=True, capture_output=True, text=True
    ).stdout
    return raw.split()


def container_id(name: str) -> str:
    return subprocess.run(
        ["docker", "inspect", "--format", "{{.Id}}", name],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_the_proxy_denies_a_container_from_another_project() -> None:
    others = [name for name in container_names() if not name.startswith("citadel-")]
    if not others:
        pytest.skip("no container from another project is running")
    assert proxy_status(f"/containers/{others[0]}/json") == "403"


def test_the_proxy_denies_a_citadel_container_addressed_by_id() -> None:
    citadel = next(name for name in container_names() if name.startswith("citadel-"))
    assert proxy_status(f"/containers/{container_id(citadel)}/json") == "403"


def test_the_proxy_allows_a_citadel_container_by_name() -> None:
    citadel = next(name for name in container_names() if name.startswith("citadel-"))
    assert proxy_status(f"/containers/{citadel}/json") == "200"
