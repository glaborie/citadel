"""Live check: no provisioned secret is visible to the Docker API.

The sandbox reaches the Docker API through the socket proxy, and the API
exposes every container's ``Config``. Since #108 the credentials are bound as
files, so none of their values may appear there. Host ``docker inspect`` calls
the same API the proxy fronts; the Config it returns is identical.

    CITADEL_LIVE_TESTS=1 uv run pytest tests/test_socket_proxy_live.py
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 with the Compose stack running",
)

# Exact names, so a new non-secret key never trips the check by accident.
SENSITIVE = {
    "POSTGRES_PASSWORD",
    "CITADEL_DB_PASSWORD",
    "KEYCLOAK_ADMIN_PASSWORD",
    "OPENROUTER_API_KEY",
    "OMNIROUTE_API_KEY",
    "OMNIROUTE_JWT_SECRET",
    "OMNIROUTE_API_KEY_SECRET",
    "OMNIROUTE_STORAGE_ENCRYPTION_KEY",
    "OMNIROUTE_ADMIN_PASSWORD",
    "CITADEL_CONSOLE_SESSION_KEY",
    "CITADEL_RUN_TOKEN_PRIVATE_KEY",
    "GH_READ_TOKEN",
    "GH_WRITE_TOKEN",
}


def provisioned_values() -> set[str]:
    values: set[str] = set()
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            name, sep, value = line.partition("=")
            if sep and name in SENSITIVE:
                values.add(value)
    for path in (ROOT / "secrets").glob("*"):
        if path.name == "citadel.env":
            continue
        values.add(path.read_text(encoding="utf-8").strip())
    # A short value can be a substring of unrelated config; every real
    # credential in this repo is long.
    return {value for value in values if len(value) >= 6}


def container_configs() -> list[tuple[str, str]]:
    ids = subprocess.run(
        ["docker", "ps", "-aq"], check=True, capture_output=True, text=True
    ).stdout.split()
    configs: list[tuple[str, str]] = []
    for container_id in ids:
        raw = subprocess.run(
            ["docker", "inspect", "--format", "{{json .}}", container_id],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        config = json.loads(raw)["Config"] or {}
        configs.append((json.loads(raw)["Name"].lstrip("/"), json.dumps(config)))
    return configs


def test_no_provisioned_secret_is_visible_in_a_container_config() -> None:
    values = provisioned_values()
    assert values, "no provisioned secret values found to check"
    exposed = [
        name for name, config in container_configs() if any(value in config for value in values)
    ]
    assert not exposed, f"containers still expose a provisioned secret: {exposed}"
