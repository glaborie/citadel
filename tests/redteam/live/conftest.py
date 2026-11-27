"""Fixtures for the live red-team suite.

Everything here assumes the compose stack is up and reachable from the host on
the published ports. The suite is opt-in (``CITADEL_LIVE=1``) because CI has no
stack and a live suite that silently skips is worse than one that never runs.

Seeding goes through ``docker compose exec`` so the tests can create the rows
they need without a published Postgres port, and every seeded row is deleted
afterwards.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

REPO = Path(__file__).parents[3]
# The worktree has no .env (it is ignored), and docker compose must run where the
# stack was created, or it would look for a project named after this directory.
MAIN = Path(os.environ.get("CITADEL_MAIN_REPO", str(Path.home() / "projects" / "citadel")))
_explicit = os.environ.get("CITADEL_ENV_FILE")
ENV_FILES: list[Path] = [Path(_explicit)] if _explicit else []
ENV_FILES += [REPO / ".env", MAIN / ".env"]
API = os.environ.get("CITADEL_API_URL", "http://localhost:18000")
KEYCLOAK = os.environ.get("CITADEL_KEYCLOAK_URL", "http://localhost:18081")
REALM = os.environ.get("KEYCLOAK_REALM", "citadel")
CLIENT = os.environ.get("KEYCLOAK_CLIENT_ID", "citadel-api")


def env_value(name: str) -> str:
    """Environment first, then the stack's .env file, so the suite needs no exports."""
    if name in os.environ:
        return os.environ[name]
    for env_file in ENV_FILES:
        if not env_file or not env_file.exists():
            continue
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if line.startswith(f"{name}="):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    searched = [str(path) for path in ENV_FILES if path]
    raise pytest.skip(f"{name} not available in the environment or {searched}")


def http_json(url: str, *, token: str | None = None, payload: dict[str, Any] | None = None) -> Any:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None if payload is None else json.dumps(payload).encode()
    method = "POST" if data else "GET"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(request, timeout=15) as response:
        return json.loads(response.read())


def form_json(url: str, fields: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        body: dict[str, Any] = json.loads(response.read())
    return body


def sub_of(token: str) -> str:
    """The run owner is the token subject, so tests need it without verifying the JWT."""
    payload = token.split(".")[1]
    padded = payload + "=" * (-len(payload) % 4)
    claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(padded))
    return str(claims["sub"])


@dataclass(frozen=True)
class Tokens:
    alice: str
    bob: str
    carol: str

    def sub(self, who: str) -> str:
        return sub_of(getattr(self, who))


@pytest.fixture(scope="session")
def live() -> None:
    if os.environ.get("CITADEL_LIVE") != "1":
        pytest.skip("set CITADEL_LIVE=1 to run against the compose stack")
    try:
        http_json(f"{API}/healthz")
    except Exception as exc:  # noqa: BLE001 - any failure means not reachable
        pytest.skip(f"stack not reachable at {API}: {exc}")


@pytest.fixture(scope="session")
def tokens(live: None) -> Tokens:
    admin = form_json(
        f"{KEYCLOAK}/realms/master/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": env_value("KEYCLOAK_ADMIN_USER"),
            "password": env_value("KEYCLOAK_ADMIN_PASSWORD"),
        },
    ).get("access_token")
    if not admin:
        pytest.skip("could not obtain a Keycloak admin token")

    clients = http_json(
        f"{KEYCLOAK}/admin/realms/{REALM}/clients?clientId={CLIENT}", token=str(admin)
    )
    if not clients:
        pytest.skip(f"client {CLIENT} not found in realm {REALM}")
    client_id = clients[0]["id"]
    secret = http_json(
        f"{KEYCLOAK}/admin/realms/{REALM}/clients/{client_id}/client-secret", token=str(admin)
    )["value"]

    issued: dict[str, str] = {}
    for user in ("alice", "bob", "carol"):
        body = form_json(
            f"{KEYCLOAK}/realms/{REALM}/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": CLIENT,
                "client_secret": str(secret),
                "username": user,
                "password": env_value("CITADEL_DEV_PASSWORD"),
            },
        )
        token = body.get("access_token")
        if not token:
            pytest.skip(f"no token for {user}: {str(body)[:120]}")
        issued[user] = str(token)
    return Tokens(alice=issued["alice"], bob=issued["bob"], carol=issued["carol"])


def psql(sql: str) -> str:
    completed = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "postgres",
            "psql",
            "-U",
            env_value("POSTGRES_USER"),
            "-d",
            env_value("POSTGRES_DB"),
            "-tAc",
            sql,
        ],
        cwd=MAIN if (MAIN / "compose.yaml").exists() else REPO,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        pytest.skip(f"psql unavailable: {completed.stderr.strip()[:160]}")
    return completed.stdout.strip()


@pytest.fixture
def seeded_runs(tokens: Tokens) -> Any:
    """One lab-b run owned by bob, one lab-a run owned by carol (the approver)."""
    foreign = str(uuid.uuid4())
    own = str(uuid.uuid4())
    psql(
        "INSERT INTO runs (id, tenant_id, user_id, agent_id, risk_tier, status) VALUES "
        f"('{foreign}', 'lab-b', '{tokens.sub('bob')}', 'docker', 'T0', 'created'), "
        f"('{own}', 'lab-a', '{tokens.sub('carol')}', 'docker', 'T0', 'created')"
    )
    try:
        yield {"foreign_lab_b": foreign, "owned_by_carol": own}
    finally:
        psql(f"DELETE FROM runs WHERE id IN ('{foreign}', '{own}')")
