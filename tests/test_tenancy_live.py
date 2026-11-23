"""Live tenancy proofs against the running stack.

These need the Compose stack up and the dev users bootstrapped. They are
skipped by default so a clean clone still passes without Docker:

    docker compose up -d
    uv run python scripts/bootstrap-identity.py
    CITADEL_LIVE_TESTS=1 uv run pytest tests/test_tenancy_live.py

Two boundaries are proved: the API propagates the token's tenant, and
Postgres RLS itself denies when the tenant is unset or belongs to someone else.
"""

from __future__ import annotations

import json
import os
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 with the Compose stack running",
)

KC = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://localhost:18081")
API = os.environ.get("CITADEL_API_URL", "http://127.0.0.1:18000")
REALM = os.environ.get("KEYCLOAK_REALM", "citadel")


def _post_form(url: str, fields: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        payload: dict[str, Any] = json.loads(r.read())
    return payload


def _admin_json(path: str) -> Any:
    token = _post_form(
        f"{KC}/realms/master/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.environ["KEYCLOAK_ADMIN_USER"],
            "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
        },
    )["access_token"]
    req = urllib.request.Request(f"{KC}{path}", headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def user_token(username: str) -> str:
    client = _admin_json(f"/admin/realms/{REALM}/clients?clientId=citadel-api")[0]
    secret = _admin_json(f"/admin/realms/{REALM}/clients/{client['id']}/client-secret")["value"]
    token: str = _post_form(
        f"{KC}/realms/{REALM}/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": "citadel-api",
            "client_secret": secret,
            "username": username,
            "password": os.environ["CITADEL_DEV_PASSWORD"],
            "scope": "openid",
        },
    )["access_token"]
    return token


def api_call(
    method: str, path: str, token: str | None, body: dict[str, Any] | None = None
) -> tuple[int, Any]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(
        f"{API}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]


def psql_as_app(sql: str) -> str:
    out = subprocess.run(
        [
            "docker",
            "compose",
            "exec",
            "-T",
            "-e",
            f"PGPASSWORD={os.environ['CITADEL_DB_PASSWORD']}",
            "postgres",
            "psql",
            "-U",
            "citadel_app",
            "-d",
            os.environ.get("POSTGRES_DB", "citadel"),
            "-tAc",
            sql,
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    )
    return out.stdout.strip()


def test_api_rejects_a_request_without_a_token() -> None:
    status, _ = api_call("GET", "/runs", None)
    assert status == 401


def test_cross_tenant_run_is_invisible() -> None:
    """Red team: bob in lab-b must never see a run created by alice in lab-a."""
    alice, bob = user_token("alice"), user_token("bob")
    status, created = api_call("POST", "/runs", alice, {"agent_id": "docker", "risk_tier": "T0"})
    assert status == 201, created
    assert created["tenant_id"] == "lab-a"

    status, mine = api_call("GET", "/runs", alice)
    assert status == 200
    assert created["run_id"] in [r["id"] for r in mine["runs"]]

    status, theirs = api_call("GET", "/runs", bob)
    assert status == 200
    assert theirs["tenant_id"] == "lab-b"
    assert created["run_id"] not in [r["id"] for r in theirs["runs"]]


def test_rls_denies_when_tenant_is_unset() -> None:
    """Fail closed: no app.tenant_id means no rows, not every row."""
    assert psql_as_app("SELECT count(*) FROM runs;") == "0"


def test_rls_scopes_rows_to_the_tenant() -> None:
    lab_a = psql_as_app(
        "BEGIN; SELECT set_config('app.tenant_id','lab-a',true); SELECT count(*) FROM runs; COMMIT;"
    )
    lab_b = psql_as_app(
        "BEGIN; SELECT set_config('app.tenant_id','lab-b',true); SELECT count(*) FROM runs; COMMIT;"
    )
    assert lab_a.splitlines()[-2] != "0"
    assert lab_b.splitlines()[-2] == "0"


def test_app_role_cannot_bypass_rls() -> None:
    row = psql_as_app(
        "SELECT rolsuper || ',' || rolbypassrls FROM pg_roles WHERE rolname='citadel_app';"
    )
    assert row == "false,false"


def _new_run(token: str, agent: str = "docker") -> str:
    status, created = api_call("POST", "/runs", token, {"agent_id": agent, "risk_tier": "T0"})
    assert status == 201, created
    run_id: str = created["run_id"]
    return run_id


def _authorize(token: str, tool: str, run_id: str, agent: str = "docker") -> tuple[int, Any]:
    return api_call(
        "POST", "/policy/authorize", token, {"agent_id": agent, "tool": tool, "run_id": run_id}
    )


def test_policy_allows_a_t0_tool_in_own_tenant() -> None:
    token = user_token("alice")
    status, decision = _authorize(token, "read_logs", _new_run(token))
    assert status == 200
    assert decision["outcome"] == "allow"
    assert decision["tier"] == "T0"


def test_policy_gates_a_t1_tool_behind_approval() -> None:
    token = user_token("alice")
    _status, decision = _authorize(token, "restart_service", _new_run(token))
    assert decision["outcome"] == "requires_approval"
    assert decision["tier"] == "T1"


def test_policy_denies_t2_and_unknown_tools() -> None:
    token = user_token("alice")
    run_id = _new_run(token)
    assert _authorize(token, "delete_volume", run_id)[1]["outcome"] == "deny"
    assert _authorize(token, "exfiltrate_secrets", run_id)[1]["rule_id"] == "tool.unknown"


def test_policy_denies_another_tenants_run() -> None:
    """Red team: bob cannot authorise a tool call against alice's run."""
    alice_run = _new_run(user_token("alice"))
    _status, decision = _authorize(user_token("bob"), "read_logs", alice_run)
    assert decision["outcome"] == "deny"
    assert decision["rule_id"] == "identity.unknown_run"
