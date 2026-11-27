#!/usr/bin/env python3
"""Start a Citadel run from the host, the way the stack expects it.

There is no run button in the MLflow UI and there is not meant to be: a run starts on the
Citadel API (`POST /runs`), which takes the tenant and the user from a Keycloak token and
never from the request body. Minting that token by hand is four requests deep - admin token,
client secret, password grant, then the run - so it is scripted here once.

    scripts/start-run.py --task "Call inspect_containers, then name one running container."
    scripts/start-run.py --token-only          # a bearer token for curl, nothing else
    scripts/start-run.py --task "..." --wait   # poll until the workflow finishes

Credentials come from the environment or, like every consumer in this stack, from
`<NAME>_FILE`:

    KEYCLOAK_PUBLIC_URL   default http://localhost:18081
    KEYCLOAK_REALM        default citadel
    KEYCLOAK_CLIENT_ID    default citadel-api
    KEYCLOAK_ADMIN_USER   the admin that reads the client secret
    KEYCLOAK_ADMIN_PASSWORD / KEYCLOAK_ADMIN_PASSWORD_FILE   (secrets/keycloak_admin_password)
    CITADEL_DEV_PASSWORD / CITADEL_DEV_PASSWORD_FILE         the dev user's password
    CITADEL_API_URL       default http://127.0.0.1:18000

`set -a; . ./.env; set +a` before running is enough; the secret files are only a fallback.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

KEYCLOAK_URL = os.environ.get("KEYCLOAK_PUBLIC_URL", "http://localhost:18081").rstrip("/")
REALM = os.environ.get("KEYCLOAK_REALM", "citadel")
CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "citadel-api")
API_URL = os.environ.get("CITADEL_API_URL", "http://127.0.0.1:18000").rstrip("/")
SECRETS_DIR = pathlib.Path(os.environ.get("CITADEL_SECRETS_DIR", "secrets"))

TERMINAL = {"completed", "failed", "cancelled"}


def setting(name: str, default: str = "") -> str:
    """An environment value, else the file this stack stores that credential in."""
    value = os.environ.get(name, "").strip()
    if value:
        return value
    for candidate in (os.environ.get(f"{name}_FILE", ""), str(SECRETS_DIR / name.lower())):
        if candidate and pathlib.Path(candidate).is_file():
            return pathlib.Path(candidate).read_text(encoding="utf-8").strip()
    return default


def open_request(request: urllib.request.Request) -> Any:
    """Send it and parse the answer. The one place a connection is opened."""
    # The rule's premise is an actor-controlled URL. These URLs are assembled from the
    # operator's environment (a base URL and fixed paths), and the only values interpolated
    # into a path are percent-escaped; no response or argument chooses the host.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(request, timeout=30) as response:
        body = response.read()
    return json.loads(body) if body else {}


def post_form(url: str, fields: dict[str, str]) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    payload: dict[str, Any] = open_request(request)
    return payload


def admin_token() -> str:
    user = setting("KEYCLOAK_ADMIN_USER")
    password = setting("KEYCLOAK_ADMIN_PASSWORD")
    if not user or not password:
        raise SystemExit(
            "KEYCLOAK_ADMIN_USER and KEYCLOAK_ADMIN_PASSWORD must be set "
            "(or secrets/keycloak_admin_password must exist)"
        )
    return str(
        post_form(
            f"{KEYCLOAK_URL}/realms/master/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": user,
                "password": password,
            },
        )["access_token"]
    )


def client_secret(token: str) -> str:
    """The API client's secret, read from Keycloak: no copy of it lives in this repo."""
    listing = open_request(
        urllib.request.Request(
            f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients"
            f"?clientId={urllib.parse.quote(CLIENT_ID, safe='')}",
            headers={"Authorization": f"Bearer {token}"},
        )
    )
    if not listing:
        raise SystemExit(f"no client {CLIENT_ID!r} in realm {REALM!r}")
    return str(
        open_request(
            urllib.request.Request(
                f"{KEYCLOAK_URL}/admin/realms/{REALM}/clients/"
                f"{urllib.parse.quote(str(listing[0]['id']), safe='')}/client-secret",
                headers={"Authorization": f"Bearer {token}"},
            )
        )["value"]
    )


def user_token(username: str) -> str:
    password = setting("CITADEL_DEV_PASSWORD")
    if not password:
        raise SystemExit("CITADEL_DEV_PASSWORD must be set, or secrets/citadel_dev_password")
    return str(
        post_form(
            f"{KEYCLOAK_URL}/realms/{REALM}/protocol/openid-connect/token",
            {
                "grant_type": "password",
                "client_id": CLIENT_ID,
                "client_secret": client_secret(admin_token()),
                "username": username,
                "password": password,
                "scope": "openid",
            },
        )["access_token"]
    )


def run_body(*, agent: str, risk_tier: str, pack: str, alias: str, task: str) -> dict[str, Any]:
    """Exactly the fields `RunRequest` accepts; it forbids anything else."""
    return {
        "agent_id": agent,
        "risk_tier": risk_tier,
        "prompt_pack_version": pack,
        "model_alias": alias,
        "task": task,
    }


def submit(token: str, body: dict[str, Any]) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{API_URL}/runs",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    created: dict[str, Any] = open_request(request)
    return created


def status_of(token: str, run_id: str) -> str | None:
    listing = open_request(
        urllib.request.Request(f"{API_URL}/runs", headers={"Authorization": f"Bearer {token}"})
    )
    return {row["id"]: row["status"] for row in listing.get("runs", [])}.get(run_id)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--task", default="", help="what the agent should do; empty only records the run"
    )
    parser.add_argument("--agent", default="docker", help="agent whose skill pack runs it")
    parser.add_argument("--pack", default="", help="prompt pack version (default: <agent>-1.0.0)")
    parser.add_argument("--alias", default="auto/best-fast", help="model alias")
    parser.add_argument("--risk-tier", default="T0")
    parser.add_argument("--user", default="alice", help="dev user whose identity the run carries")
    parser.add_argument("--token-only", action="store_true", help="print a bearer token and stop")
    parser.add_argument("--wait", action="store_true", help="poll until the run leaves 'created'")
    parser.add_argument("--timeout", type=float, default=240.0)
    args = parser.parse_args()

    token = user_token(args.user)
    if args.token_only:
        print(token)
        return 0

    body = run_body(
        agent=args.agent,
        risk_tier=args.risk_tier,
        pack=args.pack or f"{args.agent}-1.0.0",
        alias=args.alias,
        task=args.task,
    )
    created = submit(token, body)
    run_id = str(created["run_id"])
    print(f"run {run_id} created for {args.user} ({args.agent}, {body['prompt_pack_version']})")
    if args.task:
        print("the trace appears in MLflow under citadel-trajectories once the workflow ends")

    if args.wait and args.task:
        deadline = time.time() + args.timeout
        outcome: str | None = "created"
        while time.time() < deadline and outcome not in TERMINAL:
            time.sleep(3)
            outcome = status_of(token, run_id)
        print(f"run {run_id}: {outcome}")
        return 0 if outcome == "completed" else 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
