#!/usr/bin/env python3
"""Create the Citadel dev users in Keycloak. Idempotent.

Passwords come from CITADEL_DEV_PASSWORD so no credential is ever committed.
Run after `docker compose up -d` has imported the realm:

    uv run python scripts/bootstrap-identity.py
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from citadel.net import open_url

KC = os.environ.get("KEYCLOAK_URL", "http://127.0.0.1:18081")
REALM = os.environ.get("KEYCLOAK_REALM", "citadel")

# Two tenants so cross-tenant tests have something real to cross.
USERS = [
    ("alice", "Alice", "Anderson", "lab-a", ["operator", "approver"]),
    ("bob", "Bob", "Baker", "lab-b", ["operator"]),
    ("carol", "Carol", "Chen", "lab-a", ["approver"]),
]


def call(url: str, data: bytes | None, headers: dict[str, str], method: str = "GET") -> Any:
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with open_url(req, timeout=20) as r:
            body = r.read()
            return json.loads(body) if body else {"_status": r.status}
    except urllib.error.HTTPError as e:
        return {"_http": e.code, "_body": e.read().decode()[:300]}


def admin_token() -> str:
    form = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.environ["KEYCLOAK_ADMIN_USER"],
            "password": os.environ["KEYCLOAK_ADMIN_PASSWORD"],
        }
    ).encode()
    out = call(
        f"{KC}/realms/master/protocol/openid-connect/token",
        form,
        {"Content-Type": "application/x-www-form-urlencoded"},
        "POST",
    )
    if "access_token" not in out:
        sys.exit(f"admin login failed: {out}")
    return out["access_token"]


def main() -> int:
    password = os.environ.get("CITADEL_DEV_PASSWORD")
    if not password:
        sys.exit("CITADEL_DEV_PASSWORD is not set")

    token = admin_token()
    hdr = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    base = f"{KC}/admin/realms/{REALM}"

    roles = {r["name"]: r for r in call(f"{base}/roles", None, hdr)}

    for username, first, last, tenant, wanted in USERS:
        existing = call(f"{base}/users?username={username}&exact=true", None, hdr)
        if isinstance(existing, list) and existing:
            uid = existing[0]["id"]
        else:
            created = call(
                f"{base}/users",
                json.dumps(
                    {
                        "username": username,
                        "firstName": first,
                        "lastName": last,
                        "enabled": True,
                        "email": f"{username}@example.test",
                        "emailVerified": True,
                        "attributes": {"tenant": [tenant]},
                        "credentials": [
                            {"type": "password", "value": password, "temporary": False}
                        ],
                    }
                ).encode(),
                hdr,
                "POST",
            )
            if created.get("_status") != 201:
                sys.exit(f"could not create {username}: {created}")
            uid = call(f"{base}/users?username={username}&exact=true", None, hdr)[0]["id"]

        call(
            f"{base}/users/{uid}/role-mappings/realm",
            json.dumps([roles[r] for r in wanted if r in roles]).encode(),
            hdr,
            "POST",
        )
        user = call(f"{base}/users/{uid}", None, hdr)
        got = (user.get("attributes") or {}).get("tenant")
        if got != [tenant]:
            sys.exit(f"{username}: tenant attribute was dropped ({got!r}); check the user profile")
        print(f"{username:6} tenant={tenant} roles={wanted}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
