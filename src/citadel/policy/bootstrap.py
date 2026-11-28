"""Load the versioned OpenFGA model and its dev tuples. Idempotent.

    make policy-bootstrap

That runs the `policy-bootstrap` one-shot, which mounts the Keycloak admin
password for the length of the run. Reading it from the environment stopped
working when credentials left `Config.Env` (#221, #273), and the always-on api
must not hold a credential that can mint identities.

`policy/model.json` is generated from `policy/model.fga` by `make policy-model`
and committed, so the container never needs the OpenFGA CLI.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from openfga_sdk.client.models import ClientTuple
from openfga_sdk.models.create_store_request import CreateStoreRequest
from openfga_sdk.models.write_authorization_model_request import WriteAuthorizationModelRequest
from openfga_sdk.sync import OpenFgaClient

from citadel.env import secret
from citadel.net import open_url
from citadel.policy import PolicyError, load_catalog
from citadel.policy.openfga import configuration, resolve_store_id

MODEL_PATH = Path(os.environ.get("CITADEL_POLICY_MODEL", "/app/policy/model.json"))

# Dev tenants and their members. Usernames are resolved to Keycloak subs.
TENANTS: dict[str, list[str]] = {"lab-a": ["alice", "carol"], "lab-b": ["bob"]}


def _post_form(url: str, fields: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=urllib.parse.urlencode(fields).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    with open_url(req, timeout=20) as r:
        payload: dict[str, Any] = json.loads(r.read())
    return payload


def _admin_get(base: str, path: str, token: str) -> Any:
    req = urllib.request.Request(f"{base}{path}", headers={"Authorization": f"Bearer {token}"})
    with open_url(req, timeout=20) as r:
        return json.loads(r.read())


def admin_token() -> str:
    base = os.environ.get("KEYCLOAK_ADMIN_URL", "http://keycloak:8080")
    realm = os.environ.get("KEYCLOAK_REALM", "citadel")
    out = _post_form(
        f"{base}/realms/master/protocol/openid-connect/token",
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": os.environ["KEYCLOAK_ADMIN_USER"],
            # Mounted as a file and named by KEYCLOAK_ADMIN_PASSWORD_FILE: a
            # password in Config.Env is readable through the socket proxy.
            "password": secret("KEYCLOAK_ADMIN_PASSWORD"),
        },
    )
    del realm
    return str(out["access_token"])


def user_id(username: str, token: str) -> str:
    base = os.environ.get("KEYCLOAK_ADMIN_URL", "http://keycloak:8080")
    realm = os.environ.get("KEYCLOAK_REALM", "citadel")
    users = _admin_get(base, f"/admin/realms/{realm}/users?username={username}&exact=true", token)
    if not users:
        raise PolicyError(f"user {username!r} does not exist; run scripts/bootstrap-identity.py")
    return str(users[0]["id"])


def tuples_for(sub_ids: dict[str, str]) -> list[ClientTuple]:
    tools = load_catalog()
    out: list[ClientTuple] = []
    for tenant, members in TENANTS.items():
        for username in members:
            out.append(
                ClientTuple(
                    user=f"user:{sub_ids[username]}", relation="member", object=f"tenant:{tenant}"
                )
            )
        for agent in sorted({spec.agent for spec in tools.values()}):
            out.append(
                ClientTuple(
                    user=f"tenant:{tenant}", relation="tenant", object=f"agent:{tenant}/{agent}"
                )
            )
        for name, spec in tools.items():
            obj = f"tool:{tenant}/{name}"
            out.append(ClientTuple(user=f"tenant:{tenant}", relation="tenant", object=obj))
            out.append(
                ClientTuple(user=f"agent:{tenant}/{spec.agent}", relation="agent", object=obj)
            )
    return out


def tuple_keys(page: dict[str, Any]) -> set[tuple[str, str, str]]:
    """The (user, relation, object) triples in one `/read` page."""
    return {
        (item["key"]["user"], item["key"]["relation"], item["key"]["object"])
        for item in page.get("tuples", [])
    }


def new_tuples(
    desired: Iterable[ClientTuple], existing: set[tuple[str, str, str]]
) -> list[ClientTuple]:
    """The tuples the store does not hold yet.

    OpenFGA refuses a write that repeats an existing tuple, so an idempotent
    bootstrap has to ask rather than assume (#273).
    """
    return [t for t in desired if (t.user, t.relation, t.object) not in existing]


def existing_tuples(api_url: str, store_id: str) -> set[tuple[str, str, str]]:
    """Every tuple in the store, following the continuation token."""
    found: set[tuple[str, str, str]] = set()
    token = ""
    while True:
        body: dict[str, Any] = {"page_size": 100}
        if token:
            body["continuation_token"] = token
        req = urllib.request.Request(
            f"{api_url}/stores/{store_id}/read",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with open_url(req, timeout=20) as r:
            page: dict[str, Any] = json.loads(r.read())
        found |= tuple_keys(page)
        token = page.get("continuation_token") or ""
        if not token:
            return found


def main() -> int:
    api_url = os.environ.get("OPENFGA_API_URL", "http://openfga:8080")
    store_name = os.environ.get("OPENFGA_STORE_NAME", "citadel")

    model = json.loads(MODEL_PATH.read_text(encoding="utf-8"))

    token = admin_token()
    sub_ids = {u: user_id(u, token) for members in TENANTS.values() for u in members}

    bootstrap = OpenFgaClient(configuration(api_url))
    try:
        resolve_store_id(api_url, store_name)
        print(f"store {store_name!r} already exists")
    except PolicyError:
        bootstrap.create_store(CreateStoreRequest(name=store_name))  # type: ignore[no-untyped-call]
        print(f"created store {store_name!r}")

    store_id = resolve_store_id(api_url, store_name)
    client = OpenFgaClient(configuration(api_url, store_id))

    written = client.write_authorization_model(
        WriteAuthorizationModelRequest(  # type: ignore[no-untyped-call]
            schema_version=model["schema_version"],
            type_definitions=model["type_definitions"],
        )
    )
    print(f"wrote authorization model {written.authorization_model_id}")

    desired = tuples_for(sub_ids)
    missing = new_tuples(desired, existing_tuples(api_url, store_id))
    if missing:
        client.write_tuples(missing)
    print(
        f"wrote {len(missing)} tuples "
        f"({len(desired) - len(missing)} of {len(desired)} already present)"
    )

    print(f"OPENFGA_STORE_ID={store_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
