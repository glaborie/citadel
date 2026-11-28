"""Issue #273: `make policy-bootstrap` reads the admin password from its mount.

The target ran `docker compose exec api` and read `KEYCLOAK_ADMIN_USER` and
`KEYCLOAK_ADMIN_PASSWORD` from the environment. The api stopped carrying them
when credentials left `Config.Env` (#221), so the documented repair for the
policy tuples could not run at all, and every tool added to the catalog after
the last bootstrap stayed denied.
"""

from __future__ import annotations

import pathlib

import pytest
from openfga_sdk.client.models import ClientTuple

from citadel.policy import bootstrap


def _capture_form(monkeypatch: pytest.MonkeyPatch, seen: dict[str, str]) -> None:
    def fake(url: str, fields: dict[str, str]) -> dict[str, object]:
        seen.update(fields)
        return {"access_token": "token-from-keycloak"}

    monkeypatch.setattr(bootstrap, "_post_form", fake)


def test_admin_token_sends_the_password_from_the_mounted_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    password_file = tmp_path / "keycloak_admin_password"
    password_file.write_text("mounted-admin-password\n", encoding="ascii")
    monkeypatch.setenv("KEYCLOAK_ADMIN_USER", "admin")
    monkeypatch.setenv("KEYCLOAK_ADMIN_PASSWORD_FILE", str(password_file))
    monkeypatch.delenv("KEYCLOAK_ADMIN_PASSWORD", raising=False)
    seen: dict[str, str] = {}
    _capture_form(monkeypatch, seen)

    assert bootstrap.admin_token() == "token-from-keycloak"
    assert seen["username"] == "admin"
    assert seen["password"] == "mounted-admin-password", (
        "the file is the source; a stale environment fallback must not win"
    )


def test_admin_token_refuses_to_invent_a_password(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("KEYCLOAK_ADMIN_USER", "admin")
    monkeypatch.delenv("KEYCLOAK_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("KEYCLOAK_ADMIN_PASSWORD_FILE", raising=False)

    with pytest.raises(KeyError):
        bootstrap.admin_token()


def test_only_the_missing_tuples_are_written() -> None:
    """OpenFGA answers 400 to a write that repeats a tuple, so the documented
    idempotent repair failed after one successful run (#273)."""
    page = {
        "tuples": [
            {
                "key": {
                    "user": "agent:lab-a/docker",
                    "relation": "agent",
                    "object": "tool:lab-a/inspect_containers",
                },
                "timestamp": "2026-11-28T10:00:00Z",
            }
        ],
        "continuation_token": "",
    }
    existing = bootstrap.tuple_keys(page)
    assert existing == {("agent:lab-a/docker", "agent", "tool:lab-a/inspect_containers")}

    desired = [
        ClientTuple(user="agent:lab-a/docker", relation="agent", object=name)
        for name in ("tool:lab-a/inspect_containers", "tool:lab-a/compose_config")
    ]
    missing = bootstrap.new_tuples(desired, existing)
    assert [t.object for t in missing] == ["tool:lab-a/compose_config"]

    already_there = existing | {("agent:lab-a/docker", "agent", "tool:lab-a/compose_config")}
    assert bootstrap.new_tuples(desired, already_there) == []
