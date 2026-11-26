"""The read-back route: tenant-scoped, audited, and honest about absence."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from citadel import tool_outputs
from citadel.api import app as api_module
from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token

RUN = "33333333-3333-3333-3333-333333333333"
DIGEST = "a" * 64
BODY = "HEAD\n" + ("x" * 9000) + "\nEND\n"


class Cursor:
    def __init__(self, row: tuple[Any, ...] | None) -> None:
        self._row = row

    def fetchone(self) -> tuple[Any, ...] | None:
        return self._row


class Conn:
    def __init__(self, known_run: bool) -> None:
        self.known_run = known_run

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Cursor:
        statement = " ".join(sql.split())
        if statement.startswith("SELECT 1 FROM runs"):
            return Cursor((1,) if self.known_run else None)
        if statement.startswith("SELECT body FROM tool_outputs"):
            return Cursor(None)
        raise AssertionError(f"unexpected SQL: {statement}")


@pytest.fixture
def env(
    monkeypatch: pytest.MonkeyPatch, rsa_key: rsa.RSAPrivateKey
) -> tuple[TestClient, list[dict[str, Any]], Any]:
    events: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(events)}")

    def connect(_dsn: str, tenant_id: str) -> Any:
        from contextlib import contextmanager

        @contextmanager
        def _cm() -> Any:
            yield Conn(known_run=tenant_id == "lab-a")

        return _cm()

    monkeypatch.setattr(api_module, "tenant_connection", connect)
    monkeypatch.setattr(api_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    client = TestClient(
        create_app(
            verifier=verifier, dsn="postgres://fake", private_key=Ed25519PrivateKey.generate()
        )
    )
    return client, events, rsa_key


def _get(client: TestClient, token: str, run_id: str = RUN, digest: str = DIGEST) -> Any:
    return client.get(
        f"/runs/{run_id}/outputs/{digest}", headers={"Authorization": f"Bearer {token}"}
    )


def test_a_stored_stream_is_returned_with_the_audit_event(
    env: tuple[TestClient, list[dict[str, Any]], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, events, key = env
    monkeypatch.setattr(tool_outputs, "fetch", lambda _conn, digest: BODY)

    response = _get(client, user_token(key, roles=["approver"], sub="alice"))

    assert response.status_code == 200
    assert response.json()["output"] == BODY
    assert response.json()["digest"] == DIGEST
    assert response.json()["bytes"] == len(BODY.encode("utf-8"))
    assert events[-1]["event_type"] == "tool.output.read"
    assert events[-1]["payload"]["digest"] == DIGEST


def test_a_digest_with_nothing_behind_it_is_404(
    env: tuple[TestClient, list[dict[str, Any]], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The record can carry a digest the store refused to keep; say so."""
    client, events, key = env
    monkeypatch.setattr(tool_outputs, "fetch", lambda _conn, digest: None)

    response = _get(client, user_token(key, roles=["approver"], sub="alice"))

    assert response.status_code == 404
    assert "no stored output" in response.json()["detail"]
    assert events == [], "a miss is not evidence of a read"


def test_a_run_outside_the_tenant_is_404_before_the_store_is_consulted(
    env: tuple[TestClient, list[dict[str, Any]], Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _events, key = env
    consulted: list[str] = []

    def fetch(_conn: Any, digest: str) -> str:
        consulted.append(digest)
        return BODY

    monkeypatch.setattr(tool_outputs, "fetch", fetch)

    response = _get(client, user_token(key, tenant="lab-b", roles=["approver"], sub="bob"))

    assert response.status_code == 404
    assert consulted == [], "the store must not be queried for a run this tenant cannot see"


def test_the_route_requires_a_token(env: tuple[TestClient, list[dict[str, Any]], Any]) -> None:
    client, _events, _key = env

    assert client.get(f"/runs/{RUN}/outputs/{DIGEST}").status_code == 401
