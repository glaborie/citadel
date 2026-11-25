"""Run creation records the provenance a trajectory needs."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from citadel.api import app as api_app
from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token


class FakeConn:
    def __init__(self, statements: list[str]) -> None:
        self._statements = statements

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        self._statements.append(" ".join(sql.split()))


class FakeLedger:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> SimpleNamespace:
        self.events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(self.events)}")


@pytest.fixture
def client(
    monkeypatch: pytest.MonkeyPatch, rsa_key: rsa.RSAPrivateKey
) -> tuple[TestClient, FakeLedger]:
    ledger = FakeLedger()
    statements: list[str] = []

    @contextmanager
    def connect(_dsn: str, _tenant: str) -> Iterator[FakeConn]:
        yield FakeConn(statements)

    monkeypatch.setattr(api_app, "tenant_connection", connect)
    monkeypatch.setattr(api_app, "AuditLedger", lambda _dsn: ledger)
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    return (
        TestClient(
            create_app(verifier=verifier, dsn="unused", private_key=Ed25519PrivateKey.generate())
        ),
        ledger,
    )


def _body() -> dict[str, Any]:
    return {
        "agent_id": "docker",
        "risk_tier": "T0",
        "prompt_pack_version": "docker-1.0.0",
        "model_alias": "auto/best-fast",
    }


def test_run_start_records_pinned_provenance(
    client: tuple[TestClient, FakeLedger], rsa_key: rsa.RSAPrivateKey
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")

    response = http.post("/runs", json=_body(), headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 201, response.text
    assert len(ledger.events) == 1
    event = ledger.events[0]
    assert event["event_type"] == "run.start"
    assert event["payload"]["prompt_pack_version"] == "docker-1.0.0"
    assert event["payload"]["model_alias"] == "auto/best-fast"
    assert event["payload"]["run_id"] == response.json()["run_id"]


def test_unpinned_provenance_is_rejected(
    client: tuple[TestClient, FakeLedger], rsa_key: rsa.RSAPrivateKey
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")
    body = _body()
    del body["model_alias"]

    response = http.post("/runs", json=body, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 422
    assert ledger.events == []
