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


def test_a_pack_version_the_deployment_does_not_have_is_rejected(
    client: tuple[TestClient, FakeLedger], rsa_key: rsa.RSAPrivateKey
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")
    body = _body()
    body["prompt_pack_version"] = "docker-9.9.9"

    response = http.post("/runs", json=body, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert "docker-1.0.0" in response.json()["detail"]
    assert ledger.events == []


def test_an_agent_without_a_skill_pack_cannot_start_a_run(
    client: tuple[TestClient, FakeLedger], rsa_key: rsa.RSAPrivateKey
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")
    body = _body()
    body["agent_id"] = "nobody"

    response = http.post("/runs", json=body, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 400
    assert "no skill pack" in response.json()["detail"]
    assert ledger.events == []


def test_a_task_submits_the_workflow_and_keeps_the_text_out_of_the_ledger(
    client: tuple[TestClient, FakeLedger],
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")
    submitted: list[Any] = []

    async def fake_start(item: Any) -> None:
        submitted.append(item)

    monkeypatch.setattr(api_app, "start_run", fake_start)
    body = _body() | {"task": "which containers are running?"}

    response = http.post("/runs", json=body, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 201, response.text
    assert len(submitted) == 1
    assert submitted[0].task == "which containers are running?"
    assert submitted[0].agent_id == "docker"
    assert submitted[0].prompt_pack_version == "docker-1.0.0"
    assert submitted[0].run_id == response.json()["run_id"]
    payload = ledger.events[0]["payload"]
    assert payload["task_chars"] == len("which containers are running?")
    assert len(payload["task_sha256"]) == 64
    assert "which containers" not in str(payload)


def test_a_workflow_that_does_not_start_is_not_reported_as_started(
    client: tuple[TestClient, FakeLedger],
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, ledger = client
    token = user_token(rsa_key, tenant="lab-a")

    async def failing_start(item: Any) -> None:
        raise RuntimeError("temporal is down")

    monkeypatch.setattr(api_app, "start_run", failing_start)
    body = _body() | {"task": "which containers are running?"}

    response = http.post("/runs", json=body, headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 503
    assert "was recorded but its workflow did not start" in response.json()["detail"]
    assert [event["event_type"] for event in ledger.events] == ["run.start", "run.end"]
    assert ledger.events[1]["payload"]["safety_flags"] == ["workflow_not_started"]


def test_a_run_without_a_task_is_recorded_only(
    client: tuple[TestClient, FakeLedger],
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    http, _ledger = client
    token = user_token(rsa_key, tenant="lab-a")

    async def unexpected(item: Any) -> None:
        raise AssertionError("a run without a task must not submit a workflow")

    monkeypatch.setattr(api_app, "start_run", unexpected)

    response = http.post("/runs", json=_body(), headers={"Authorization": f"Bearer {token}"})

    assert response.status_code == 201, response.text


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
