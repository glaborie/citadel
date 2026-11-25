"""The approval route checks arguments before it signs or audits them."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from citadel import dlp
from citadel.api import app as api_module
from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token
from tests.redteam.support import FakeDB

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture
def env(
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    analyzer: dict[str, list[dict[str, Any]]],
) -> tuple[TestClient, list[dict[str, Any]], str]:
    db = FakeDB()
    events: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(events)}")

    monkeypatch.setattr(api_module, "tenant_connection", db.connect)
    monkeypatch.setattr(api_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    client = TestClient(
        create_app(
            verifier=verifier, dsn="postgres://fake", private_key=Ed25519PrivateKey.generate()
        )
    )
    return client, events, user_token(rsa_key, roles=["approver"], sub="carol")


def _post(client: TestClient, token: str, arguments: dict[str, Any]) -> Any:
    return client.post(
        "/approvals",
        json={
            "run_id": "run-1",
            "tool": "restart_service",
            "agent_id": "docker",
            "arguments": arguments,
            "approved": True,
            "reason": "looks fine",
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def test_clean_arguments_are_approved_and_audited(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    client, events, token = env
    # The approval signal needs a live Temporal; the route logic under test does not.
    with mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()):
        response = _post(client, token, {"service": "checkout-api"})
    assert response.status_code == 200
    assert [event["event_type"] for event in events] == ["approval.decision"]


def test_secret_in_arguments_is_refused_before_mint(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    client, events, token = env
    response = _post(client, token, {"service": "checkout-api", "note": SECRET})
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    # No token was minted and nothing was written for a human to read.
    assert events == []


def test_unreachable_detector_refuses_rather_than_passing(
    monkeypatch: pytest.MonkeyPatch, env: tuple[TestClient, list[dict[str, Any]], str]
) -> None:
    client, events, token = env

    def down(_request: Any, timeout: Any = None) -> Any:
        raise OSError("detector down")

    monkeypatch.setattr(dlp, "urlopen", down)
    response = _post(client, token, {"service": "checkout-api"})
    assert response.status_code == 503
    assert response.json()["detail"]["reason"] == "dlp_unavailable"
    assert events == []
