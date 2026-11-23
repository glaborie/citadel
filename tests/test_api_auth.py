"""API authentication boundary. These paths must reject before touching the database."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token


@pytest.fixture
def client(rsa_key: rsa.RSAPrivateKey) -> TestClient:
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    # No DSN: any request that reaches the database would raise, so a 2xx here
    # would mean an unauthenticated request got through.
    return TestClient(create_app(verifier=verifier))


def test_healthz_needs_no_token(client: TestClient) -> None:
    assert client.get("/healthz").status_code == 200


@pytest.mark.parametrize("path", ["/runs"])
def test_missing_token_is_rejected(client: TestClient, path: str) -> None:
    assert client.get(path).status_code == 401


def test_malformed_authorization_is_rejected(client: TestClient) -> None:
    assert client.get("/runs", headers={"Authorization": "Basic abc"}).status_code == 401


def test_token_without_tenant_is_rejected(client: TestClient, rsa_key: rsa.RSAPrivateKey) -> None:
    token = user_token(rsa_key, tenant=None)
    response = client.get("/runs", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
    assert "tenant" in response.json()["detail"]


def test_expired_token_is_rejected(client: TestClient, rsa_key: rsa.RSAPrivateKey) -> None:
    token = user_token(rsa_key, ttl=-10)
    assert client.get("/runs", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_forged_token_is_rejected(client: TestClient) -> None:
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = user_token(attacker, tenant="lab-b")
    assert client.get("/runs", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_body_cannot_smuggle_a_tenant(client: TestClient, rsa_key: rsa.RSAPrivateKey) -> None:
    """Red team: tenant_id in the payload is rejected, not honoured."""
    token = user_token(rsa_key, tenant="lab-a")
    response = client.post(
        "/runs",
        json={"agent_id": "docker", "tenant_id": "lab-b"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
