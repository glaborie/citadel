"""The API schema is served only when the environment opts in (#220).

/docs, /redoc and /openapi.json are answered before any authentication runs,
so the default configuration is the deny test and the flag is the allow test.
A future edit to the FastAPI(...) call cannot silently restore the defaults
without failing these.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token

SCHEMA_PATHS = ["/docs", "/redoc", "/openapi.json"]


def _client(rsa_key: rsa.RSAPrivateKey) -> TestClient:
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    # No DSN: any request that reaches the database would raise, so a 2xx here
    # would mean an unauthenticated request got past the gate.
    return TestClient(create_app(verifier=verifier))


@pytest.mark.parametrize("path", SCHEMA_PATHS)
def test_schema_is_404_by_default(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.delenv("CITADEL_EXPOSE_API_DOCS", raising=False)
    assert _client(rsa_key).get(path).status_code == 404


@pytest.mark.parametrize("value", ["", "false", "0", "off", "junk", "  "])
def test_schema_stays_404_for_non_truthy_values(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("CITADEL_EXPOSE_API_DOCS", value)
    assert _client(rsa_key).get("/openapi.json").status_code == 404


@pytest.mark.parametrize("value", ["1", "true", "True", "YES", " on "])
def test_opt_in_serves_docs_and_schema_but_never_redoc(
    rsa_key: rsa.RSAPrivateKey,
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    monkeypatch.setenv("CITADEL_EXPOSE_API_DOCS", value)
    client = _client(rsa_key)
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/openapi.json").json()["info"]["title"] == "Citadel API"
    assert client.get("/redoc").status_code == 404


def test_gate_does_not_change_other_route_behaviour(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("CITADEL_EXPOSE_API_DOCS", raising=False)
    client = _client(rsa_key)
    # The control: the app itself is fine, only the schema paths are gone.
    assert client.get("/healthz").status_code == 200
    # And the protected route still refuses without a token.
    assert client.get("/runs").status_code == 401


def test_opt_in_does_not_open_protected_routes(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CITADEL_EXPOSE_API_DOCS", "true")
    client = _client(rsa_key)
    assert client.get("/runs").status_code == 401


def test_opt_in_still_requires_a_verified_token_for_runs(
    rsa_key: rsa.RSAPrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CITADEL_EXPOSE_API_DOCS", "true")
    token = user_token(rsa_key, tenant=None)
    response = _client(rsa_key).get("/runs", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 401
