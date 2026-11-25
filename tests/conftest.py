"""Shared fixtures: a local RSA identity key and an Ed25519 run-token keypair."""

from __future__ import annotations

import json
import time
from types import SimpleNamespace
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from citadel import dlp

ISSUER = "http://keycloak.test/realms/citadel"
AUDIENCE = "citadel-agent"


class StaticKeys:
    """Stands in for PyJWKClient so tests never need a live Keycloak."""

    def __init__(self, key: Any) -> None:
        self._key = key

    def get_signing_key_from_jwt(self, token: str) -> Any:
        return SimpleNamespace(key=self._key)


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def run_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="session")
def run_public_key(run_private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return run_private_key.public_key()


class AnalyzerResponse:
    def __init__(self, entities: list[dict[str, Any]]) -> None:
        self._body = json.dumps(entities).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> AnalyzerResponse:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


@pytest.fixture
def analyzer(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[dict[str, Any]]]:
    """A stand-in Presidio, keyed by the text it is asked about."""
    entities: dict[str, list[dict[str, Any]]] = {}

    def fake(request: Any, timeout: Any = None) -> AnalyzerResponse:
        return AnalyzerResponse(entities.get(json.loads(request.data)["text"], []))

    monkeypatch.setattr(dlp, "urlopen", fake)
    return entities


def user_token(
    key: rsa.RSAPrivateKey,
    *,
    tenant: str | None = "lab-a",
    sub: str = "user-alice",
    roles: list[str] | None = None,
    issuer: str = ISSUER,
    audience: str = AUDIENCE,
    ttl: int = 300,
) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "sub": sub,
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + ttl,
        "realm_access": {"roles": roles if roles is not None else ["operator"]},
    }
    if tenant is not None:
        claims["tenant"] = tenant
    return jwt.encode(claims, key, algorithm="RS256")
