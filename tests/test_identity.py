"""Identity boundary: allow, deny and red-team cases for both token types."""

from __future__ import annotations

import time
from typing import Any

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from citadel.identity import (
    IdentityError,
    KeycloakVerifier,
    Principal,
    mint_run_token,
    verify_run_token,
)
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token


def verifier(key: rsa.RSAPrivateKey) -> KeycloakVerifier:
    return KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(key.public_key()))


# --- Keycloak user tokens -------------------------------------------------


def test_valid_token_yields_principal(rsa_key: rsa.RSAPrivateKey) -> None:
    principal = verifier(rsa_key).verify(user_token(rsa_key, roles=["operator", "approver"]))
    assert principal == Principal("user-alice", "lab-a", frozenset({"operator", "approver"}))


@pytest.mark.parametrize("tenant", [None, "", "   "])
def test_missing_tenant_is_denied(rsa_key: rsa.RSAPrivateKey, tenant: str | None) -> None:
    with pytest.raises(IdentityError, match="tenant"):
        verifier(rsa_key).verify(user_token(rsa_key, tenant=tenant))


def test_expired_token_is_denied(rsa_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(IdentityError):
        verifier(rsa_key).verify(user_token(rsa_key, ttl=-10))


def test_wrong_issuer_is_denied(rsa_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(IdentityError):
        verifier(rsa_key).verify(user_token(rsa_key, issuer="http://evil.test/realms/citadel"))


def test_wrong_audience_is_denied(rsa_key: rsa.RSAPrivateKey) -> None:
    with pytest.raises(IdentityError):
        verifier(rsa_key).verify(user_token(rsa_key, audience="some-other-client"))


def test_forged_signature_is_denied(rsa_key: rsa.RSAPrivateKey) -> None:
    """Red team: a token signed by an attacker key must never be accepted."""
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(IdentityError):
        verifier(rsa_key).verify(user_token(attacker, tenant="lab-b"))


def test_unreachable_key_source_fails_closed(rsa_key: rsa.RSAPrivateKey) -> None:
    class Broken:
        def get_signing_key_from_jwt(self, token: str) -> Any:
            raise jwt.PyJWKClientError("keycloak unreachable")

    with pytest.raises(IdentityError):
        KeycloakVerifier(ISSUER, AUDIENCE, Broken()).verify(user_token(rsa_key))


# --- Citadel run tokens ---------------------------------------------------


def test_run_token_roundtrip(
    run_private_key: Ed25519PrivateKey, run_public_key: Ed25519PublicKey
) -> None:
    principal = Principal("user-alice", "lab-a", frozenset({"operator"}))
    token, context = mint_run_token(
        principal,
        agent_id="docker",
        scopes=frozenset({"read_logs"}),
        risk_tier="T0",
        private_key=run_private_key,
    )
    assert verify_run_token(token, run_public_key) == context
    assert context.tenant_id == "lab-a"


def test_run_token_cannot_be_minted_without_a_tenant(
    run_private_key: Ed25519PrivateKey,
) -> None:
    with pytest.raises(IdentityError):
        mint_run_token(
            Principal("user-alice", "", frozenset()),
            agent_id="docker",
            scopes=frozenset(),
            risk_tier="T0",
            private_key=run_private_key,
        )


def test_expired_run_token_is_denied(
    run_private_key: Ed25519PrivateKey, run_public_key: Ed25519PublicKey
) -> None:
    token, _ = mint_run_token(
        Principal("user-alice", "lab-a", frozenset()),
        agent_id="docker",
        scopes=frozenset(),
        risk_tier="T0",
        private_key=run_private_key,
        ttl_seconds=-10,
    )
    with pytest.raises(IdentityError):
        verify_run_token(token, run_public_key)


def test_forged_run_token_is_denied(run_public_key: Ed25519PublicKey) -> None:
    """Red team: a run token signed by another key must be rejected."""
    attacker = Ed25519PrivateKey.generate()
    token, _ = mint_run_token(
        Principal("user-alice", "lab-b", frozenset()),
        agent_id="docker",
        scopes=frozenset(),
        risk_tier="T1",
        private_key=attacker,
    )
    with pytest.raises(IdentityError):
        verify_run_token(token, run_public_key)


def test_worker_holding_only_the_public_key_cannot_mint(
    run_public_key: Ed25519PublicKey,
) -> None:
    """The delegation is asymmetric: verifiers cannot issue run tokens."""
    now = int(time.time())
    with pytest.raises((AttributeError, TypeError, ValueError)):
        jwt.encode(
            {
                "iss": "citadel",
                "sub": "user-alice",
                "tenant": "lab-b",
                "run_id": "r1",
                "agent": "docker",
                "risk_tier": "T1",
                "iat": now,
                "exp": now + 300,
            },
            run_public_key,  # type: ignore[arg-type]
            algorithm="EdDSA",
        )


def test_run_token_missing_claim_is_denied(
    run_private_key: Ed25519PrivateKey, run_public_key: Ed25519PublicKey
) -> None:
    now = int(time.time())
    token = jwt.encode(
        {"iss": "citadel", "sub": "u", "iat": now, "exp": now + 300},
        run_private_key,
        algorithm="EdDSA",
    )
    with pytest.raises(IdentityError):
        verify_run_token(token, run_public_key)
