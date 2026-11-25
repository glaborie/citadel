"""Approval tokens: signed, scoped and not interchangeable with run tokens."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from citadel.approvals import mint_approval_token, verify_approval_token
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError, Principal, mint_run_token


@pytest.fixture(scope="module")
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture(scope="module")
def pub(key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return key.public_key()


def token(key: Ed25519PrivateKey, **overrides: object) -> str:
    base: dict[str, object] = {
        "tenant_id": "lab-a",
        "run_id": "run-1",
        "tool": "restart_service",
        "arguments": {"service": "checkout-api"},
        "approver": "user-carol",
    }
    base.update(overrides)
    return mint_approval_token(**base, private_key=key)  # type: ignore[arg-type]


def verify(pub: Ed25519PublicKey, value: str) -> object:
    return verify_approval_token(
        value,
        public_key=pub,
        tenant_id="lab-a",
        run_id="run-1",
        tool="restart_service",
        arguments={"service": "checkout-api"},
    )


def test_valid_approval_is_accepted(key: Ed25519PrivateKey, pub: Ed25519PublicKey) -> None:
    claims = verify_approval_token(
        token(key),
        public_key=pub,
        tenant_id="lab-a",
        run_id="run-1",
        tool="restart_service",
        arguments={"service": "checkout-api"},
    )
    assert claims.approver == "user-carol"
    assert claims.jti


def test_arguments_hash_is_order_independent() -> None:
    assert arguments_hash({"a": 1, "b": 2}) == arguments_hash({"b": 2, "a": 1})


@pytest.mark.parametrize(
    ("kwargs", "match"),
    [
        ({"tenant_id": "lab-b"}, "another tenant"),
        ({"run_id": "run-2"}, "another run"),
        ({"tool": "open_remediation_pr"}, "another tool"),
        ({"arguments": {"service": "database"}}, "does not match these arguments"),
    ],
)
def test_scope_mismatches_are_rejected(
    key: Ed25519PrivateKey, pub: Ed25519PublicKey, kwargs: dict[str, object], match: str
) -> None:
    """An approval for one action must not authorise another."""
    with pytest.raises(IdentityError, match=match):
        verify(pub, token(key, **kwargs))


def test_forged_approval_is_rejected(pub: Ed25519PublicKey) -> None:
    attacker = Ed25519PrivateKey.generate()
    with pytest.raises(IdentityError):
        verify(pub, token(attacker))


def test_expired_approval_is_rejected(key: Ed25519PrivateKey, pub: Ed25519PublicKey) -> None:
    with pytest.raises(IdentityError):
        verify(pub, token(key, ttl_seconds=-5))


def test_run_token_cannot_be_used_as_an_approval(
    key: Ed25519PrivateKey, pub: Ed25519PublicKey
) -> None:
    """Red team: a delegated run token replayed as an approval."""
    run_token, _ = mint_run_token(
        Principal("user-alice", "lab-a", frozenset()),
        agent_id="docker",
        scopes=frozenset(),
        risk_tier="T1",
        private_key=key,
    )
    with pytest.raises(IdentityError):
        verify(pub, run_token)


def test_mint_requires_a_tenant(key: Ed25519PrivateKey) -> None:
    with pytest.raises(IdentityError):
        token(key, tenant_id="")
