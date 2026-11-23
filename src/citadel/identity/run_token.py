"""Citadel run tokens: the delegated per-run identity every component requires.

Signed with Ed25519 so the API can mint while workers can only verify. A
worker holding the public key cannot forge a run token for another tenant.
"""

from __future__ import annotations

import base64
import time
import uuid
from dataclasses import dataclass

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_der_private_key,
    load_der_public_key,
)

from citadel.identity.keycloak import IdentityError, Principal

ISSUER = "citadel"
ALGORITHM = "EdDSA"
DEFAULT_TTL_SECONDS = 300


@dataclass(frozen=True)
class RunContext:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    scopes: frozenset[str]
    risk_tier: str


def private_key_from_env(value: str) -> Ed25519PrivateKey:
    key = load_der_private_key(base64.b64decode(value), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise IdentityError("run token signing key must be Ed25519")
    return key


def public_key_from_env(value: str) -> Ed25519PublicKey:
    key = load_der_public_key(base64.b64decode(value))
    if not isinstance(key, Ed25519PublicKey):
        raise IdentityError("run token verification key must be Ed25519")
    return key


def mint_run_token(
    principal: Principal,
    *,
    agent_id: str,
    scopes: frozenset[str],
    risk_tier: str,
    private_key: Ed25519PrivateKey,
    run_id: str | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[str, RunContext]:
    if not principal.tenant_id:
        raise IdentityError("cannot mint a run token without a tenant")
    now = int(time.time())
    context = RunContext(
        run_id=run_id or str(uuid.uuid4()),
        tenant_id=principal.tenant_id,
        user_id=principal.user_id,
        agent_id=agent_id,
        scopes=scopes,
        risk_tier=risk_tier,
    )
    claims = {
        "iss": ISSUER,
        "sub": principal.user_id,
        "tenant": principal.tenant_id,
        "run_id": context.run_id,
        "agent": agent_id,
        "scopes": sorted(scopes),
        "risk_tier": risk_tier,
        "roles": sorted(principal.roles),
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, private_key, algorithm=ALGORITHM), context


def verify_run_token(token: str, public_key: Ed25519PublicKey) -> RunContext:
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            options={
                "require": ["exp", "iat", "sub", "iss", "tenant", "run_id", "agent", "risk_tier"],
                "verify_aud": False,
            },
        )
    except jwt.PyJWTError as exc:
        raise IdentityError(f"run token rejected: {exc}") from exc

    tenant = claims["tenant"]
    if not isinstance(tenant, str) or not tenant.strip():
        raise IdentityError("run token carries no tenant")

    scopes = claims.get("scopes") or []
    if not isinstance(scopes, list):
        raise IdentityError("run token scopes are malformed")

    return RunContext(
        run_id=str(claims["run_id"]),
        tenant_id=tenant,
        user_id=str(claims["sub"]),
        agent_id=str(claims["agent"]),
        scopes=frozenset(str(s) for s in scopes),
        risk_tier=str(claims["risk_tier"]),
    )
