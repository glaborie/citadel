"""Signed approval tokens for T1 writes.

The API mints one after a human (or a permitted agent) approves, binding the
approval to a specific tenant, run, tool and argument set. The operator service
verifies it before performing the write, so a signal cannot be forged by
anything that cannot sign.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from citadel.hashing import arguments_hash
from citadel.identity import IdentityError

ISSUER = "citadel"
AUDIENCE = "operator"
TOKEN_TYPE = "approval"
ALGORITHM = "EdDSA"
DEFAULT_TTL_SECONDS = 300


@dataclass(frozen=True)
class ApprovalClaims:
    tenant_id: str
    run_id: str
    tool: str
    arguments_hash: str
    approver: str
    jti: str


def mint_approval_token(
    *,
    tenant_id: str,
    run_id: str,
    tool: str,
    arguments: Mapping[str, Any],
    approver: str,
    private_key: Ed25519PrivateKey,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> str:
    if not tenant_id:
        raise IdentityError("cannot mint an approval without a tenant")
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "typ": TOKEN_TYPE,
        "tenant": tenant_id,
        "run_id": run_id,
        "tool": tool,
        "args_hash": arguments_hash(arguments),
        "approver": approver,
        "iat": now,
        "exp": now + ttl_seconds,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, private_key, algorithm=ALGORITHM)


def verify_approval_token(
    token: str,
    *,
    public_key: Ed25519PublicKey,
    tenant_id: str,
    run_id: str,
    tool: str,
    arguments: Mapping[str, Any],
) -> ApprovalClaims:
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
            options={
                "require": [
                    "exp",
                    "iat",
                    "iss",
                    "aud",
                    "typ",
                    "tenant",
                    "run_id",
                    "tool",
                    "args_hash",
                    "approver",
                    "jti",
                ]
            },
        )
    except jwt.PyJWTError as exc:
        raise IdentityError(f"approval rejected: {exc}") from exc

    if claims.get("typ") != TOKEN_TYPE:
        # A run token must never be usable as an approval.
        raise IdentityError("token is not an approval token")
    if claims.get("tenant") != tenant_id:
        raise IdentityError("approval was issued for another tenant")
    if claims.get("run_id") != run_id:
        raise IdentityError("approval was issued for another run")
    if claims.get("tool") != tool:
        raise IdentityError("approval was issued for another tool")
    if claims.get("args_hash") != arguments_hash(arguments):
        raise IdentityError("approval does not match these arguments")

    return ApprovalClaims(
        tenant_id=str(claims["tenant"]),
        run_id=str(claims["run_id"]),
        tool=str(claims["tool"]),
        arguments_hash=str(claims["args_hash"]),
        approver=str(claims["approver"]),
        jti=str(claims["jti"]),
    )
