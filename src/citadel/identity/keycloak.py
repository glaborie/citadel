"""Keycloak access-token verification. Fail closed on anything missing."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import jwt


class IdentityError(Exception):
    """Raised whenever identity cannot be established. Never downgrade to a default."""


class SigningKeySource(Protocol):
    """Seam over PyJWKClient so tests can supply their own keys."""

    def get_signing_key_from_jwt(self, token: str) -> Any: ...


@dataclass(frozen=True)
class Principal:
    user_id: str
    tenant_id: str
    roles: frozenset[str]


class KeycloakVerifier:
    def __init__(self, issuer: str, audience: str, keys: SigningKeySource) -> None:
        self._issuer = issuer
        self._audience = audience
        self._keys = keys

    def verify(self, token: str) -> Principal:
        try:
            key = self._keys.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                key.key,
                algorithms=["RS256"],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "sub", "iss", "aud"]},
            )
        except jwt.PyJWTError as exc:
            raise IdentityError(f"token rejected: {exc}") from exc

        tenant = claims.get("tenant")
        if not isinstance(tenant, str) or not tenant.strip():
            raise IdentityError("token carries no tenant claim")

        roles = claims.get("realm_access") or {}
        names = roles.get("roles") if isinstance(roles, dict) else None
        if not isinstance(names, list):
            names = []

        return Principal(
            user_id=str(claims["sub"]),
            tenant_id=tenant,
            roles=frozenset(str(r) for r in names),
        )
