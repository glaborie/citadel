"""Identity: verify Keycloak user tokens and mint Citadel run tokens.

Keycloak owns user identity. Citadel owns the per-run delegation, because
RFC 8693 exchange cannot carry run_id, agent, scopes or risk tier. See
docs/implementation-notes/v0.1-verification.md, item 4.
"""

from citadel.identity.keycloak import IdentityError, KeycloakVerifier, Principal
from citadel.identity.run_token import RunContext, mint_run_token, verify_run_token

__all__ = [
    "IdentityError",
    "KeycloakVerifier",
    "Principal",
    "RunContext",
    "mint_run_token",
    "verify_run_token",
]
