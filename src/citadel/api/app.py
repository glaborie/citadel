"""Citadel API: authenticated ingress, tenant extraction and run creation.

Every route except /healthz requires a verified Keycloak token carrying a
tenant claim. Missing tenant, missing token or an unreachable identity
provider all fail closed.
"""

# No `from __future__ import annotations`: FastAPI must see the real Depends
# objects, and the dependency is a closure over create_app's arguments.
import os
import uuid
from typing import Annotated, Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__
from citadel.db import tenant_connection
from citadel.identity import IdentityError, KeycloakVerifier, Principal, mint_run_token
from citadel.identity.run_token import private_key_from_env
from citadel.policy import AuthorizationRequest, RelationChecker, authorize
from citadel.policy.openfga import build_checker


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    tool: str
    run_id: str


class RunRequest(BaseModel):
    # A client must not be able to smuggle a tenant or user into the body.
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    scopes: list[str] = []
    risk_tier: str = "T0"


def _verifier_from_env() -> KeycloakVerifier:
    try:
        issuer = os.environ["KEYCLOAK_ISSUER"]
    except KeyError as exc:
        # Unconfigured identity is a denial, never an anonymous pass-through.
        raise IdentityError("identity provider is not configured") from exc
    audience = os.environ.get("KEYCLOAK_AUDIENCE", "citadel-agent")
    # Issuer and JWKS URL differ: the issuer is the public hostname users see,
    # while the API reaches Keycloak over the internal network.
    jwks_url = os.environ.get("KEYCLOAK_JWKS_URL", f"{issuer}/protocol/openid-connect/certs")
    keys = jwt.PyJWKClient(jwks_url, cache_keys=True)
    return KeycloakVerifier(issuer=issuer, audience=audience, keys=keys)


def create_app(
    *,
    verifier: KeycloakVerifier | None = None,
    dsn: str | None = None,
    private_key: Ed25519PrivateKey | None = None,
    checker: RelationChecker | None = None,
) -> FastAPI:
    app = FastAPI(title="Citadel API", version=__version__)

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    def current_principal(
        authorization: Annotated[str | None, Header()] = None,
    ) -> Principal:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        active = verifier if verifier is not None else _verifier_from_env()
        try:
            return active.verify(authorization.removeprefix("Bearer ").strip())
        except IdentityError as exc:
            # Never fall back to a default tenant or an anonymous principal.
            raise HTTPException(status_code=401, detail=str(exc)) from exc

    def _checker() -> RelationChecker:
        if checker is not None:
            return checker
        return build_checker(
            os.environ.get("OPENFGA_API_URL", "http://openfga:8080"),
            os.environ.get("OPENFGA_STORE_NAME", "citadel"),
        )

    def _dsn() -> str:
        return dsn if dsn is not None else os.environ["CITADEL_DB_DSN"]

    def _key() -> Ed25519PrivateKey:
        if private_key is not None:
            return private_key
        return private_key_from_env(os.environ["CITADEL_RUN_TOKEN_PRIVATE_KEY"])

    @app.post("/runs", status_code=201)
    def create_run(
        body: RunRequest, principal: Annotated[Principal, Depends(current_principal)]
    ) -> dict[str, Any]:
        run_id = str(uuid.uuid4())
        token, context = mint_run_token(
            principal,
            agent_id=body.agent_id,
            scopes=frozenset(body.scopes),
            risk_tier=body.risk_tier,
            private_key=_key(),
            run_id=run_id,
        )
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            conn.execute(
                "INSERT INTO runs (id, tenant_id, user_id, agent_id, risk_tier)"
                " VALUES (%s, %s, %s, %s, %s)",
                (run_id, principal.tenant_id, principal.user_id, body.agent_id, body.risk_tier),
            )
        return {"run_id": context.run_id, "tenant_id": context.tenant_id, "run_token": token}

    @app.get("/runs")
    def list_runs(
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> dict[str, Any]:
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            rows = conn.execute(
                "SELECT id, tenant_id, agent_id, status FROM runs ORDER BY created_at"
            ).fetchall()
        return {
            "tenant_id": principal.tenant_id,
            "runs": [
                {"id": str(r[0]), "tenant_id": r[1], "agent_id": r[2], "status": r[3]} for r in rows
            ],
        }

    @app.post("/policy/authorize")
    def policy_authorize(
        body: AuthorizeRequest, principal: Annotated[Principal, Depends(current_principal)]
    ) -> dict[str, Any]:
        # The run must exist inside the caller's tenant. RLS does the filtering,
        # so another tenant's run_id is simply not found and the call is denied.
        try:
            with tenant_connection(_dsn(), principal.tenant_id) as conn:
                known = conn.execute("SELECT 1 FROM runs WHERE id = %s", (body.run_id,)).fetchone()
        except Exception:  # noqa: BLE001 - a broken lookup must not authorise
            known = None
        if known is None:
            return {
                "outcome": "deny",
                "rule_id": "identity.unknown_run",
                "reason": "run does not exist in this tenant",
                "tier": "unknown",
                "audit": {
                    "tenant_id": principal.tenant_id,
                    "user_id": principal.user_id,
                    "run_id": body.run_id,
                    "agent_id": body.agent_id,
                    "tool": body.tool,
                },
            }

        decision = authorize(
            AuthorizationRequest(
                user_id=principal.user_id,
                tenant_id=principal.tenant_id,
                run_id=body.run_id,
                agent_id=body.agent_id,
                tool=body.tool,
            ),
            _checker(),
        )
        return {
            "outcome": decision.outcome,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "tier": decision.tier,
            "audit": {
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "run_id": body.run_id,
                "agent_id": body.agent_id,
                "tool": body.tool,
            },
        }

    return app
