"""Citadel API: authenticated ingress, tenant extraction and run creation.

Every route except /healthz requires a verified Keycloak token carrying a
tenant claim. Missing tenant, missing token or an unreachable identity
provider all fail closed.
"""

# No `from __future__ import annotations`: FastAPI must see the real Depends
# objects, and the dependency is a closure over create_app's arguments.
import asyncio
import json
import os
import uuid
from typing import Annotated, Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from citadel import __version__, dlp, telemetry
from citadel.approval_requests import close_request
from citadel.approvals import mint_approval_token
from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.identity import IdentityError, KeycloakVerifier, Principal, mint_run_token
from citadel.identity.run_token import private_key_from_env
from citadel.policy import AuthorizationRequest, RelationChecker, authorize
from citadel.policy.openfga import build_checker
from citadel.runs import PostgresRunStore
from citadel.workflows.orchestrator import child_workflow_id
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import APPROVAL_TTL, ApprovalDecision

DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")


class AuthorizeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent_id: str
    tool: str
    run_id: str


class ApprovalRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    tool: str
    agent_id: str
    arguments: dict[str, Any] = {}
    approved: bool
    reason: str


class RunRequest(BaseModel):
    # A client must not be able to smuggle a tenant or user into the body.
    model_config = ConfigDict(extra="forbid")

    agent_id: str = Field(min_length=1)
    scopes: list[str] = []
    risk_tier: str = "T0"
    # Provenance the trajectory needs; an unspecified pack or alias is not
    # reproducible, so the caller has to name them.
    prompt_pack_version: str = Field(min_length=1)
    model_alias: str = Field(min_length=1)


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
    telemetry.configure("citadel-api")

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
        # Written after the row exists, so a recorded trajectory always names a
        # real run. If this fails the request fails and no run is claimed.
        ref = AuditLedger(_dsn()).append(
            tenant_id=principal.tenant_id,
            event_type="run.start",
            actor_type="user",
            actor_id=principal.user_id,
            payload={
                "run_id": run_id,
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "agent_id": body.agent_id,
                "prompt_pack_version": body.prompt_pack_version,
                "model_alias": body.model_alias,
                "risk_tier": body.risk_tier,
            },
        )
        telemetry.record_span(
            "run.start",
            run_id=run_id,
            audit_id=ref.audit_id,
            tenant_id=principal.tenant_id,
            agent_id=body.agent_id,
            risk_tier=body.risk_tier,
            prompt_pack_version=body.prompt_pack_version,
            model_alias=body.model_alias,
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

    async def _signal_decision(workflow_id: str, decision: ApprovalDecision) -> None:
        from temporalio.client import Client as TemporalClient

        client = await TemporalClient.connect(
            os.environ.get("TEMPORAL_ADDRESS", "temporal:7233"),
            namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
        )
        await client.get_workflow_handle(workflow_id).signal(SpecialistWorkflow.approve, decision)

    @app.post("/approvals")
    def approve(
        body: ApprovalRequest,
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> dict[str, Any]:
        if "approver" not in principal.roles:
            raise HTTPException(status_code=403, detail="approver role required")

        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            run = conn.execute("SELECT user_id FROM runs WHERE id = %s", (body.run_id,)).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail="run not found in this tenant")
        if str(run[0]) == principal.user_id:
            # Separation of duties: nobody approves their own request.
            raise HTTPException(status_code=403, detail="cannot approve your own run")

        # The approval preview is a rendering surface, so the arguments are
        # checked before they can be signed, audited or shown to a human. The
        # operator re-checks at execution; this closes the earlier surface.
        try:
            dlp.gate(
                json.dumps(body.arguments, ensure_ascii=False),
                surface="input",
                analyzer_url=DLP_URL,
            )
        except dlp.DlpBlocked as exc:
            # A refused approval is an event the ledger must show, even though
            # nothing was signed and the decision never happened.
            blocked = AuditLedger(_dsn()).append(
                tenant_id=principal.tenant_id,
                event_type="dlp.event",
                actor_type="user",
                actor_id=principal.user_id,
                payload={"run_id": body.run_id, "tool": body.tool, **exc.report},
            )
            telemetry.record_span(
                "dlp.event",
                run_id=body.run_id,
                audit_id=blocked.audit_id,
                tool=body.tool,
                surface=str(exc.report.get("surface", "")),
                action=str(exc.report.get("action", "")),
                detector_version=str(exc.report.get("detector_version", "")),
            )
            raise HTTPException(
                status_code=exc.status, detail={"reason": exc.reason, "dlp": [exc.report]}
            ) from exc

        token: str | None = None
        if body.approved:
            token = mint_approval_token(
                tenant_id=principal.tenant_id,
                run_id=body.run_id,
                tool=body.tool,
                arguments=body.arguments,
                approver=principal.user_id,
                private_key=_key(),
            )

        ref = AuditLedger(_dsn()).append(
            tenant_id=principal.tenant_id,
            event_type="approval.decision",
            actor_type="user",
            actor_id=principal.user_id,
            payload={
                "run_id": body.run_id,
                "tool": body.tool,
                "agent_id": body.agent_id,
                "approver": principal.user_id,
                "decision": "approved" if body.approved else "denied",
                "reason": body.reason,
                "ttl": APPROVAL_TTL,
                "rule_id": "approval.approved" if body.approved else "approval.denied",
            },
        )
        telemetry.record_span(
            "approval.decision",
            run_id=body.run_id,
            audit_id=ref.audit_id,
            tool=body.tool,
            decision="approved" if body.approved else "denied",
            approver=principal.user_id,
            ttl=APPROVAL_TTL,
        )

        close_request(
            dsn=_dsn(),
            tenant_id=principal.tenant_id,
            run_id=body.run_id,
            tool=body.tool,
            approved=body.approved,
            approver=principal.user_id,
            reason=body.reason,
        )

        decision = ApprovalDecision(
            approved=body.approved,
            approver=principal.user_id,
            reason=body.reason,
            token=token,
        )
        # Audit is written before the workflow is resumed.
        asyncio.run(_signal_decision(child_workflow_id(body.run_id, body.tool), decision))

        return {"audit_id": ref.audit_id, "approved": body.approved}

    @app.post("/policy/authorize")
    def policy_authorize(
        body: AuthorizeRequest, principal: Annotated[Principal, Depends(current_principal)]
    ) -> dict[str, Any]:
        decision = authorize(
            AuthorizationRequest(
                user_id=principal.user_id,
                tenant_id=principal.tenant_id,
                run_id=body.run_id,
                agent_id=body.agent_id,
                tool=body.tool,
            ),
            _checker(),
            PostgresRunStore(_dsn()),
        )
        # Audited before the caller can act on the decision; a ledger failure
        # fails the request rather than returning an unrecorded answer.
        ref = AuditLedger(_dsn()).append(
            tenant_id=principal.tenant_id,
            event_type="policy.decision",
            actor_type="user",
            actor_id=principal.user_id,
            payload={
                "outcome": decision.outcome,
                "rule_id": decision.rule_id,
                "tier": decision.tier,
                "tool": body.tool,
                "agent_id": body.agent_id,
                "run_id": body.run_id,
            },
        )
        return {
            "outcome": decision.outcome,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "tier": decision.tier,
            "audit_id": ref.audit_id,
            "audit": {
                "tenant_id": principal.tenant_id,
                "user_id": principal.user_id,
                "run_id": body.run_id,
                "agent_id": body.agent_id,
                "tool": body.tool,
            },
        }

    return app
