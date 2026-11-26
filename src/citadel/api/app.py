"""Citadel API: authenticated ingress, tenant extraction and run creation.

Every route except /healthz requires a verified Keycloak token carrying a
tenant claim. Missing tenant, missing token or an unreachable identity
provider all fail closed.
"""

# No `from __future__ import annotations`: FastAPI must see the real Depends
# objects, and the dependency is a closure over create_app's arguments.
import asyncio
import hashlib
import json
import os
import uuid
from typing import Annotated, Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from citadel import __version__, dlp, telemetry, tool_outputs
from citadel.approval_requests import close_request
from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.env import secret
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError, KeycloakVerifier, Principal, mint_run_token
from citadel.identity.run_token import private_key_from_env
from citadel.policy import AuthorizationRequest, RelationChecker, authorize
from citadel.policy.openfga import build_checker
from citadel.runs import PostgresRunStore
from citadel.skills import SkillPack, SkillPackError, SkillPackMissing, load_pack
from citadel.workflows.orchestrator import RunWorkflow, child_workflow_id
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import APPROVAL_TTL, ApprovalDecision, RunInput

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
    # A task turns the run into a model-driven one and starts its workflow. No
    # task means the API only records the run, which is what the tenancy and
    # policy tests rely on.
    task: str = Field(default="", max_length=8000)


async def start_run(item: RunInput) -> None:
    """Submit the orchestrator workflow for a created run.

    The run id is the workflow id, so a second submit for the same run is a
    duplicate rather than a second execution.
    """
    from temporalio.client import Client as TemporalClient

    client = await TemporalClient.connect(
        os.environ.get("TEMPORAL_ADDRESS", "temporal:7233"),
        namespace=os.environ.get("TEMPORAL_NAMESPACE", "default"),
    )
    await client.start_workflow(
        RunWorkflow.run,
        item,
        id=f"run-{item.run_id}",
        task_queue="orchestrator",
    )


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
        return dsn if dsn is not None else secret("CITADEL_DB_DSN")

    def _key() -> Ed25519PrivateKey:
        if private_key is not None:
            return private_key
        return private_key_from_env(secret("CITADEL_RUN_TOKEN_PRIVATE_KEY"))

    def _pack(agent: str) -> SkillPack:
        try:
            return load_pack(agent)
        except SkillPackMissing as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except SkillPackError as exc:
            # The deployment is broken, the request is not: do not invite a retry.
            raise HTTPException(status_code=503, detail=f"skill pack unusable: {exc}") from exc

    @app.post("/runs", status_code=201)
    async def create_run(
        body: RunRequest, principal: Annotated[Principal, Depends(current_principal)]
    ) -> dict[str, Any]:
        # Provenance is only reproducible if it names content this deployment
        # actually has, so the caller's label is checked, never trusted.
        pack = _pack(body.agent_id)
        if body.prompt_pack_version != pack.name:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"unknown prompt_pack_version {body.prompt_pack_version!r};"
                    f" agent {body.agent_id!r} runs {pack.name!r}"
                ),
            )
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
                # The task itself stays out of the ledger; the hash proves which
                # text ran without storing it.
                "task_sha256": hashlib.sha256(body.task.encode()).hexdigest() if body.task else "",
                "task_chars": len(body.task),
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
        if body.task:
            try:
                await start_run(
                    RunInput(
                        run_id=run_id,
                        tenant_id=principal.tenant_id,
                        user_id=principal.user_id,
                        agent_id=body.agent_id,
                        tool="",
                        task=body.task,
                        model_alias=body.model_alias,
                        prompt_pack_version=body.prompt_pack_version,
                    )
                )
            except Exception as exc:
                # The row and the run.start audit exist, so say what happened:
                # recorded, not started. A 201 here would be a lie.
                with tenant_connection(_dsn(), principal.tenant_id) as conn:
                    conn.execute("UPDATE runs SET status = 'failed' WHERE id = %s", (run_id,))
                AuditLedger(_dsn()).append(
                    tenant_id=principal.tenant_id,
                    event_type="run.end",
                    actor_type="user",
                    actor_id=principal.user_id,
                    payload={
                        "run_id": run_id,
                        "outcome": "failed",
                        "citation_ids": [],
                        "safety_flags": ["workflow_not_started"],
                    },
                )
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"run {run_id} was recorded but its workflow did not start:"
                        f" {str(exc)[:200]}"
                    ),
                ) from exc

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

    @app.get("/runs/{run_id}/outputs/{digest}")
    def read_output(
        run_id: str,
        digest: str,
        principal: Annotated[Principal, Depends(current_principal)],
    ) -> dict[str, Any]:
        """Read back a tool stream the event history could not carry in full.

        The run has to exist in the caller's tenant, and RLS decides the rest: a
        digest is content-addressed, so two tenants holding identical bytes are two
        rows, and neither can read the other's.
        """
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            known = conn.execute("SELECT 1 FROM runs WHERE id = %s", (run_id,)).fetchone()
            if known is None:
                raise HTTPException(status_code=404, detail="run not found in this tenant")
            body = tool_outputs.fetch(conn, digest=digest)
        if body is None:
            raise HTTPException(status_code=404, detail="no stored output for that digest")

        AuditLedger(_dsn()).append(
            tenant_id=principal.tenant_id,
            event_type="tool.output.read",
            actor_type="user",
            actor_id=principal.user_id,
            payload={"run_id": run_id, "digest": digest, "bytes": len(body.encode("utf-8"))},
        )
        return {
            "run_id": run_id,
            "digest": digest,
            "bytes": len(body.encode("utf-8")),
            "output": body,
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
                "args_hash": arguments_hash(body.arguments),
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
            approval_ref=ref.audit_id if body.approved else None,
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
