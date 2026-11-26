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
from dataclasses import dataclass
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
from citadel.identity import (
    IdentityError,
    KeycloakVerifier,
    Principal,
    mint_run_token,
    verify_run_token,
)
from citadel.identity.run_token import private_key_from_env
from citadel.policy import (
    ApprovalAuthorization,
    AuthorizationRequest,
    RelationChecker,
    authorize,
    authorize_approval,
)
from citadel.policy.openfga import build_checker
from citadel.runs import PostgresRunStore
from citadel.skills import SkillPack, SkillPackError, SkillPackMissing, load_pack
from citadel.workflows.orchestrator import RunWorkflow
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


@dataclass(frozen=True)
class Approver:
    """A verified decision-maker: a Keycloak user or a run-token agent.

    The two identities are never merged: an agent acts in its own name, with the
    user it runs for recorded as `on_behalf_of`, so the ledger can tell them apart.
    """

    tenant_id: str
    actor_type: str  # user | agent
    actor_id: str
    on_behalf_of: str | None = None
    roles: frozenset[str] = frozenset()


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

    def current_approver(
        authorization: Annotated[str | None, Header()] = None,
    ) -> Approver:
        """Authenticate a human approver or an agent approver.

        A Keycloak token is tried first; a run token is the only other accepted
        credential, and its agent identity comes from the verified claims. There is
        no anonymous path, and the tenant is never taken from the body.
        """
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = authorization.removeprefix("Bearer ").strip()
        active = verifier if verifier is not None else _verifier_from_env()
        try:
            principal = active.verify(token)
        except IdentityError as user_error:
            return _agent_approver(token, user_error)
        return Approver(
            tenant_id=principal.tenant_id,
            actor_type="user",
            actor_id=principal.user_id,
            roles=principal.roles,
        )

    def _agent_approver(token: str, user_error: IdentityError) -> Approver:
        """The second credential: a run token, whose agent identity is verified.

        Reached only after the user token was refused, and it refuses in turn rather
        than falling back: no verified run token means no approver.
        """
        try:
            key = _key()
        except (KeyError, IdentityError, ValueError) as exc:
            raise HTTPException(status_code=503, detail="api cannot verify run tokens") from exc
        try:
            context = verify_run_token(token, key.public_key())
        except IdentityError as exc:
            raise HTTPException(status_code=401, detail=str(user_error)) from exc
        return Approver(
            tenant_id=context.tenant_id,
            actor_type="agent",
            actor_id=context.agent_id,
            on_behalf_of=context.user_id,
        )

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
                        run_token=token,
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
        approver: Annotated[Approver, Depends(current_approver)],
    ) -> dict[str, Any]:
        with tenant_connection(_dsn(), approver.tenant_id) as conn:
            run = conn.execute(
                "SELECT user_id, agent_id FROM runs WHERE id = %s", (body.run_id,)
            ).fetchone()
        if run is None:
            raise HTTPException(status_code=404, detail="run not found in this tenant")
        run_user, run_agent = str(run[0]), str(run[1])

        if approver.actor_type == "user":
            if "approver" not in approver.roles:
                raise HTTPException(status_code=403, detail="approver role required")
            if run_user == approver.actor_id:
                # Separation of duties: nobody approves their own request.
                raise HTTPException(status_code=403, detail="cannot approve your own run")
            relation = "approver_role"
            decided_by = approver.actor_id
        else:
            verdict = authorize_approval(
                ApprovalAuthorization(
                    tenant_id=approver.tenant_id,
                    approving_agent=approver.actor_id,
                    origin_agent=run_agent,
                    tool=body.tool,
                ),
                _checker(),
            )
            if verdict.outcome != "allow":
                raise HTTPException(
                    status_code=403,
                    detail={"reason": verdict.reason, "rule_id": verdict.rule_id},
                )
            relation = "can_approve"
            decided_by = f"agent:{approver.tenant_id}/{approver.actor_id}"

        # The row is the only durable record of which child workflow parked: its
        # id carries the task-run step, so run and tool cannot rebuild it.
        with tenant_connection(_dsn(), approver.tenant_id) as conn:
            parked = conn.execute(
                "SELECT workflow_id FROM approval_requests"
                " WHERE run_id = %s AND tool = %s AND status = 'pending'",
                (body.run_id, body.tool),
            ).fetchone()
        if parked is None:
            raise HTTPException(status_code=409, detail="no pending approval for this run and tool")
        workflow_id = str(parked[0])
        if not workflow_id:
            raise HTTPException(status_code=409, detail="approval recorded no workflow to resume")

        # The approval preview is a rendering surface, so the arguments are
        # checked before they can be signed, audited or shown to a human. The
        # operator re-checks at execution; this closes the earlier surface.
        try:
            dlp.gate(
                json.dumps(body.arguments, ensure_ascii=False),
                surface="input",
                analyzer_url=DLP_URL,
            )
            # The reason is the one field a human types freely, usually under
            # pressure and often quoting the very secret that caused the incident.
            # It is gated too, on the `record` surface: PII is redacted in place, a
            # credential blocks. Only the redacted form is kept - the raw text is
            # replaced by its hash and a redaction count, so the ledger can prove
            # what was decided on without holding it.
            reason, reason_report = dlp.gate(
                body.reason,
                surface="record",
                analyzer_url=DLP_URL,
            )
        except dlp.DlpBlocked as exc:
            # A refused approval is an event the ledger must show, even though
            # nothing was signed and the decision never happened.
            blocked = AuditLedger(_dsn()).append(
                tenant_id=approver.tenant_id,
                event_type="dlp.event",
                actor_type=approver.actor_type,
                actor_id=decided_by,
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

        redactions = sum(
            1 for finding in reason_report["findings"] if finding["action"] == "redact"
        )
        if redactions:
            # A redaction is a detector decision, so it belongs in the ledger
            # beside the blocks rather than only implicit in a clean reason.
            redacted = AuditLedger(_dsn()).append(
                tenant_id=approver.tenant_id,
                event_type="dlp.event",
                actor_type=approver.actor_type,
                actor_id=decided_by,
                payload={"run_id": body.run_id, "tool": body.tool, **reason_report},
            )
            telemetry.record_span(
                "dlp.event",
                run_id=body.run_id,
                audit_id=redacted.audit_id,
                tool=body.tool,
                surface=str(reason_report.get("surface", "")),
                action=str(reason_report.get("action", "")),
                detector_version=str(reason_report.get("detector_version", "")),
            )

        payload: dict[str, Any] = {
            "run_id": body.run_id,
            "tool": body.tool,
            "agent_id": run_agent,
            "approver": decided_by,
            # Self-describing in the ledger and in a trajectory export: the
            # audit column carries this too, but the event must not need a join.
            "actor_type": approver.actor_type,
            "relation": relation,
            "decision": "approved" if body.approved else "denied",
            "reason": reason,
            "reason_sha256": hashlib.sha256(body.reason.encode()).hexdigest(),
            "reason_chars": len(body.reason),
            "dlp_redactions": redactions,
            "dlp_categories": reason_report["categories"],
            "ttl": APPROVAL_TTL,
            "args_hash": arguments_hash(body.arguments),
            "rule_id": "approval.approved" if body.approved else "approval.denied",
        }
        if approver.on_behalf_of is not None:
            payload["on_behalf_of"] = approver.on_behalf_of

        ref = AuditLedger(_dsn()).append(
            tenant_id=approver.tenant_id,
            event_type="approval.decision",
            actor_type=approver.actor_type,
            actor_id=decided_by,
            payload=payload,
        )
        telemetry.record_span(
            "approval.decision",
            run_id=body.run_id,
            audit_id=ref.audit_id,
            tool=body.tool,
            decision="approved" if body.approved else "denied",
            approver=decided_by,
            actor_type=approver.actor_type,
            ttl=APPROVAL_TTL,
            redactions=redactions,
        )

        decision = ApprovalDecision(
            approved=body.approved,
            approver=decided_by,
            reason=reason,
            approval_ref=ref.audit_id if body.approved else None,
        )
        # Audit is written before the workflow is resumed. The row is closed only
        # after the signal lands, so a failed signal leaves the approval pending
        # and retryable instead of consumed for a workflow nobody resumed.
        try:
            asyncio.run(_signal_decision(workflow_id, decision))
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"workflow {workflow_id} did not accept the decision: {str(exc)[:200]}",
            ) from exc

        close_request(
            dsn=_dsn(),
            tenant_id=approver.tenant_id,
            run_id=body.run_id,
            tool=body.tool,
            approved=body.approved,
            approver=decided_by,
            reason=reason,
        )

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
