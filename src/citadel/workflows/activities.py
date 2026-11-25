"""Activities: the only places that touch policy, the database or tools.

Every activity is synchronous and idempotent from Temporal's point of view:
the tool call is keyed, so a retry after a crash cannot produce a second side
effect. Whether a repeated attempt may re-run depends on how far the earlier
attempt got, which is what the `sent` marker records.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
from typing import Any
from urllib.request import Request, urlopen

from temporalio import activity

from citadel import dlp
from citadel.approval_requests import record_request
from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.hashing import arguments_hash
from citadel.model.client import ModelUnavailable, OmniRouteClient
from citadel.model.prompt import system_prompt, tool_schemas
from citadel.policy import AuthorizationRequest, RelationChecker, RunStore, authorize
from citadel.policy.catalog import load_catalog
from citadel.telemetry import record_span
from citadel.tools.bounds import DEFAULT_EVENT_LIMIT, bound
from citadel.workflows.types import (
    ModelRequest,
    ModelTurn,
    PolicyOutcome,
    RunEnd,
    ToolCall,
    ToolResult,
)

DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")
# A tool result is part of the activity's return value, which Temporal
# stores in event history: an uncapped 64 KB body becomes 64 KB of history
# per call, and a few calls reach the 256 KB warning.
EVENT_OUTPUT_LIMIT = int(os.environ.get("CITADEL_EVENT_OUTPUT_MAX_BYTES", DEFAULT_EVENT_LIMIT))


def bounded_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Cap the streams that ride in the activity result, keeping their digests.

    The digest of the whole stream stays behind, so the cap is visible in the
    record instead of being implied by an absence of bytes.
    """
    capped = dict(payload)
    digest_of: list[str] = []
    original_bytes = 0
    truncated = False
    for stream in ("stdout", "stderr"):
        text = capped.get(stream)
        if not isinstance(text, str) or not text:
            continue
        bounded = bound(text, limit=EVENT_OUTPUT_LIMIT)
        capped[stream] = bounded.text
        digest_of.append(bounded.sha256)
        original_bytes += bounded.original_bytes
        truncated = truncated or bounded.truncated
    capped["output_sha256"] = digest_of[0] if digest_of else ""
    capped["original_bytes"] = original_bytes
    capped["truncated"] = truncated or bool(payload.get("truncated", False))
    return capped


def idempotency_key(call: ToolCall) -> str:
    """Stable across retries: same run, tool and canonical arguments."""
    payload = json.dumps(
        {"tool": call.tool, "arguments": call.arguments},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"{call.run_id}:{call.tool}:{digest}"


class ToolActivities:
    def __init__(
        self,
        *,
        checker: RelationChecker,
        run_store: RunStore,
        dsn: str,
        runner_url: str,
        operator_url: str,
        audit: AuditLedger,
    ) -> None:
        self._checker = checker
        self._run_store = run_store
        self._dsn = dsn
        self._runner_url = runner_url
        self._operator_url = operator_url
        self._audit = audit

    @activity.defn
    def authorize_tool(self, call: ToolCall) -> PolicyOutcome:
        decision = authorize(
            AuthorizationRequest(
                user_id=call.user_id,
                tenant_id=call.tenant_id,
                run_id=call.run_id,
                agent_id=call.agent_id,
                tool=call.tool,
            ),
            self._checker,
            self._run_store,
        )
        # The workflow path had no policy audit before this: only the API's
        # /policy/authorize route wrote one, so a delegated run left no trace.
        ref = self._audit.append(
            tenant_id=call.tenant_id,
            event_type="policy.decision",
            actor_type="agent",
            actor_id=call.agent_id,
            payload={
                "run_id": call.run_id,
                "subject": call.user_id,
                "tool": call.tool,
                "args_hash": arguments_hash(call.arguments),
                "decision": decision.outcome,
                "rule_id": decision.rule_id,
                "tier": decision.tier,
            },
        )
        record_span(
            "policy.decision",
            run_id=call.run_id,
            audit_id=ref.audit_id,
            tool=call.tool,
            decision=decision.outcome,
            rule_id=decision.rule_id,
            tier=decision.tier,
        )
        if decision.outcome == "requires_approval":
            # The arguments are about to be shown to a human: check them now,
            # and neither persist nor ask when the detector cannot answer.
            try:
                dlp.gate(
                    json.dumps(call.arguments, ensure_ascii=False),
                    surface="input",
                    analyzer_url=DLP_URL,
                )
            except dlp.DlpBlocked as exc:
                self._audit_dlp(call, [exc.report])
                unavailable = exc.reason == "dlp_unavailable"
                return PolicyOutcome(
                    outcome="deny",
                    rule_id="dlp.unavailable" if unavailable else "dlp.blocked",
                    reason=(
                        "the detector could not check the approval arguments,"
                        " so the call was refused"
                        if unavailable
                        else "DLP found sensitive content in the approval"
                        " arguments and refused it"
                    ),
                    tier=decision.tier,
                )
            record_request(
                dsn=self._dsn, call=call, tier=decision.tier, rule_id=decision.rule_id
            )

        return PolicyOutcome(
            outcome=decision.outcome,
            rule_id=decision.rule_id,
            reason=decision.reason,
            tier=decision.tier,
        )

    @activity.defn
    def execute_tool(self, call: ToolCall) -> ToolResult:
        key = idempotency_key(call)
        args_hash = arguments_hash(call.arguments)
        spec = load_catalog().get(call.tool)
        tier = spec.tier if spec is not None else "T0"

        with tenant_connection(self._dsn, call.tenant_id) as conn:
            inserted = conn.execute(
                "INSERT INTO tool_calls (idempotency_key, tenant_id, run_id, tool, status)"
                " VALUES (%s, %s, %s, %s, 'started')"
                " ON CONFLICT (idempotency_key) DO NOTHING"
                " RETURNING id",
                (key, call.tenant_id, call.run_id, call.tool),
            ).fetchone()

            if inserted is None:
                row = conn.execute(
                    "SELECT status, result FROM tool_calls WHERE idempotency_key = %s",
                    (key,),
                ).fetchone()
                if row is None:  # pragma: no cover - the conflict implies a row
                    raise RuntimeError(f"idempotency row missing for {key}")
                settled = self._settled(call, key, str(row[0]), row[1], tier)
                if settled is not None:
                    self._audit_tool(call, settled, args_hash=args_hash, key=key, tier=tier)
                    return settled

            # Committed before the call leaves this process: a crash after this
            # point must not be retried as if nothing had been sent.
            conn.execute("UPDATE tool_calls SET status = 'sent' WHERE idempotency_key = %s", (key,))

        # Transport failures propagate so Temporal retries them. Anything the
        # tool actually answered is returned as a result, because a retry could
        # repeat a side effect.
        started = time.monotonic()
        outcome = self._invoke(call)
        duration = round((time.monotonic() - started) * 1000)

        result = ToolResult(
            status=outcome.status,
            tool=call.tool,
            rule_id=outcome.rule_id,
            detail=outcome.detail,
            idempotency_key=key,
            output=outcome.output,
        )
        with tenant_connection(self._dsn, call.tenant_id) as conn:
            conn.execute(
                "UPDATE tool_calls SET status = %s, result = %s WHERE idempotency_key = %s",
                (result.status, json.dumps(result.output), key),
            )
        self._audit_tool(call, result, args_hash=args_hash, key=key, tier=tier, duration=duration)
        return result

    def _audit_tool(
        self,
        call: ToolCall,
        result: ToolResult,
        *,
        args_hash: str,
        key: str,
        tier: str,
        duration: int = 0,
    ) -> None:
        ref = self._audit.append(
            tenant_id=call.tenant_id,
            event_type="tool.call",
            actor_type="agent",
            actor_id=call.agent_id,
            payload={
                "run_id": call.run_id,
                "tool": call.tool,
                "tier": tier,
                "args_hash": args_hash,
                "idempotency_key": result.idempotency_key or key,
                "status": result.status,
                "duration": duration,
                "rule_id": result.rule_id,
                "detail": result.detail,
                "replayed": result.replayed,
                # Evidence that a cap was applied, and of what it hid.
                "output_sha256": result.output_sha256,
                "output_bytes": result.output_bytes,
                "output_truncated": result.output_truncated,
            },
        )
        record_span(
            "tool.call",
            run_id=call.run_id,
            audit_id=ref.audit_id,
            tool=call.tool,
            tier=tier,
            status=result.status,
            idempotency_key=result.idempotency_key or key,
            duration=duration,
            replayed=result.replayed,
        )

    def _settled(
        self, call: ToolCall, key: str, status: str, result: Any, tier: str
    ) -> ToolResult | None:
        """What a repeated attempt may do with a key that already exists.

        None means the earlier attempt provably never reached the tool, so
        attempting again is safe. A `sent` row on a write is the one case where
        the outcome is genuinely unknown.
        """
        if status in {"executed", "replayed", "failed"}:
            return ToolResult(
                status="replayed",
                tool=call.tool,
                rule_id="idempotency.replayed",
                detail="an earlier attempt produced this key",
                idempotency_key=key,
                replayed=True,
                output=result or {},
            )
        if tier == "T1":
            # The approval was consumed and the command may have run. Retrying
            # would either duplicate it or be refused; neither is a result.
            return ToolResult(
                status="failed",
                tool=call.tool,
                rule_id="tool.possibly_executed",
                detail=(
                    "an earlier attempt was interrupted after the approval was consumed;"
                    " the write may have happened, verify before retrying"
                ),
                idempotency_key=key,
            )
        return None

    def _invoke(self, call: ToolCall) -> ToolResult:
        spec = load_catalog().get(call.tool)
        if spec is not None and spec.tier == "T1":
            return self._invoke_operator(call)
        return self._invoke_sandbox(call)

    def _invoke_operator(self, call: ToolCall) -> ToolResult:
        if not call.approval_token:
            return ToolResult(
                status="denied",
                tool=call.tool,
                rule_id="approval.missing_token",
                detail="T1 execution requires a signed approval token",
            )
        body = json.dumps(
            {
                "tenant_id": call.tenant_id,
                "run_id": call.run_id,
                "tool": call.tool,
                "arguments": call.arguments,
                "approval_token": call.approval_token,
            }
        ).encode()
        return self._post(f"{self._operator_url}/execute", body, call)

    def _invoke_sandbox(self, call: ToolCall) -> ToolResult:
        body = json.dumps(
            {"agent": call.agent_id, "tool": call.tool, "arguments": call.arguments}
        ).encode()
        return self._post(f"{self._runner_url}/execute", body, call)

    def _post(self, url: str, body: bytes, call: ToolCall) -> ToolResult:
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(request, timeout=60) as response:
                payload: dict[str, Any] = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            # A tool service that answered is deterministic: retrying the same
            # request would get the same answer, and for a write it could repeat
            # a side effect. So this is a result, not an exception.
            raw = exc.read().decode("utf-8", errors="replace")
            reports = _dlp_reports(_json_or_none(raw))
            if reports is not None:
                self._audit_dlp(call, reports)
                unavailable = exc.code == 503
                return ToolResult(
                    status="failed",
                    tool=call.tool,
                    rule_id="dlp.unavailable" if unavailable else "dlp.blocked",
                    detail=(
                        "the detector could not check this call, so it was refused"
                        if unavailable
                        else "DLP found sensitive content in this call and refused it"
                    ),
                )
            detail = raw[:300]
            rule = "tool.refused" if exc.code in (403, 409) else "tool.error"
            return ToolResult(
                status="failed",
                tool=call.tool,
                rule_id=rule,
                detail=f"the tool service refused the call: {detail}",
            )
        # Transport failures deliberately propagate: Temporal's retry policy is
        # the only retry mechanism, and swallowing the error here would make it
        # decorative.
        reports = _dlp_reports(payload)
        if reports is not None:
            self._audit_dlp(call, reports)
        capped = bounded_payload(payload)
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="tool.executed",
            detail=f"{call.tool} executed as {payload.get('allowlist_id')}",
            output=capped,
            output_sha256=str(capped.get("output_sha256", "")),
            output_bytes=int(capped.get("original_bytes", 0)),
            output_truncated=bool(capped.get("truncated", False)),
        )

    def _audit_dlp(self, call: ToolCall, reports: list[Any]) -> None:
        # One event per surface, passes included: the ledger has to show the
        # control ran, not only that it found something.
        for report in reports:
            if not isinstance(report, dict):
                continue
            ref = self._audit.append(
                tenant_id=call.tenant_id,
                event_type="dlp.event",
                actor_type="agent",
                actor_id=call.agent_id,
                payload={"run_id": call.run_id, "tool": call.tool, **report},
            )
            categories = report.get("categories", [])
            record_span(
                "dlp.event",
                run_id=call.run_id,
                audit_id=ref.audit_id,
                tool=call.tool,
                surface=str(report.get("surface", "")),
                action=str(report.get("action", "")),
                detector_version=str(report.get("detector_version", "")),
                categories=",".join(str(item) for item in categories)
                if isinstance(categories, list)
                else "",
            )


class RunActivities:
    """Run lifecycle writes. The orchestrator owns no tools, only this record."""

    def __init__(self, *, dsn: str, audit: AuditLedger) -> None:
        self._dsn = dsn
        self._audit = audit

    @activity.defn
    def finish_run(self, end: RunEnd) -> None:
        with tenant_connection(self._dsn, end.tenant_id) as conn:
            conn.execute(
                "UPDATE runs SET status = %s WHERE id = %s",
                (end.outcome, end.run_id),
            )
            existing = conn.execute(
                "SELECT 1 FROM audit_events WHERE tenant_id = %s"
                " AND event_type = 'run.end' AND payload->>'run_id' = %s LIMIT 1",
                (end.tenant_id, end.run_id),
            ).fetchone()
            if existing is not None:
                # A retried activity must not fork the trajectory.
                return
        ref = self._audit.append(
            tenant_id=end.tenant_id,
            event_type="run.end",
            actor_type="agent",
            actor_id="orchestrator",
            payload={
                "run_id": end.run_id,
                "outcome": end.outcome,
                "citation_ids": end.citation_ids,
                "safety_flags": end.safety_flags,
                # Empty for a tool-driven run; for a model run it is the gated
                # answer, and the console has no other place to show it.
                "answer": end.answer[:4000],
            },
        )
        record_span(
            "run.end",
            run_id=end.run_id,
            audit_id=ref.audit_id,
            outcome=end.outcome,
            safety_flags=",".join(end.safety_flags),
        )


class ModelActivities:
    """Model turns. The only place the runtime talks to the gateway.

    The prompt arrives already assembled from the agent's pack and tool
    manifest, and the gateway's own DLP gate runs inside the client before the
    request leaves the process. What this adds is the `model.call` audit row:
    one per completion, with the provider's token and cost figures.
    """

    def __init__(
        self,
        *,
        dsn: str,
        audit: AuditLedger,
        gateway_url: str,
        api_key: str,
        analyzer_url: str,
        default_alias: str,
    ) -> None:
        self._dsn = dsn
        self._audit = audit
        self._gateway_url = gateway_url
        self._api_key = api_key
        self._analyzer_url = analyzer_url
        self._default_alias = default_alias

    @activity.defn
    def system_prompt(self, agent: str) -> str:
        return system_prompt(agent)

    @activity.defn
    def tools(self, agent: str) -> list[dict[str, Any]]:
        return tool_schemas(agent)

    @activity.defn
    def complete(self, request: ModelRequest) -> ModelTurn:
        client = OmniRouteClient(
            base_url=self._gateway_url,
            api_key=self._api_key,
            analyzer_url=self._analyzer_url,
            alias=self._default_alias,
        )
        try:
            reply = client.complete(
                messages=request.messages,
                tools=request.tools,
                alias=request.alias or None,
                run_id=request.run_id,
            )
        except dlp.DlpBlocked as exc:
            # The prompt never left the process. Recorded like any other DLP
            # refusal so the trajectory shows why there is no answer.
            self._audit.append(
                tenant_id=request.tenant_id,
                event_type="dlp.event",
                actor_type="agent",
                actor_id=request.agent_id,
                payload={"run_id": request.run_id, **exc.report},
            )
            return ModelTurn(blocked="dlp", detail=exc.reason)
        except ModelUnavailable as exc:
            return ModelTurn(blocked="unavailable", detail=str(exc)[:200])

        ref = self._audit.append(
            tenant_id=request.tenant_id,
            event_type="model.call",
            actor_type="agent",
            actor_id=request.agent_id,
            payload={
                "run_id": request.run_id,
                "alias": request.alias or self._default_alias,
                # The gateway is the provider boundary; the alias and the model
                # it resolved to are what a comparison needs.
                "provider": "omniroute",
                "model": reply.model,
                "input_hash": f"sha256:{_sha(json.dumps(request.messages, sort_keys=True))}",
                "output_hash": f"sha256:{_sha(_reply_text(reply))}",
                "tokens": reply.usage.total,
                "cost": reply.usage.cost_usd,
                "latency": reply.latency_ms,
            },
        )
        record_span(
            "model.call",
            run_id=request.run_id,
            audit_id=ref.audit_id,
            model=reply.model,
            alias=request.alias or self._default_alias,
            tokens=reply.usage.total,
        )
        return ModelTurn(reply=reply)

    @activity.defn
    def gate(self, text: str, surface: str) -> str:
        return dlp.gate(text, surface=surface, analyzer_url=self._analyzer_url)[0]


def _reply_text(reply: Any) -> str:
    return json.dumps(
        {
            "content": reply.content,
            "tools": [
                {"name": call.name, "arguments": call.arguments} for call in reply.tools
            ],
        },
        sort_keys=True,
    )


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _json_or_none(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return None


def _dlp_reports(payload: Any) -> list[Any] | None:
    """DLP reports at the top level on success, under `detail` on a refusal."""
    if not isinstance(payload, dict):
        return None
    reports = payload.get("dlp")
    if reports is None and isinstance(payload.get("detail"), dict):
        reports = payload["detail"].get("dlp")
    return reports if isinstance(reports, list) else None
