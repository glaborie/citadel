"""Activities: the only places that touch policy, the database or tools.

Every activity is synchronous and idempotent from Temporal's point of view:
the tool call is keyed, so a retry after a crash cannot produce a second side
effect. Whether a repeated attempt may re-run depends on how far the earlier
attempt got, which is what the `sent` marker records.
"""

from __future__ import annotations

import hashlib
import json
import urllib.error
from typing import Any
from urllib.request import Request, urlopen

from temporalio import activity

from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.policy import AuthorizationRequest, RelationChecker, RunStore, authorize
from citadel.policy.catalog import load_catalog
from citadel.workflows.types import PolicyOutcome, ToolCall, ToolResult


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
        return PolicyOutcome(
            outcome=decision.outcome,
            rule_id=decision.rule_id,
            reason=decision.reason,
            tier=decision.tier,
        )

    @activity.defn
    def execute_tool(self, call: ToolCall) -> ToolResult:
        key = idempotency_key(call)
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
                    return settled

            # Committed before the call leaves this process: a crash after this
            # point must not be retried as if nothing had been sent.
            conn.execute("UPDATE tool_calls SET status = 'sent' WHERE idempotency_key = %s", (key,))

        # Transport failures propagate so Temporal retries them. Anything the
        # tool actually answered is returned as a result, because a retry could
        # repeat a side effect.
        outcome = self._invoke(call)

        with tenant_connection(self._dsn, call.tenant_id) as conn:
            conn.execute(
                "UPDATE tool_calls SET status = %s, result = %s WHERE idempotency_key = %s",
                (outcome.status, json.dumps(outcome.output), key),
            )
        return ToolResult(
            status=outcome.status,
            tool=call.tool,
            rule_id=outcome.rule_id,
            detail=outcome.detail,
            idempotency_key=key,
            output=outcome.output,
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
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="tool.executed",
            detail=f"{call.tool} executed as {payload.get('allowlist_id')}",
            output=payload,
        )

    def _audit_dlp(self, call: ToolCall, reports: list[Any]) -> None:
        # One event per surface, passes included: the ledger has to show the
        # control ran, not only that it found something.
        for report in reports:
            if not isinstance(report, dict):
                continue
            self._audit.append(
                tenant_id=call.tenant_id,
                event_type="dlp.event",
                actor_type="agent",
                actor_id=call.agent_id,
                payload={"run_id": call.run_id, "tool": call.tool, **report},
            )


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
