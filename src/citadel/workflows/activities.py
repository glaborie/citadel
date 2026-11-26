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
from dataclasses import dataclass, replace
from typing import Any
from urllib.request import Request

from temporalio import activity

from citadel import dlp, tool_outputs
from citadel.approval_requests import record_request
from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.hashing import arguments_hash
from citadel.net import open_url
from citadel.policy import AuthorizationRequest, RelationChecker, RunStore, authorize
from citadel.policy.catalog import load_catalog
from citadel.telemetry import record_span
from citadel.tools.bounds import DEFAULT_EVENT_LIMIT, bound
from citadel.workflows.types import PolicyOutcome, RunEnd, ToolCall, ToolResult

DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")
# A tool result is part of the activity's return value, which Temporal
# stores in event history: an uncapped 64 KB body becomes 64 KB of history
# per call, and a few calls reach the 256 KB warning.
EVENT_OUTPUT_LIMIT = int(os.environ.get("CITADEL_EVENT_OUTPUT_MAX_BYTES", DEFAULT_EVENT_LIMIT))


@dataclass(frozen=True)
class Bounded:
    """What the record carries, and what the cap pushed out of it."""

    payload: dict[str, Any]
    dropped: dict[str, str]


def bounded_payload(payload: dict[str, Any]) -> Bounded:
    """Cap the streams that ride in the activity result, keeping their digests.

    The digest of the whole stream stays behind, so the cap is visible in the
    record instead of being implied by an absence of bytes - and the text that did
    not fit is returned as `dropped`, so the caller can keep it somewhere a
    reviewer can reach.
    """
    capped = dict(payload)
    digests: dict[str, str] = {}
    dropped: dict[str, str] = {}
    original_bytes = 0
    truncated = False
    for stream in ("stdout", "stderr"):
        text = capped.get(stream)
        if not isinstance(text, str) or not text:
            continue
        bounded = bound(text, limit=EVENT_OUTPUT_LIMIT)
        capped[stream] = bounded.text
        digests[stream] = bounded.sha256
        original_bytes += bounded.original_bytes
        truncated = truncated or bounded.truncated
        if bounded.text != text:
            dropped[stream] = text
    # What the tool service measured before its own cap is the truth about how much
    # output existed. Ignoring it made a 10 MB log that the sandbox cut to 64 KB
    # report 64 KB, so the record said "nothing was lost" about 9.9 MB.
    discarded = int(payload.get("omitted_bytes", 0) or 0)
    capped["output_sha256"] = digests.get("stdout", "")
    capped["stream_sha256"] = digests
    capped["original_bytes"] = original_bytes + discarded
    capped["discarded_bytes"] = discarded
    capped["truncated"] = truncated or bool(payload.get("truncated", False)) or discarded > 0
    return Bounded(payload=capped, dropped=dropped)


def cap_and_offload(
    dsn: str, call: ToolCall, payload: dict[str, Any]
) -> tuple[dict[str, Any], str, bool]:
    """Cap for the record, keep the rest by digest, and say which happened.

    Returns the payload that enters history, the digest of the primary stream, and
    whether anything was stored. A tool whose output fits changes nothing.
    """
    bounded = bounded_payload(payload)
    if not bounded.dropped:
        return bounded.payload, "", False

    offloaded: dict[str, Any] = {}
    with tenant_connection(dsn, call.tenant_id) as conn:
        for stream, text in bounded.dropped.items():
            kept = tool_outputs.store(
                conn,
                tenant_id=call.tenant_id,
                run_id=call.run_id,
                tool=call.tool,
                stream=stream,
                text=text,
            )
            offloaded[stream] = {"digest": kept.digest, "bytes": kept.bytes, "stored": kept.stored}
    bounded.payload["offloaded"] = offloaded
    primary = offloaded.get("stdout") or next(iter(offloaded.values()))
    stored = any(item["stored"] for item in offloaded.values())
    return bounded.payload, str(primary["digest"]), stored


def _offload_pointer(stored: dict[str, Any]) -> tuple[str, bool]:
    """The digest a stored payload points at, and whether any body was kept.

    `cap_and_offload` writes `offloaded` keyed by stream; stdout is the primary one
    when it exists, because that is the stream a reader asks for first.
    """
    offloaded = stored.get("offloaded")
    if not isinstance(offloaded, dict) or not offloaded:
        return "", False
    primary = offloaded.get("stdout") or next(iter(offloaded.values()))
    digest = str(primary.get("digest", "")) if isinstance(primary, dict) else ""
    kept = any(bool(item.get("stored")) for item in offloaded.values() if isinstance(item, dict))
    return digest, kept


def _replayed(call: ToolCall, key: str, stored: dict[str, Any]) -> ToolResult:
    """The result of a repeated attempt, describing the output it hands back.

    The stored payload is the same dict the first attempt capped, so every typed
    field is derivable - `offloaded` names the digest and whether the body was
    kept. Returning the payload with the typed fields left at their defaults told a
    consumer "no output" about a call whose output is stored and readable.
    """
    output_ref, stored_any = _offload_pointer(stored)
    return ToolResult(
        status="replayed",
        tool=call.tool,
        rule_id="idempotency.replayed",
        detail="an earlier attempt produced this key",
        idempotency_key=key,
        replayed=True,
        output=stored,
        output_sha256=str(stored.get("output_sha256", "")),
        output_bytes=int(stored.get("original_bytes", 0) or 0),
        output_truncated=bool(stored.get("truncated", False)),
        output_ref=output_ref,
        output_stored=stored_any,
    )


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
                        else "DLP found sensitive content in the approval arguments and refused it"
                    ),
                    tier=decision.tier,
                )
            record_request(dsn=self._dsn, call=call, tier=decision.tier, rule_id=decision.rule_id)

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

        # `replace`, not a field-by-field copy: the earlier spelling listed the
        # fields it knew about and silently dropped `output_sha256`,
        # `output_bytes`, `output_truncated`, `output_ref` and `output_stored`, so
        # the audit event for a capped call reported no cap. A copy that cannot
        # forget a field added later is the only copy worth writing here.
        result = replace(outcome, idempotency_key=key)
        # The event goes before the row settles. A worker killed between the two
        # writes then leaves `sent` with an event - which is true - instead of
        # `executed` with none, a completed call the ledger cannot prove.
        self._audit_tool(call, result, args_hash=args_hash, key=key, tier=tier, duration=duration)
        with tenant_connection(self._dsn, call.tenant_id) as conn:
            conn.execute(
                "UPDATE tool_calls SET status = %s, result = %s WHERE idempotency_key = %s",
                (result.status, json.dumps(result.output), key),
            )
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
        arguments, gated = self._recorded_arguments(call)
        payload: dict[str, Any] = {
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
            # Where the bytes the cap removed can be read back, when they were kept.
            "output_ref": result.output_ref,
            "output_stored": result.output_stored,
        }
        if arguments is not None:
            payload["arguments"] = arguments
        ref = self._audit.append(
            tenant_id=call.tenant_id,
            event_type="tool.call",
            actor_type="agent",
            actor_id=call.agent_id,
            payload=payload,
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
        # After the call it explains, so the record reads call then reason.
        if gated is not None:
            self._audit_dlp(call, [gated])

    def _recorded_arguments(
        self, call: ToolCall
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        """The canonical values a trajectory may assert on: gated, or absent.

        The ledger is append-only and never expires, so the copy is taken on the
        `record` surface - PII redacted in place, a credential blocks. A digest
        alone tells a grader a 60-second timeout happened, not whether it was 60.
        When the detector cannot answer, `args_hash` stays the only evidence: a
        value parked in the record unchecked is the leak this gate prevents.
        """
        try:
            text, report = dlp.gate(
                json.dumps(call.arguments, ensure_ascii=False),
                surface="record",
                analyzer_url=DLP_URL,
            )
        except dlp.DlpBlocked as exc:
            return None, exc.report

        try:
            values = json.loads(text)
        except ValueError:
            # A redaction broke the JSON: keep no values rather than a fragment.
            return None, {**report, "action": "block"}
        if not isinstance(values, dict):
            return None, {**report, "action": "block"}
        noted = report if report.get("action") != "pass" else None
        return values, noted

    def _settled(
        self, call: ToolCall, key: str, status: str, result: Any, tier: str
    ) -> ToolResult | None:
        """What a repeated attempt may do with a key that already exists.

        None means the earlier attempt provably never reached the tool, so
        attempting again is safe. A `sent` row on a write is the one case where
        the outcome is genuinely unknown.
        """
        if status in {"executed", "replayed", "failed"}:
            return _replayed(call, key, result or {})
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
        if not call.approval_ref:
            return ToolResult(
                status="denied",
                tool=call.tool,
                rule_id="approval.missing_ref",
                detail="T1 execution requires an approved action reference",
            )
        body = json.dumps(
            {
                "tenant_id": call.tenant_id,
                "run_id": call.run_id,
                "tool": call.tool,
                "arguments": call.arguments,
                "approval_ref": call.approval_ref,
            }
        ).encode()
        return self._post(f"{self._operator_url}/execute", body, call)

    def _invoke_sandbox(self, call: ToolCall) -> ToolResult:
        body = json.dumps(
            {"agent": call.agent_id, "tool": call.tool, "arguments": call.arguments}
        ).encode()
        # The runner verifies this token and takes the agent from its claims; a
        # run with no token is refused there with 401, never executed unauthenticated.
        headers = {"Authorization": f"Bearer {call.run_token}"} if call.run_token else None
        return self._post(f"{self._runner_url}/execute", body, call, headers=headers)

    def _post(
        self, url: str, body: bytes, call: ToolCall, *, headers: dict[str, str] | None = None
    ) -> ToolResult:
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", **(headers or {})},
            method="POST",
        )
        try:
            with open_url(request, timeout=60) as response:
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
            rule = "tool.refused" if exc.code in (401, 403, 409) else "tool.error"
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
        capped, output_ref, stored = cap_and_offload(self._dsn, call, payload)
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="tool.executed",
            detail=f"{call.tool} executed as {payload.get('allowlist_id')}",
            output=capped,
            output_sha256=str(capped.get("output_sha256", "")),
            output_bytes=int(capped.get("original_bytes", 0)),
            output_truncated=bool(capped.get("truncated", False)),
            output_ref=output_ref,
            output_stored=stored,
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
