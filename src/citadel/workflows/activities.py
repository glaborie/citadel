"""Activities: the only places that touch policy, the database or tools.

Every activity is synchronous and idempotent from Temporal's point of view:
the tool call is keyed, so a retry after a crash cannot produce a second side
effect. Whether a repeated attempt may re-run depends on how far the earlier
attempt got, which is what the `sent` marker records.
"""

from __future__ import annotations

import hashlib
import json
import logging
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
from citadel.evals import online as eval_online
from citadel.evals.recorder import export_run
from citadel.hashing import arguments_hash
from citadel.net import open_url
from citadel.policy import AuthorizationRequest, RelationChecker, RunStore, authorize
from citadel.policy.catalog import ToolSpec, load_catalog
from citadel.research import external_flags, label_untrusted
from citadel.research.client import ResearchError, ResearchRefused, search_web
from citadel.research.client import fetch_page as fetch_remote_page
from citadel.telemetry import record_span
from citadel.tools.bounds import DEFAULT_EVENT_LIMIT, bound
from citadel.workflows.types import PolicyOutcome, RunEnd, ToolCall, ToolResult

DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")
SEARXNG_URL = os.environ.get("CITADEL_SEARXNG_URL", "http://searxng:8080")
FETCHER_URL = os.environ.get("CITADEL_FETCHER_URL", "http://fetcher:8040")
# A tool result is part of the activity's return value, which Temporal
# stores in event history: an uncapped 64 KB body becomes 64 KB of history
# per call, and a few calls reach the 256 KB warning.
EVENT_OUTPUT_LIMIT = int(os.environ.get("CITADEL_EVENT_OUTPUT_MAX_BYTES", DEFAULT_EVENT_LIMIT))


@dataclass(frozen=True)
class Bounded:
    """What the record carries, and what the cap pushed out of it."""

    payload: dict[str, Any]
    dropped: dict[str, str]


@dataclass(frozen=True)
class WebContent:
    """What a research service answered, before the output gate."""

    rule_id: str
    text: str
    source: str


def _web_payload(content: WebContent, flags: list[str]) -> dict[str, Any]:
    return {
        "stdout": label_untrusted(content.text, source=content.source),
        "source": content.source,
        "content_flags": flags,
    }


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


def _stored_flags(stored: dict[str, Any]) -> list[str]:
    flags = stored.get("content_flags")
    if not isinstance(flags, list):
        return []
    return [str(flag) for flag in flags if isinstance(flag, str)]


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
        content_flags=_stored_flags(stored),
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


def _gated_values(
    text: str, report: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """The redacted JSON a gate returned, or no values and an event saying why."""
    try:
        values = json.loads(text)
    except ValueError:
        # A redaction broke the JSON: keep no values rather than a fragment.
        return None, {**report, "action": "block"}
    if not isinstance(values, dict):
        return None, {**report, "action": "block"}
    return values, (report if report.get("action") != "pass" else None)


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

    def _recorded_output(
        self, result: ToolResult
    ) -> tuple[dict[str, Any] | None, dict[str, Any] | None, str]:
        """The tool's answer as the record may keep it, and why if it does not.

        Mirrors `_recorded_arguments`: the ledger is append-only, so it takes the same
        gate, and a body the detector blocks is not carried at all - the digest and the
        event remain. Oversized is not the same as refused: a 200 KB body the record
        cannot hold is marked as such, because "no output" and "output too large to
        keep" are different facts about a run and a grader has to tell them apart.
        """
        if not result.output:
            return None, None, "absent"
        text = json.dumps(result.output, ensure_ascii=False)
        if len(text.encode("utf-8")) > EVENT_OUTPUT_LIMIT:
            return None, None, "too_large"
        try:
            gated, report = dlp.gate(text, surface="record", analyzer_url=DLP_URL)
        except dlp.DlpBlocked as exc:
            return None, exc.report, "redacted"
        values, event = _gated_values(gated, report)
        if values is None:
            return None, event, "redacted"
        return values, event, "kept"

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
        output, output_event, disposition = self._recorded_output(result)
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
            "content_flags": result.content_flags,
        }
        if arguments is not None:
            payload["arguments"] = arguments
        if disposition == "kept" and output is not None:
            payload["output"] = output
        elif disposition == "redacted":
            payload["output_redacted"] = True
        elif disposition == "too_large":
            payload["output_too_large"] = True
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
        if output_event is not None:
            self._audit_dlp(call, [output_event])

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
        return _gated_values(text, report)

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
        if spec is not None and spec.transport == "http":
            return self._invoke_web(call, spec)
        if spec is not None and spec.tier == "T1":
            return self._invoke_operator(call)
        return self._invoke_sandbox(call)

    def _invoke_web(self, call: ToolCall, spec: ToolSpec) -> ToolResult:
        """Search or fetch, with the same policy, DLP and caps as a CLI tool.

        The URL guard and the byte cap live in the fetcher; this method owns the
        half the sandbox would otherwise own: the input gate, the output gate
        (credential blocks, PII redacts), the label that reaches the model and
        the statement the trajectory keeps.
        """
        denied = self._web_owner(call, spec)
        if denied is not None:
            return denied
        blocked = self._web_input(call)
        if blocked is not None:
            return blocked
        content = self._web_fetch(call, spec)
        if isinstance(content, ToolResult):
            return content
        gated = self._web_output(call, content.text)
        if isinstance(gated, ToolResult):
            return gated
        text, flags = gated
        return self._web_record(call, spec, replace(content, text=text), flags)

    def _web_owner(self, call: ToolCall, spec: ToolSpec) -> ToolResult | None:
        if spec.agent == call.agent_id:
            return None
        return ToolResult(
            status="denied",
            tool=call.tool,
            rule_id="tool.agent_mismatch",
            detail=f"{call.tool} belongs to the {spec.agent} agent",
        )

    def _web_input(self, call: ToolCall) -> ToolResult | None:
        raw_arguments = json.dumps(call.arguments, ensure_ascii=False)
        try:
            _, report = dlp.gate(raw_arguments, surface="input", analyzer_url=DLP_URL)
        except dlp.DlpBlocked as exc:
            self._audit_dlp(call, [exc.report])
            return ToolResult(
                status="denied",
                tool=call.tool,
                rule_id="dlp.unavailable" if exc.reason == "dlp_unavailable" else "dlp.blocked",
                detail="DLP refused this research call before it left the worker",
            )
        self._audit_dlp(call, [report])
        return None

    def _web_fetch(self, call: ToolCall, spec: ToolSpec) -> ToolResult | WebContent:
        try:
            if spec.service == "searxng":
                return self._web_search(call)
            if spec.service == "fetcher":
                return self._web_page(call)
        except ResearchRefused as exc:
            return self._web_error(call, "research.url_refused", str(exc), status="denied")
        except ResearchError as exc:
            return self._web_error(call, "research.unavailable", str(exc))
        return self._web_error(
            call, "research.unconfigured", f"{call.tool} names no research service"
        )

    def _web_error(
        self, call: ToolCall, rule_id: str, detail: str, *, status: str = "failed"
    ) -> ToolResult:
        return ToolResult(status=status, tool=call.tool, rule_id=rule_id, detail=detail[:300])

    def _web_search(self, call: ToolCall) -> WebContent:
        query = str(call.arguments.get("query", ""))
        text = search_web(query, base_url=SEARXNG_URL)
        return WebContent(rule_id="research.search", text=text, source="")

    def _web_page(self, call: ToolCall) -> WebContent:
        url = str(call.arguments.get("url", ""))
        page = fetch_remote_page(url, base_url=FETCHER_URL)
        text = str(page["text"])
        if page.get("truncated"):
            text += "\n\n[the fetcher stopped at its byte cap; this page is truncated]"
        return WebContent(rule_id="research.fetch", text=text, source=str(page.get("url", "")))

    def _web_output(self, call: ToolCall, text: str) -> ToolResult | tuple[str, list[str]]:
        try:
            text, report = dlp.gate(text, surface="output", analyzer_url=DLP_URL)
        except dlp.DlpBlocked as exc:
            self._audit_dlp(call, [exc.report])
            return ToolResult(
                status="denied",
                tool=call.tool,
                rule_id="dlp.unavailable" if exc.reason == "dlp_unavailable" else "dlp.blocked",
                detail="DLP refused the fetched content before it entered context",
            )
        self._audit_dlp(call, [report])
        return text, external_flags(text)

    def _web_record(
        self,
        call: ToolCall,
        spec: ToolSpec,
        content: WebContent,
        flags: list[str],
    ) -> ToolResult:
        capped, output_ref, stored = cap_and_offload(self._dsn, call, _web_payload(content, flags))
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id=content.rule_id,
            detail=f"{call.tool} answered through {spec.service}",
            output=capped,
            output_sha256=str(capped.get("output_sha256", "")),
            output_bytes=int(capped.get("original_bytes", 0)),
            output_truncated=bool(capped.get("truncated", False)),
            output_ref=output_ref,
            output_stored=stored,
            content_flags=flags,
        )

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
        try:
            _offer_online_sample(end=end, dsn=self._dsn, audit=self._audit)
        except Exception as exc:  # noqa: BLE001 - the run is over; a sampler cannot fail it
            logging.getLogger(__name__).warning(
                "online eval sample skipped for %s: %s", end.run_id, exc
            )


def _record_gate(text: str) -> tuple[str, dict[str, Any]]:
    """The `record` DLP surface, as the eval export uses it."""
    return dlp.gate(text, surface="record", analyzer_url=DLP_URL)


def _sample_counts(*, dsn: str, tenant_id: str, day: str) -> tuple[int, list[tuple[Any, ...]]]:
    """How many rows this tenant already has today, and the newest dataset id."""
    with tenant_connection(dsn, tenant_id) as conn:
        taken = conn.execute(
            "SELECT count(*) FROM audit_events WHERE tenant_id = %s"
            " AND event_type = 'eval.sample' AND payload->>'day' = %s",
            (tenant_id, day),
        ).fetchone()
        rows = conn.execute(
            "SELECT seq, payload FROM audit_events WHERE tenant_id = %s"
            " AND event_type = 'eval.sample' ORDER BY seq DESC LIMIT 1",
            (tenant_id,),
        ).fetchall()
    return (int(taken[0]) if taken else 0), list(rows)


def _sample_meta(events: list[dict[str, Any]]) -> eval_online.Meta:
    """The run's own metadata, plus the schema version and judge this export claims."""
    start = next((event for event in events if event.get("type") == "run.start"), {})
    judge = [item.strip() for item in os.environ.get("CITADEL_EVAL_JUDGE", "").split(",")]
    return eval_online.Meta(
        model_alias=str(start.get("model_alias", "")),
        prompt_pack_version=str(start.get("prompt_pack_version", "")),
        dataset_version=int(os.environ.get("CITADEL_EVAL_DATASET_VERSION", "1")),
        judge=tuple(item for item in judge if item),
    )


def _ledger_sample(
    *, end: RunEnd, dsn: str, policy: eval_online.Policy, taken: int
) -> eval_online.Sample:
    """The run as the exporter sees it: the ledger's trajectory, and its metadata."""
    events = export_run(dsn=dsn, tenant_id=end.tenant_id, run_id=end.run_id)
    return eval_online.Sample(
        events=events,
        tenant_id=end.tenant_id,
        run_id=end.run_id,
        meta=_sample_meta(events),
        policy=policy,
        taken=taken,
    )


def _sample_endpoint(*, rows: list[tuple[Any, ...]], tracking: str) -> eval_online.Endpoint:
    """Where the row goes: the id the last sample recorded, or a fresh dataset."""
    return eval_online.Endpoint(
        tracking_uri=tracking,
        experiment_id=os.environ.get("MLFLOW_EXPERIMENT_ID", "1"),
        dataset_id=eval_online.dataset_id_from(rows),
    )


def _audit_sample(
    *, end: RunEnd, outcome: tuple[dict[str, Any], eval_online.Endpoint],
    policy: eval_online.Policy, audit: AuditLedger,
) -> None:
    """The sampler's own ledger row: what was exported, and what the graders said."""
    record, endpoint = outcome
    failed = [item.grader for item in eval_online.replay(record) if not item.passed]
    audit.append(
        tenant_id=end.tenant_id,
        event_type="eval.sample",
        actor_type="agent",
        actor_id="orchestrator",
        payload={
            "run_id": end.run_id,
            "day": policy.day,
            "dataset_id": endpoint.dataset_id,
            "events": len(record["outputs"]["trajectory"]),
            "failed_graders": failed,
        },
    )


def _offer_online_sample(*, end: RunEnd, dsn: str, audit: AuditLedger) -> None:
    """ADR-017 decision 3: a deterministic, bounded sample of real runs into the dataset.

    Best-effort: the run has finished, so a failure here is a log line, not a failed
    activity. A refusal (a secret in the trajectory) is the sampler working.
    """
    policy = eval_online.policy_from_env()
    tracking = os.environ.get("MLFLOW_TRACKING_URI", "").rstrip("/")
    if policy.rate <= 0 or not tracking:
        return
    taken, rows = _sample_counts(dsn=dsn, tenant_id=end.tenant_id, day=policy.day)
    sample = _ledger_sample(end=end, dsn=dsn, policy=policy, taken=taken)
    endpoint = _sample_endpoint(rows=rows, tracking=tracking)
    outcome = eval_online.offer(sample, endpoint=endpoint, gate=_record_gate)
    if outcome is not None:
        _audit_sample(end=end, outcome=outcome, policy=policy, audit=audit)


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
