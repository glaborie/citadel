"""One model step, as an activity: the only place a workflow spends money.

The workflow owns sequencing - how many steps, when to delegate a tool call - and
this activity owns a single completion plus the controls around it: pack
provenance, a DLP gate on the task before anything leaves the process, a gate on
the reply before it enters context, and an audit event that carries the cost even
when the gateway refuses to report one.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from temporalio import activity

from citadel import dlp
from citadel.audit import AuditLedger
from citadel.env import optional_secret
from citadel.model import ModelUnavailable, OmniRouteClient, contains_tool_markup
from citadel.prompts import assemble
from citadel.telemetry import record_span

DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")
DEFAULT_ALIAS = os.environ.get("CITADEL_MODEL", "auto/best-fast")

ClientFactory = Callable[[str], Any]


def _client(alias: str) -> OmniRouteClient:
    return OmniRouteClient(
        base_url=os.environ.get("OMNIROUTE_URL", "http://omniroute:20128/v1"),
        api_key=optional_secret("OMNIROUTE_API_KEY"),
        analyzer_url=DLP_URL,
        alias=alias,
    )


@dataclass
class ModelStepRequest:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    task: str
    model_alias: str = ""
    pack_version: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ModelStepResult:
    status: str  # answered | tool_requested | refused | dlp_blocked | unavailable
    rule_id: str
    detail: str
    content: str = ""
    tool: str = ""
    arguments: dict[str, Any] = field(default_factory=dict)
    prompt_digest: str = ""
    prompt_pack: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cost_usd: float | None = None
    cost_source: str = "unreported"


def _messages(request: ModelStepRequest, system: str) -> list[dict[str, Any]]:
    """The pack's instructions, the task, then whatever the run has already seen."""
    turns: list[dict[str, Any]] = [
        {"role": "system", "content": system},
        {"role": "user", "content": request.task},
    ]
    turns.extend(request.history)
    return turns


class ModelActivities:
    def __init__(
        self,
        *,
        dsn: str,
        audit: AuditLedger,
        client_factory: ClientFactory | None = None,
        analyzer: Any = None,
    ) -> None:
        self._dsn = dsn
        self._audit = audit
        self._client_factory = client_factory or _client
        self._analyzer = analyzer

    def _gate(self, text: str, *, surface: str) -> dict[str, Any] | None:
        """Returns the refusal report, or None when the text may proceed."""
        try:
            _, report = dlp.gate(text, surface=surface, analyzer_url=DLP_URL, opener=self._analyzer)
        except dlp.DlpBlocked as exc:
            return dict(exc.report)
        return None

    def _record(self, request: ModelStepRequest, payload: dict[str, Any]) -> Any:
        # The trajectory schema requires the provenance fields on every
        # `model.call`, refusals included: a run that spent nothing still has to
        # say which prompt was attempted. Call sites override what they know.
        body: dict[str, Any] = {
            "alias": request.model_alias or DEFAULT_ALIAS,
            "provider": "omniroute",
            "tokens": 0,
            "cost": None,
            "latency": 0,
            "input_hash": _hash({"task": request.task, "history": request.history}),
            "output_hash": "",
            **payload,
        }
        return self._audit.append(
            tenant_id=request.tenant_id,
            event_type="model.call",
            actor_type="agent",
            actor_id=request.agent_id,
            payload={"run_id": request.run_id, **body},
        )

    def _refuse(
        self, request: ModelStepRequest, *, status: str, rule_id: str, detail: str
    ) -> ModelStepResult:
        self._record(request, {"status": status, "rule_id": rule_id, "detail": detail[:200]})
        return ModelStepResult(status=status, rule_id=rule_id, detail=detail)

    @activity.defn
    def next_step(self, request: ModelStepRequest) -> ModelStepResult:
        try:
            prompt = assemble(request.agent_id, request.task)
        except Exception as exc:  # noqa: BLE001 - an unverifiable pack is a refusal
            return self._refuse(
                request,
                status="refused",
                rule_id="pack.unavailable",
                detail=f"prompt pack could not be loaded: {exc}",
            )

        if request.pack_version and request.pack_version != prompt.pack_id:
            # A run names the pack it was approved against. Silently using a newer
            # one would make the trajectory's provenance a guess.
            return self._refuse(
                request,
                status="refused",
                rule_id="pack.version_mismatch",
                detail=f"run names {request.pack_version}, disk has {prompt.pack_id}",
            )

        blocked = self._gate(request.task, surface="input")
        if blocked is not None:
            self._record(request, {"status": "dlp_blocked", "surface": "input", **blocked})
            return ModelStepResult(
                status="dlp_blocked",
                rule_id="dlp.blocked",
                detail="the detector refused the task before any request left the process",
                prompt_digest=prompt.digest,
                prompt_pack=prompt.pack_id,
            )

        alias = request.model_alias or DEFAULT_ALIAS
        client = self._client_factory(alias)
        messages = _messages(request, prompt.system)
        try:
            reply = client.complete(messages=messages, tools=prompt.tools)
        except ModelUnavailable as exc:
            return self._refuse(
                request,
                status="unavailable",
                rule_id="model.unavailable",
                detail=f"the gateway did not answer: {exc}",
            )

        blocked = self._gate(reply.content, surface="output")
        if blocked is not None:
            self._record(
                request,
                {
                    "status": "dlp_blocked",
                    "surface": "output",
                    "model": reply.model,
                    "cost_usd": reply.usage.cost_usd,
                    "cost_source": reply.usage.cost_source,
                    **blocked,
                },
            )
            return ModelStepResult(
                status="dlp_blocked",
                rule_id="dlp.blocked",
                detail="the reply was refused at the output surface and never entered context",
                prompt_digest=prompt.digest,
                prompt_pack=prompt.pack_id,
            )

        tool = reply.tools[0] if reply.tools else None
        # An upstream that does not translate the pack's tools answers in prose
        # with its native markup. Treating that as an answer ends the run having
        # done nothing and puts the markup in front of a reader.
        markup = tool is None and contains_tool_markup(reply.content)
        if markup:
            status, rule_id = "refused", "model.tool_markup"
        elif tool is not None:
            status, rule_id = "tool_requested", "model.tool_requested"
        else:
            status, rule_id = "answered", "model.answered"
        ref = self._record(
            request,
            {
                "status": status,
                "rule_id": rule_id,
                "model": reply.model,
                "input_hash": _hash(messages),
                "output_hash": _hash(
                    {
                        "content": reply.content,
                        "tools": [
                            {"name": call.name, "arguments": call.arguments} for call in reply.tools
                        ],
                    }
                ),
                "tokens": reply.usage.total,
                "cost": reply.usage.cost_usd,
                "latency": reply.latency_ms,
                "prompt_pack": prompt.pack_id,
                "prompt_digest": prompt.digest,
                "prompt_tokens": reply.usage.prompt_tokens,
                "completion_tokens": reply.usage.completion_tokens,
                "cached_tokens": reply.usage.cached_tokens,
                "cost_usd": reply.usage.cost_usd,
                "cost_source": reply.usage.cost_source,
                "requested_tool": tool.name if tool is not None else "",
            },
        )
        record_span(
            "model.call",
            run_id=request.run_id,
            audit_id=getattr(ref, "audit_id", ""),
            model=reply.model,
            prompt_tokens=reply.usage.prompt_tokens,
            completion_tokens=reply.usage.completion_tokens,
            cached_tokens=reply.usage.cached_tokens,
            cost_usd=reply.usage.cost_usd if reply.usage.cost_usd is not None else -1.0,
            cost_source=reply.usage.cost_source,
            prompt_pack=prompt.pack_id,
        )
        return ModelStepResult(
            status=status,
            rule_id=rule_id,
            detail=(
                "the reply carried tool-call markup in content instead of tool_calls"
                if markup
                else f"{reply.model} answered in {reply.latency_ms} ms"
            ),
            content="" if markup else reply.content,
            tool=tool.name if tool is not None else "",
            arguments=dict(tool.arguments) if tool is not None else {},
            prompt_digest=prompt.digest,
            prompt_pack=prompt.pack_id,
            prompt_tokens=reply.usage.prompt_tokens,
            completion_tokens=reply.usage.completion_tokens,
            cost_usd=reply.usage.cost_usd,
            cost_source=reply.usage.cost_source,
        )


def _hash(value: Any) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def assistant_turn(reply: ModelStepResult) -> dict[str, Any]:
    """The reply as a message, so a later step can see what it said.

    The tool request is kept in prose: the next step needs to know which tool it
    asked for and what the platform answered, not a replayed tool-call object.
    """
    if reply.status == "tool_requested":
        return {
            "role": "assistant",
            "content": f"{reply.content}\\n[requested {reply.tool} with {sorted(reply.arguments)}]",
        }
    return {"role": "assistant", "content": reply.content}


def tool_turn(result: Mapping[str, Any]) -> dict[str, Any]:
    """Whatever came back from a delegated tool call, bounded and named.

    `role: "user"`, not `role: "tool"`: the assistant turn above is prose, so
    there is no `tool_call_id` for a provider to match, and an OpenAI-compatible
    endpoint rejects an orphan tool message with a 400 - which the gateway
    surfaces as a 502. The label keeps the provenance visible to the model.
    """
    return {
        "role": "user",
        "content": f"[tool result] {str(result.get('detail', ''))[:2_000]}",
    }
