"""OpenAI-compatible client for OmniRoute, with the prompt gated before send.

Two properties matter more than the wire format:

* the prompt is inspected before it leaves the process, so a credential in a
  user message blocks the call instead of travelling to a provider;
* cost is whatever the gateway reported. When it reports nothing the cost is
  `None`, and no caller may treat that as zero.

No SDK on purpose. The gateway speaks plain JSON over HTTP, and a client
library for it is a supply-chain surface with no offsetting benefit here.
"""

from __future__ import annotations

import json
import time
import urllib.error
from collections.abc import Callable, Mapping, Sequence
from typing import Any
from urllib.request import Request, urlopen

from citadel import dlp
from citadel.model.types import Reply, RequestedTool, Usage

DEFAULT_TIMEOUT_SECONDS = 60
Opener = Callable[..., Any]


class ModelUnavailable(RuntimeError):
    """The gateway could not answer. The run must not pretend that it did."""


def parse_usage(raw: object) -> Usage:
    """Read the usage block, including the gateway's own cost figure."""
    if not isinstance(raw, Mapping):
        return Usage()
    prompt = _int(raw.get("prompt_tokens"))
    completion = _int(raw.get("completion_tokens"))
    details = raw.get("prompt_tokens_details")
    cached = _int(details.get("cached_tokens")) if isinstance(details, Mapping) else 0
    cost = raw.get("cost")
    cost_usd: float | None = None
    if isinstance(cost, (int, float)) and not isinstance(cost, bool):
        cost_usd = float(cost)
    return Usage(
        prompt_tokens=prompt,
        completion_tokens=completion,
        cached_tokens=cached,
        cost_usd=cost_usd,
        cost_source="reported" if cost_usd is not None else "unreported",
    )


def parse_reply(payload: Mapping[str, Any], *, latency_ms: int) -> Reply:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ModelUnavailable("gateway returned no choices")
    first = choices[0]
    if not isinstance(first, Mapping):
        raise ModelUnavailable("gateway returned a malformed choice")
    message = first.get("message")
    if not isinstance(message, Mapping):
        raise ModelUnavailable("gateway returned a choice without a message")

    tools: list[RequestedTool] = []
    raw_calls = message.get("tool_calls")
    if isinstance(raw_calls, list):
        for item in raw_calls:
            if not isinstance(item, Mapping):
                continue
            function = item.get("function")
            if not isinstance(function, Mapping):
                continue
            tools.append(
                RequestedTool(
                    name=str(function.get("name", "")),
                    arguments=_arguments(function.get("arguments")),
                    call_id=str(item.get("id", "")),
                )
            )

    content = message.get("content")
    return Reply(
        content="" if content is None else str(content),
        tools=tuple(tools),
        usage=parse_usage(payload.get("usage")),
        model=str(payload.get("model", "")),
        latency_ms=latency_ms,
    )


def _arguments(raw: object) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    if isinstance(raw, str) and raw.strip():
        try:
            loaded = json.loads(raw)
        except ValueError:
            return {}
        if isinstance(loaded, Mapping):
            return dict(loaded)
    return {}


def _int(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


class OmniRouteClient:
    """`complete` is the only method; the loop owns everything else."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        analyzer_url: str,
        alias: str = "auto/best-fast",
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        opener: Opener | None = None,
    ) -> None:
        # OMNIROUTE_URL is documented as the OpenAI base (http://host:port/v1);
        # accept both forms so a correct config and a bare host both work.
        trimmed = base_url.rstrip("/")
        if trimmed.endswith("/v1"):
            trimmed = trimmed[: -len("/v1")]
        self.base_url = trimmed
        self.api_key = api_key
        self.analyzer_url = analyzer_url
        self.alias = alias
        self.timeout = timeout
        self._opener: Opener = opener or urlopen

    def complete(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] = (),
        alias: str | None = None,
        run_id: str = "",
    ) -> Reply:
        # A credential typed into a prompt is exactly what this blocks: the
        # conversation never reaches the provider with a live token in it.
        dlp.gate(
            _conversation_text(messages),
            surface="input",
            analyzer_url=self.analyzer_url,
            opener=self._opener,
        )
        payload: dict[str, Any] = {
            "model": alias or self.alias,
            "messages": [dict(message) for message in messages],
        }
        if tools:
            payload["tools"] = [dict(tool) for tool in tools]

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }
        if run_id:
            # Lets the gateway's own usage log be joined back to a Citadel run.
            headers["X-Correlation-Id"] = run_id

        request = Request(
            f"{self.base_url}/v1/chat/completions",
            data=json.dumps(payload).encode(),
            headers=headers,
            method="POST",
        )
        started = time.monotonic()
        try:
            with self._opener(request, timeout=self.timeout) as response:
                raw = response.read()
        except (urllib.error.URLError, OSError) as exc:
            raise ModelUnavailable(f"gateway unreachable: {exc}") from exc
        latency_ms = int((time.monotonic() - started) * 1000)

        try:
            body = json.loads(raw)
        except ValueError as exc:
            raise ModelUnavailable("gateway returned unparseable JSON") from exc
        if not isinstance(body, Mapping):
            raise ModelUnavailable("gateway returned an unexpected payload")
        error = body.get("error")
        if error is not None:
            raise ModelUnavailable(f"gateway error: {str(error)[:300]}")

        return parse_reply(body, latency_ms=latency_ms)


def _conversation_text(messages: Sequence[Mapping[str, Any]]) -> str:
    """Only what a person or system prompt contributed; tool output is gated on arrival."""
    return "\n".join(
        str(message.get("content") or "")
        for message in messages
        if message.get("role") in {"system", "user"}
    )
