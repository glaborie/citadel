"""Gateway contract tests against the live OmniRoute instance.

These make real model calls, so they need an opt-in on top of the normal live
gate: the smoke completion is capped at 8 tokens, but it is still spend.

    set -a; . ./.env; set +a
    CITADEL_LIVE_TESTS=1 CITADEL_LLM_TESTS=1 uv run pytest tests/test_gateway_live.py -v

OmniRoute reports provider, tokens, cost and latency in x-omniroute-* headers,
which is exactly what the trajectory schema's model.call event needs.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1" or os.environ.get("CITADEL_LLM_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 and CITADEL_LLM_TESTS=1 to run gateway tests",
)

# OMNIROUTE_URL points at the compose service name, which does not resolve from
# the host where these tests run.
BASE = os.environ.get("OMNIROUTE_PUBLIC_URL", "http://127.0.0.1:20128/v1")


def _key() -> str:
    return os.environ["OMNIROUTE_API_KEY"]


def _request(
    path: str, body: dict[str, Any] | None = None, key: str | None = None
) -> tuple[int, dict[str, str], Any]:
    headers = {"Content-Type": "application/json"}
    if key is not None:
        headers["Authorization"] = f"Bearer {key}"
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers=headers,
        method="POST" if body is not None else "GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.status, dict(r.headers), json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()[:400]


def test_models_endpoint_requires_auth() -> None:
    """The gateway must not be readable without the minted key."""
    status, _headers, _body = _request("/models")
    assert status == 401


def test_models_endpoint_lists_models() -> None:
    status, _headers, body = _request("/models", key=_key())
    assert status == 200
    assert len(body["data"]) > 0


@pytest.mark.parametrize(
    "alias_var", ["MODEL_ALIAS_STRONG", "MODEL_ALIAS_FAST", "MODEL_ALIAS_JUDGE"]
)
def test_configured_alias_resolves_to_a_real_model(alias_var: str) -> None:
    """Regression guard: 'strong' is not a model id and returns 400."""
    alias = os.environ[alias_var]
    _status, _headers, body = _request("/models", key=_key())
    available = {m["id"] for m in body["data"]}
    assert alias in available, f"{alias_var}={alias!r} is not an OmniRoute model"


def test_chat_completion_returns_usage_and_provider() -> None:
    """A real call must yield the observability fields the trace schema needs."""
    status, headers, body = _request(
        "/chat/completions",
        {
            "model": os.environ["MODEL_ALIAS_FAST"],
            "messages": [{"role": "user", "content": "ok"}],
            "max_tokens": 8,
        },
        key=_key(),
    )
    assert status == 200, body
    assert body["choices"][0]["message"]["content"] is not None
    assert body["usage"]["total_tokens"] > 0

    lowered = {k.lower(): v for k, v in headers.items()}
    assert lowered.get("x-omniroute-provider"), (
        "no provider header; model.call event would be incomplete"
    )
    assert "x-omniroute-latency-ms" in lowered
    assert "x-omniroute-response-cost" in lowered


def test_unknown_alias_is_rejected_not_silently_substituted() -> None:
    """A bad alias must fail loudly rather than fall back to some other model."""
    status, _headers, body = _request(
        "/chat/completions",
        {"model": "strong", "messages": [{"role": "user", "content": "ok"}], "max_tokens": 4},
        key=_key(),
    )
    assert status == 400
    assert "provider" in str(body).lower()
