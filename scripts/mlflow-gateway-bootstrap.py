#!/usr/bin/env python3
"""Give the in-server MLflow AI Gateway one endpoint, and point the assistant at it.

Why the assistant could not work before this: it is a container on `citadel_internal`
(`internal: true`), so it has no external DNS and no route off the stack —

    generativelanguage.googleapis.com:443   gaierror: Temporary failure in name resolution
    1.1.1.1:443                             OSError: Network is unreachable
    omniroute:20128                         reachable

A Gemini or opencode-go endpoint configured in the UI therefore fails at name resolution
before a token is sent. The route that works is the one the stack already has: the
assistant's `mlflow_gateway` provider calls this server's own gateway
(`/gateway/mlflow/v1/chat/completions`), and that gateway calls OmniRoute, the single
egress. Nothing about MLflow's position on the network changes.

Run it inside the mlflow container (it must be a loopback caller to change assistant
settings):

    make mlflow-gateway

Idempotent: an existing secret, model definition, endpoint and assistant selection are
left alone, so it is safe to run after every `docker compose up`.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

BASE = "http://127.0.0.1:5000"
SECRET_NAME = "omniroute"
DEFINITION_NAME = "omniroute-fast"
ENDPOINT_NAME = "omniroute"


def open_request(request: urllib.request.Request) -> bytes:
    """Send it and hand back the body. The one place a connection is opened."""
    # The rule's premise is an actor-controlled URL. This one cannot be: the host is the
    # module constant BASE (loopback), the scheme is fixed by it, and every path is a
    # literal in this file. Nothing here accepts a host, a scheme or a file path.
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read()


def post(path: str, body: dict[str, Any] | None = None, *, method: str = "POST") -> tuple[int, Any]:
    """One call to this server, with the error body kept instead of raised."""
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        BASE + path, data=data, method=method, headers={"Content-Type": "application/json"}
    )
    try:
        return 200, json.loads(open_request(request) or b"{}")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode(errors="replace")
        try:
            return exc.code, json.loads(raw)
        except json.JSONDecodeError:
            return exc.code, {"raw": raw[:400]}


def named(payload: dict[str, Any], key: str) -> dict[str, str]:
    """`{name: id}` for a list endpoint, so existence checks need no extra parsing."""
    return {
        str(item.get("name") or item.get("secret_name")): str(
            item.get("secret_id") or item.get("model_definition_id") or item.get("endpoint_id")
        )
        for item in payload.get(key) or []
    }


def ensure_secret(api_key: str, api_base: str) -> str:
    _, listing = post("/api/3.0/mlflow/gateway/secrets/list", method="GET")
    known = named(listing, "secrets")
    if SECRET_NAME in known:
        print("  gateway key: exists")
        return known[SECRET_NAME]
    status, created = post(
        "/api/3.0/mlflow/gateway/secrets/create",
        {
            "secret_name": SECRET_NAME,
            "secret_value": {"api_key": api_key},
            # api_base is a routing decision, not a credential: the server rejects it in
            # secret_value and requires it here.
            "auth_config": {"api_base": api_base},
            "provider": "openai",
        },
    )
    print(f"  gateway key: created ({status})")
    return str((created.get("secret") or {}).get("secret_id") or "")


def ensure_definition(secret_id: str, model_name: str) -> str:
    _, listing = post("/api/3.0/mlflow/gateway/model-definitions/list", method="GET")
    known = named(listing, "model_definitions")
    if DEFINITION_NAME in known:
        print(f"  model definition {DEFINITION_NAME}: exists")
        return known[DEFINITION_NAME]
    status, created = post(
        "/api/3.0/mlflow/gateway/model-definitions/create",
        {
            "name": DEFINITION_NAME,
            "secret_id": secret_id,
            "provider": "openai",
            "model_name": model_name,
        },
    )
    print(f"  model definition {DEFINITION_NAME}: created ({status})")
    return str((created.get("model_definition") or {}).get("model_definition_id") or "")


def ensure_endpoint(definition_id: str) -> None:
    _, listing = post("/api/3.0/mlflow/gateway/endpoints/list", method="GET")
    if ENDPOINT_NAME in named(listing, "endpoints"):
        print(f"  endpoint {ENDPOINT_NAME}: exists")
        return
    status, _ = post(
        "/api/3.0/mlflow/gateway/endpoints/create",
        {
            "name": ENDPOINT_NAME,
            "model_configs": [{"model_definition_id": definition_id, "linkage_type": "PRIMARY"}],
        },
    )
    print(f"  endpoint {ENDPOINT_NAME}: created ({status})")


def ensure_assistant() -> None:
    _, current = post("/ajax-api/3.0/mlflow/assistant/config", method="GET")
    chosen = (current.get("providers") or {}).get("mlflow_gateway") or {}
    if chosen.get("selected") and chosen.get("model") == ENDPOINT_NAME:
        print("  assistant: already pointed at the gateway endpoint")
        return
    status, _ = post(
        "/ajax-api/3.0/mlflow/assistant/config",
        {"providers": {"mlflow_gateway": {"selected": True, "model": ENDPOINT_NAME}}},
        method="PUT",
    )
    print(f"  assistant: pointed at {ENDPOINT_NAME} ({status})")


def report() -> int:
    """One chat completion through the whole chain, so the claim is measured."""
    status, payload = post(
        "/gateway/mlflow/v1/chat/completions",
        {
            "model": ENDPOINT_NAME,
            "messages": [{"role": "user", "content": "Answer with exactly: ok"}],
            "max_tokens": 16,
        },
    )
    choices = (payload or {}).get("choices") or []
    answer = choices[0]["message"]["content"] if choices else json.dumps(payload)[:200]
    print(f"  chat through {ENDPOINT_NAME}: {status} -> {str(answer)[:80]}")
    return 0 if status == 200 else 1


DEFAULT_KEY_FILE = "/run/secrets/omniroute_api_key"


def secret_key() -> str:
    """The OmniRoute key: an environment value if one was given, else the mounted file.

    The stack hands credentials over as files (`<NAME>_FILE`), so the file is the normal
    case; the environment branch exists for a one-off run with `docker exec -e`.
    """
    direct = os.environ.get("OMNIROUTE_API_KEY", "").strip()
    if direct:
        return direct
    candidates = [os.environ.get("OMNIROUTE_API_KEY_FILE", ""), DEFAULT_KEY_FILE]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).read_text(encoding="utf-8").strip()
    return ""


def main() -> int:
    api_key = secret_key()
    api_base = os.environ.get("OMNIROUTE_BASE_URL", "http://omniroute:20128/v1")
    model_name = os.environ.get("MODEL_ALIAS_FAST", "auto/best-fast")
    if not api_key:
        print(f"no OmniRoute key: set OMNIROUTE_API_KEY or mount {DEFAULT_KEY_FILE}", file=sys.stderr)
        return 2
    print(f"gateway setup: {api_base} model={model_name}")
    secret_id = ensure_secret(api_key, api_base)
    if not secret_id:
        print("no secret id: stopping", file=sys.stderr)
        return 1
    definition_id = ensure_definition(secret_id, model_name)
    if not definition_id:
        print("no model definition id: stopping", file=sys.stderr)
        return 1
    ensure_endpoint(definition_id)
    ensure_assistant()
    return report()


if __name__ == "__main__":
    raise SystemExit(main())
