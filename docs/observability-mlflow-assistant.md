# The MLflow assistant, and why it goes through OmniRoute

MLflow 3.18 ships an assistant panel. Its built-in providers are `claude_code`,
`codex`, `mlflow_gateway` and `ollama`; a Gemini or opencode-go endpoint typed into
the panel cannot work here, and the failure has nothing to do with the endpoint:

```
$ docker exec citadel-mlflow-1 python3 -c "import socket; socket.create_connection(('generativelanguage.googleapis.com', 443), 4)"
gaierror: [Errno -3] Temporary failure in name resolution
$ ... socket.create_connection(('1.1.1.1', 443), 4)
OSError: [Errno 101] Network is unreachable
$ ... socket.create_connection(('omniroute', 20128), 4)
ok
```

`citadel_internal` is `internal: true`. MLflow has no external DNS and no route off the
stack, by design: it is a store, and ADR-017 keeps it that way. So the assistant's model
access takes the path the rest of the platform already uses:

```
assistant panel
  -> mlflow_gateway provider            (server's own address)
  -> POST /gateway/mlflow/v1/chat/completions      (in-server AI Gateway)
  -> endpoint "omniroute"  ->  model definition (provider openai, model auto/best-fast)
  -> http://omniroute:20128/v1          (the stack's single egress)
  -> the upstream provider
```

MLflow never gains an egress route; OmniRoute stays the only thing that talks to the
internet.

## What has to be true

`compose.yaml`, on the `mlflow` service:

| variable | why |
| --- | --- |
| `MLFLOW_ENABLE_AI_GATEWAY=true` | mounts `/gateway/...`; without it the assistant has no provider it can reach |
| `MLFLOW_GATEWAY_API_BASE_ALLOW_PRIVATE_IPS=true` | the gateway refuses a private upstream by default (SSRF guard); OmniRoute is private on purpose |
| `MLFLOW_GATEWAY_API_BASE_ALLOWED_SCHEMES=https,http` | the default allowlist is https-only, and a sibling service speaks http |
| `OMNIROUTE_API_KEY` | the gateway's secret is created from it |

Then:

```
make mlflow-gateway
```

which runs `scripts/mlflow-gateway-bootstrap.py` **inside** the mlflow container (assistant
settings can only be changed by a loopback caller) and does four idempotent things:

1. secret `omniroute` — `api_key` in `secret_value`, `api_base` in `auth_config`. The server
   rejects `api_base` in `secret_value`: it chooses where requests go, so it is not treated
   as a credential.
2. model definition `omniroute-fast` — provider `openai`, model `auto/best-fast`.
3. endpoint `omniroute` — one `PRIMARY` mapping to that definition.
4. assistant selection — provider `mlflow_gateway`, model `omniroute`.

If the provider is `openai` pointed at OmniRoute rather than a vendor name, it is because
MLflow only knows how to speak OpenAI-compatible HTTP to an arbitrary host that way;
anything else (`opencode_go`, for instance) falls through to LiteLLM, which is not installed
in the server image — and which this project does not want (see the dependency stance in
ADR-004).

## Verifying

```
$ make mlflow-gateway
gateway setup: http://omniroute:20128/v1 model=auto/best-fast
  secret omniroute: exists
  model definition omniroute-fast: exists
  endpoint omniroute: exists
  assistant: already pointed at the gateway endpoint
  chat through omniroute: 200 -> ok
```

The last line is the whole chain in one call: gateway, endpoint, OmniRoute, upstream model.

## Known limitation

The assistant's provider selection is per-user state under `~/.mlflow/assistant/` **inside
the container**, not on the `mlflow-data` volume. A `--force-recreate` therefore forgets it;
`make mlflow-gateway` puts it back, which is why it is safe (and cheap) to run after any
`docker compose up`.
