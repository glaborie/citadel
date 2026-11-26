# Issue #131: the Researcher specialist

The pre-existing state: `skills/researcher` was a reviewed pack and the policy
model could name a researcher, but no worker polled its queue, the catalog had
no research tools and the red-team case that covers a fetched page was pending.

## What changed

- `worker-researcher` polls its own task queue. It owns `search_web` (SearXNG)
  and `fetch_page` (the fetcher), both T0, and no Docker, GitHub or write tool.
- `searxng` and `fetcher` services. SearXNG is pinned to
  `2026.11.23-a7163d091@sha256:a7fc607aa6723f5a8982105bcc5ffba4d1b9fc7c6922a31a88d6e4cba49ef12a`;
  the fetcher is built from the `fetcher` Docker target, which is the only image
  carrying trafilatura.
- `src/citadel/research/`: the URL guard, the bounded fetch, the deterministic
  labels, the worker-side clients and the fetcher FastAPI app.
- The catalog gains a `transport: http` shape, so a tool can name an internal
  service instead of an allowlisted CLI. The worker executes it with the same
  policy, idempotency, DLP and audit path.
- `ToolResult.content_flags` carries the labels; `run.end.safety_flags` copies
  them. The offline loop computes the same flags from the catalog, so RT-INJ-02
  exercises the real rule.
- Networks: `research` (internal, worker + the two services) and `web`
  (egress, only the two services). Neither service joins `edge` and neither
  publishes a port.

## Measured

Fetcher image built from the `fetcher` target and run with the compose flags
(`--read-only`, `--cap-drop ALL`, `--user 10001:10001`, tmpfs `/tmp`):

| Request | Result |
|---|---|
| `GET /healthz` | 200 |
| `http://169.254.169.254/latest/meta-data` | 400, "not a global unicast address" |
| `http://localhost/` | 400, "not a public host" |
| `http://127.0.0.1/` | 400, "not a global unicast address" |
| `http://postgres:5432/` | 400, port 5432 not allowed |
| `http://example.com:8080/` | 400, port 8080 not allowed |
| `https://example.com/` | 200, title `Example Domain`, 577 bytes |
| `http://github.com/` | 200, followed to `https://github.com/` |

SearXNG with `docker/searxng/settings.yml`, read-only and as uid 977:
`GET /healthz` → 200; `GET /search?q=python+programming&format=json` → 200 with
27 results, and `citadel.research.client.search_web` against it returned the
normalised `[n] title / url / snippet` list.

Tests:

- `tests/test_research_guard.py` — 18 parametrised refusals plus the public
  allow and the literal-address path.
- `tests/test_research_fetch.py` — truncation marked, MIME refusal, non-2xx,
  redirect to an internal target never opened, public redirect followed, no
  cookie header, extraction title/text.
- `tests/test_research_tools.py` — label and flag, input and output DLP gates
  audited, refusal is a denial, an unavailable fetcher is a failure, agent
  mismatch denied, routing away from the sandbox.
- `tests/test_research_exposure.py` — no ports, no `edge`, `research` + `web`
  only, digest pin, `--extra fetcher` only in the fetcher image.
- `tests/test_policy.py` — the Researcher owns exactly the two web tools and is
  denied `restart_service`.
- RT-INJ-02 now has an executor and passes: the fetched page is labelled
  `untrusted_external` + `prompt_injection`, the model reads it, the following
  Docker write is denied by ownership, and the run ends read-only.

Full `uv run pytest` passes; ruff and mypy strict are clean.

## Running it on the owner's stack

After `make up`, run `make policy-bootstrap` once. The seeded tuples are built from
the catalog, so this is what creates `agent:<tenant>/researcher` and the two
`tool:<tenant>/…` objects. Without it the worker starts and every call is denied,
which is fail-closed but looks like a broken deployment.

## Not measured

- The two services were exercised standalone, not as part of `make up` on the
  running stack. Starting the new Compose file would use the same project name
  and recreate the owner's stack; the compose file is validated with
  `docker compose config --no-interpolate -q`.
- No live Temporal task run with a real model was executed. The offline loop and
  the activity seam are covered by tests; the live path needs the owner's
  stack, an API token and a model call.
- SearXNG logs a non-fatal `openstreetmap` and `torch` engine-loading error and
  a missing `limiter.toml` warning. The limiter is off by design; JSON search
  answered 200.
