# Service metrics

Prometheus exposition for the controls and the money. Metrics are service-level
telemetry, not a security control (ADR-015): a metrics failure never changes a
decision, and nothing here replaces the audit ledger.

## Scrape targets

| Target | URL | Notes |
|---|---|---|
| API | `http://api:8000/metrics` | Also `http://localhost:18000/metrics` on the host, because the API is published there |
| Orchestrator worker | `http://worker-orchestrator:9100/metrics` | Model calls, tokens, cost, cache, run outcomes |
| Tool workers | `http://worker-docker:9100/metrics`, `http://worker-github:9100/metrics`, `http://worker-researcher:9100/metrics` | Policy denials, DLP blocks, tool calls |

Each process exports its own registry. Nothing aggregates across workers, so a
Prometheus scrape config needs every target; `CITADEL_METRICS_PORT` sets the
worker port (default `9100`) and the worker logs a warning and keeps running if
the port cannot be bound.

## Authentication

Every `/metrics` endpoint requires `Authorization: Bearer <token>`, where the
token is the value of the `metrics_token` Docker secret
(`CITADEL_METRICS_TOKEN_FILE`). The API and each worker read it per request, so a
rotated file takes effect without a restart.

| Situation | Response |
|---|---|
| correct bearer token | `200` with the registry |
| missing or wrong token | `401`, `WWW-Authenticate: Bearer` |
| secret unset or unreadable | `503` - never an unauthenticated fallback |

The comparison is constant time; the token is never logged or returned. The
payload remains aggregate counters and histograms only: no tenant, user, run id,
prompt, tool argument or approval reason is a label.

Prometheus reads the same secret with `bearer_token_file`, not with a token
inline in `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: citadel-api
    authorization:
      type: Bearer
      credentials_file: /run/secrets/metrics_token
    static_configs:
      - targets: ["api:8000"]
```

The same block is needed for every worker target.

## Provisioning and rotation

`make up` runs `scripts/provision-secrets.sh`, which writes `secrets/metrics_token`.
If SOPS defines `CITADEL_METRICS_TOKEN`, that value wins; otherwise the script
generates one on first use and keeps it, so a later `make up` does not break a
Prometheus that is already scraping. To rotate, set a new value in
`secrets/citadel.env` (or delete `secrets/metrics_token`), run `make up`, and
restart Prometheus so it reloads the file. The API and workers pick it up per
request.

## Metrics

| Metric | Type | Labels | Source |
|---|---|---|---|
| `citadel_runs_total` | counter | `outcome` (`completed`, `denied`, `failed`, `cancelled`) | `finish_run` |
| `citadel_model_calls_total` | counter | `outcome` (`ok`, `unavailable`, `dlp_blocked`) | `next_step`, around the gateway call |
| `citadel_model_tokens_total` | counter | `kind` (`prompt`, `completion`) | gateway usage |
| `citadel_model_cost_reported_total` | counter | - | gateway usage with a reported cost |
| `citadel_model_cost_unreported_total` | counter | - | gateway usage with no cost |
| `citadel_model_cost_usd_total` | counter | - | sum of reported cost |
| `citadel_dlp_blocks_total` | counter | `surface` (`input`, `output`, `record`), `reason` (`dlp_blocked`, `dlp_unavailable`) | `dlp.gate` |
| `citadel_policy_denials_total` | counter | `rule` (the bounded rule ids in `policy/authorize.py`) | `_deny` |
| `citadel_cache_lookups_total` | counter | `result` (`exact`, `semantic`, `miss`) | `ModelActivities._cached` |
| `citadel_approval_wait_seconds` | histogram | `decision` (`approved`, `denied`) | `close_request`, from the approval row's database clock |

A value outside its label set is recorded as `other`, so a request cannot create
an unbounded time series. A new policy rule counts under `other` until it is
named in `metrics.POLICY_RULES`.

## Cost semantics

A gateway that reported `0.0` increments `citadel_model_cost_reported_total` and
`citadel_model_cost_usd_total` (which stays at zero). A gateway that reported
nothing increments `citadel_model_cost_unreported_total` and leaves the USD
counter alone. A dashboard must show the unreported counter: "free" and "unknown"
are different answers, and summing only USD would hide the second.

## Cache metrics without a cache

The metric definitions exist whether or not a cache is configured. A model step
with no cache never enters `_cached`, so it emits no cache sample; a deployment
without one still scrapes every other metric. Cache samples appear only once
`ModelActivities` is given an `AnswerCache` (ADR-018 / #180).

## Grafana

No Grafana service or dashboard is shipped. The milestone makes Grafana optional;
add it behind a Compose profile once the dashboards exist, and read these metric
names rather than inventing new ones. A dashboard that sums reported USD without
the unreported counter repeats the cost mistake above.
