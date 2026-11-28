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
| Pushgateway | `http://pushgateway:9091/metrics` | The host-side policy drift check pushes here (#285); job `citadel_policy_drift` |

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
| `citadel_runs_refused_total` | counter | - | `budgeted_principal`, when `POST /runs` returns `429` |
| `citadel_policy_drift` | gauge | - | `scripts/policy-drift-alert.py`, 1 when the last scheduled run found drift |
| `citadel_policy_drift_check_failed` | gauge | - | the same run, 1 when it could not compare (exit 2) |
| `citadel_policy_drift_last_run_timestamp_seconds` | gauge | - | the same run, so a job that stopped reporting is visible |

A value outside its label set is recorded as `other`, so a request cannot create
an unbounded time series. A new policy rule counts under `other` until it is
named in `metrics.POLICY_RULES`.

## Alerts

Prometheus evaluates the rules in `docker/prometheus/rules/citadel.yml`
(groups `citadel-ingress` and `citadel-policy-drift`), mounted read-only at
`/etc/prometheus/rules` and loaded by `rule_files` in `prometheus.yml`:

| Alert | Expression | For | Severity |
|---|---|---|---|
| `CitadelRunRefusalsSustained` | `sum(rate(citadel_runs_refused_total[5m])) * 60 > 5` | 10 m | `warning` |
| `CitadelPolicyDrift` | `max(citadel_policy_drift) > 0` | 1 m | `critical` |
| `CitadelPolicyDriftCheckFailed` | `max(citadel_policy_drift_check_failed) > 0` | 5 m | `warning` |
| `CitadelPolicyDriftStale` | `time() - max(citadel_policy_drift_last_run_timestamp_seconds) > 7200 or absent(citadel_policy_drift_last_run_timestamp_seconds)` | 10 m | `warning` |

The three policy-drift alerts come from a check that runs on the host, not in
the stack (#281), so their series arrive through `pushgateway` rather than a
scrape of a Citadel process. Drift and a check that cannot compare are separate
series on purpose: `CitadelPolicyDriftCheckFailed` firing must never be read as
"no drift" by a dashboard, and `CitadelPolicyDriftStale` exists because a job
that stopped reporting looks exactly like a store that matches.

That is more than five refusals per minute, averaged over five minutes, for ten
minutes. The per-credential budget defaults to 30 runs/min
(`CITADEL_RUNS_PER_MINUTE`), so one client sitting at its own limit does not
fire it: it takes several callers looping, or a budget set below the workload's
real rate. The rule names no tenant or user - the counter carries no such label,
by design - so the investigation starts from the API log and the audit ledger.

No Alertmanager ships with the stack, and nothing here may reach the internet
anyway. A firing alert therefore shows up in Prometheus' own `/alerts` page
(reachable through `make grafana-ui`) and in the dashboard's "Firing alerts"
panel, which charts the `ALERTS` series; paging delivery is an operator decision
for later, not something this repository implements.

The "Ingress refusals per minute" panel next to it draws the rule's own
expression with the threshold as a line, so the rate is visible before it is
sustained: `ALERTS` only turns red after `for:`, while the line shows how close
the traffic is to firing it.

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

`prometheus` and `grafana` are Compose services and start with the rest of the
stack: `make up`, or `docker compose up -d --wait prometheus grafana`. They are
not profile-gated, because the dashboard is the only view of these metrics.

| Item | Value |
|---|---|
| Scrape config | `docker/prometheus/prometheus.yml`, job `citadel` |
| Alert rules | `docker/prometheus/rules/citadel.yml`, group `citadel-ingress` |
| Targets | `api:8000` plus `worker-orchestrator`, `worker-docker`, `worker-github`, `worker-researcher` on `:9100` |
| Scrape interval | 15 s |
| Retention | 15 d (`--storage.tsdb.retention.time`), named volume `prometheus-data` |
| Dashboard | `docker/grafana/dashboards/citadel.json`, provisioned as "Citadel controls" |
| Grafana state | named volume `grafana-data` |
| Login | `admin`, password from `secrets/grafana_admin_password` |

Both containers sit on `internal` only. Prometheus publishes no port at all:
Grafana reads it through the proxy datasource. Grafana publishes none either,
because Docker binds nothing on an internal network. Reach the UI through the
loopback socat sidecar, the same pattern as `scripts/mlflow-ui.sh`:

```bash
make grafana-ui       # 127.0.0.1:13000 -> grafana:3000, then http://localhost:13000
make grafana-ui-off   # close it again
```

The sidecar listens on loopback only, so Grafana is not reachable from the edge
network or the LAN and the compose file itself stays closed. Anonymous access and
sign-up are off, and the admin password arrives as a Docker secret
(`GF_SECURITY_ADMIN_PASSWORD__FILE`), never as a plaintext env value.

The dashboard reads only the metric names above with their bounded labels: no
tenant, user, run id or prompt-derived series. The exceptions are Prometheus's
own series. `up`, in the "Scrape targets up" panel, exists before any run emits a
`citadel_*` sample, so "empty because nothing ran" is distinguishable from "the
scrape is broken". `ALERTS`, in "Firing alerts", is the only view of the rules
above from inside the dashboard, and it carries just the alert name and state.
The cost panel shows reported USD
and unreported calls side by side, so a dashboard cannot repeat the "free versus
unknown" mistake above.

The two policy-drift panels read the pushed gauges directly, without a query
(#298). "Policy drift verdict" shows `max(citadel_policy_drift)` beside
`max(citadel_policy_drift_check_failed)`: a green `0` next to a red
"could not compare" is the state a drift-only panel would have shown as healthy,
and the same mistake the alert rules avoid by keeping the series separate.
"Drift check last run age" shows
`time() - max(citadel_policy_drift_last_run_timestamp_seconds)` with thresholds
at one and two hourly runs, and both panels read "never reported" instead of an
empty `0` when the timer has not pushed yet.
