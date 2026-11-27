# Starting a run

There is no run button in the MLflow UI, and there is not meant to be. A run starts on the
Citadel API and MLflow only records what the run produces:

```
keycloak (identity)  ->  POST /runs  ->  Temporal workflow  ->  model, policy, tools
                                              |
                                              +-> OTLP spans -> MLflow trace
                                              +-> audit_events ledger
```

```bash
cd ~/projects/citadel
set -a; . ./.env; set +a

scripts/start-run.py --task "Call inspect_containers, then name one running container." --wait
# run 4f61bb68-7044-4f24-ae22-0c6389690880 created for alice (docker, docker-1.1.0)
# run 4f61bb68-7044-4f24-ae22-0c6389690880: completed
```

`make run TASK="…"` is the same thing, and `make token` prints a bearer token when you want
`curl` instead.

## What the request carries

| field | why it is required |
| --- | --- |
| `agent_id` | selects the skill pack; an unknown one is a 400, not a fallback |
| `prompt_pack_version` | must be the pack's real name, or provenance lies |
| `model_alias` | what OmniRoute is asked for; the trajectory records the alias, not a vendor model |
| `risk_tier` | decides the approval path for side-effecting tools |
| `task` | the work. **Empty means no workflow starts** — the API only records the run, which is what the tenancy and policy tests need |

The tenant and the user are **not** body fields. They come from the Keycloak token, so a
caller cannot submit a run as somebody else.

## Where the credentials come from

Four requests deep, which is why this is scripted: an admin token on the `master` realm, the
`citadel-api` client secret read from Keycloak's admin API, a password grant for the dev
user, then the run. Nothing in the repo holds the client secret — only
`secrets/keycloak_admin_password` exists, and it lets the script read the other one.

| setting | source |
| --- | --- |
| `KEYCLOAK_PUBLIC_URL` | default `http://localhost:18081` |
| `KEYCLOAK_REALM` / `KEYCLOAK_CLIENT_ID` | default `citadel` / `citadel-api` |
| `KEYCLOAK_ADMIN_USER`, `KEYCLOAK_ADMIN_PASSWORD` | `.env`, else `secrets/keycloak_admin_password` |
| `CITADEL_DEV_PASSWORD` | `.env`, else `secrets/citadel_dev_password` |
| `CITADEL_API_URL` | default `http://127.0.0.1:18000` |

## Watching it

- **MLflow** — `citadel-trajectories` experiment, `Traces` tab: the run's spans, newest first.
  The trace id begins with the run id, so the two are easy to pair.
- **Temporal** — `http://localhost:18080`, workflow id = run id.
- **Ledger** — `make audit-verify` walks the hash chain for a tenant.

A task runs a model, so a run costs a fraction of a cent of OmniRoute traffic.
