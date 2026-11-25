# Issue #21: secrets out of the Docker-readable environment

The socket proxy exposes every container's `Config.Env` because `CONTAINERS=1`
allows the whole `/containers` surface, and the sandbox is the one component
that can reach the proxy. The fix has two halves: stop keeping secrets in env,
and stop the proxy from reading files inside a container.

## What changed

- The five values the probe named live in Docker secrets, mounted as files:
  `db_dsn`, `run_token_private_key`, `console_session_key`, `gh_write_token`,
  `gh_read_token`. Services read `<NAME>_FILE` via `citadel.env.secret()`.
- `x-app` no longer mounts the whole `.env` into api, approval-ui and the
  workers. The non-secret variables those services need (`MLFLOW_*`,
  `OPENFGA_STORE_NAME`, `TEMPORAL_NAMESPACE`, `CITADEL_APPROVAL_TTL_SECONDS`)
  are explicit.
- `docker/haproxy.cfg.template` is mounted over the image default and denies
  `/containers/{id}/archive` and `/export` before the blanket `CONTAINERS`
  allow. Upstream PR #183 is unmerged, so no release carries the fix.
- `scripts/provision-secrets.sh` writes the secret files; `make up` runs it
  inside `sops exec-env`. The files are gitignored.

## Measured on the live stack

```text
sensitive env keys on api / operator / approval-ui / workers / tool-runner
                                                          -> none
GET  /containers/json                                     -> 200
GET  /containers/citadel-api-1/json                       -> 200, no secret entries
GET  /containers/citadel-api-1/archive?path=/run/secrets  -> 403
GET  /containers/citadel-api-1/export                     -> 403
GET  /containers/citadel-api-1/logs                       -> 200
docker inspect --format ... citadel-api-1 (via proxy)     -> /citadel-api-1 running
POST /execute inspect_container                           -> 200 docker.inspect
POST /runs (private key + DSN from files)                 -> 201
operator /execute with an unknown ref                     -> 403 no approval
```

## Still exposed (follow-up)

The proxy can inspect any container, and these still carry a credential:

| container | value | source |
|---|---|---|
| `postgres` | `POSTGRES_PASSWORD`, `CITADEL_DB_PASSWORD` | environment |
| `omniroute` | `OPENROUTER_API_KEY` | environment |
| `keycloak` | `KC_BOOTSTRAP_ADMIN_PASSWORD` | environment |
| `temporal` | `POSTGRES_PWD` | environment |
| `openfga`, `openfga-migrate` | datastore URI with the password | command argv |

They are outside issue #21's named verification set and need the same
file-based treatment (or a per-container proxy scope) in a follow-up.
