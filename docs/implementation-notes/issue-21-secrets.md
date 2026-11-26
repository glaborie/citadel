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
- `docker/haproxy.cfg.template` is mounted over the image default. It denies
  `/containers/{id}/archive` and `/export`, and since #110 it forwards only
  `/containers/citadel-*` names, so the files above are not readable either.
  Upstream PR #183 is unmerged, so no release carries the fix.
- `scripts/provision-secrets.sh` writes the secret files; `make up` runs it
  inside `sops exec-env`. The files are gitignored.

## Measured on the live stack

```text
sensitive env keys on api / operator / approval-ui / workers / tool-runner
                                                          -> none
GET  /containers/json                                     -> 200
GET  /containers/citadel-api-1/json                       -> 200, no secret entries
GET  /containers/bastion-db/json                          -> 403 (#110 scope)
GET  /containers/{id}/json                                -> 403 (#110: names only)
GET  /containers/citadel-api-1/archive?path=/run/secrets  -> 403
GET  /containers/citadel-api-1/export                     -> 403
GET  /containers/citadel-api-1/logs                       -> 200
docker inspect --format ... citadel-api-1 (via proxy)     -> /citadel-api-1 running
POST /execute inspect_container                           -> 200 docker.inspect
POST /runs (private key + DSN from files)                 -> 201
operator /execute with an unknown ref                     -> 403 no approval
```

## Follow-up closed by #108

The same probe found five more credentials in `Config.Env`/`Config.Cmd`. They
are now file-backed too, and the live check is a test that fails on a reversal:

| container | value | how it is supplied now |
|---|---|---|
| `postgres` | `POSTGRES_PASSWORD`, `CITADEL_DB_PASSWORD` | `POSTGRES_PASSWORD_FILE`, `CITADEL_DB_PASSWORD_FILE` (read by the init script) |
| `keycloak` | `KC_DB_PASSWORD`, `KC_BOOTSTRAP_ADMIN_PASSWORD` | entrypoint reads the files and exports them into the process only |
| `temporal` | `POSTGRES_PWD` | entrypoint reads the file and exports it to `auto-setup` |
| `openfga`, `openfga-migrate` | datastore URI with the password | URI has no password; `PGPASSFILE` points at a mounted `.pgpass` |
| `omniroute` | `JWT_SECRET`, `API_KEY_SECRET`, `STORAGE_ENCRYPTION_KEY`, `INITIAL_PASSWORD` | entrypoint reads the files and exports them |
| `worker-orchestrator` | `OMNIROUTE_API_KEY` | `OMNIROUTE_API_KEY_FILE` (`citadel.env.optional_secret`) |
| `omniroute` | `OPENROUTER_API_KEY` | **removed**: the pinned image never reads it; provider keys live in its SQLite store, configured through the dashboard |

The entrypoint exports are not part of `Config.Env`, which is what the Docker
API returns; `archive`/`export` remain denied, so the mounted files are not
readable either. `scripts/provision-secrets.sh` writes the new files, including
the `.pgpass` (pgx honours it; verified with `openfga migrate` and `openfga run`).

`tests/test_socket_proxy_live.py` collects every provisioned value and asserts
none appears in any container's `Config`. It is skipped unless
`CITADEL_LIVE_TESTS=1`, like the other live tests.

The proxy still lets the sandbox inspect containers from other Compose projects
on the same daemon; that is a separate boundary, tracked as issue #110.
