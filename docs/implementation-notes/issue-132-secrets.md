# Issue #132: SOPS + age, Docker secrets and the no-plaintext sweep

The encryption and the Docker-secret binding were already delivered under #21
and #108: `secrets/citadel.env` is the tracked SOPS file, `make up` unwraps it
into gitignored files under `secrets/`, and every service reads a file instead of
`Config.Env`. #132 closes the remaining acceptance: a rotation runbook, a sweep
of each surface the ground rule names, and a regression test for the custody
invariant.

## What changed

- `docs/security/secrets.md` — custody, the one-value rotation flow (age key,
  database password, run-token keypair, GitHub tokens, console key, Keycloak and
  OmniRoute), and the surface-to-control table.
- `tests/test_secrets_custody.py` — the tracked secret file holds only SOPS
  ciphertext, `.env.example` keeps a placeholder for every credential, and only
  `secrets/citadel.env` is tracked under `secrets/`.
- `tests/test_secret_surfaces_live.py` — opt-in live sweep of the source tree,
  eval fixtures, skill packs, docs, the Postgres audit/approval/tool tables (the
  console renders `approval_requests` directly) and MLflow's trace store.
- `ADR-019` amended: the rotation procedure and the CI leak scan move from the
  v0.3 line to v0.2, which is where they landed.
- The dangling "SOPS decision note" in the Makefile now points at the runbook;
  `.env.example` no longer says the migration is still ahead.

## Measured

Gitleaks, pinned to the CI version, run in a container against the working tree:

| Input | Exit |
|---|---|
| a directory with one planted `ghp_…` PAT | 1 (leak) |
| the same directory with `.env.example` only | 0 (clean) |

Provisioning is deterministic: running `scripts/provision-secrets.sh` under
`sops exec-env` into a fresh directory and diffing against the live `secrets/`
produced no differences, so a fresh clone with the owner's age key materialises
the same files.

The live sweep read the 15 provisioned values from the files without printing
them and found none of them in:

- `src/`, `tests/`, `evals/`, `skills/`, `knowledge/`, `docs/`, `policy/`,
  `migrations/`;
- `audit_events`, `approval_requests`, `tool_calls`, `tool_outputs` in Postgres;
- the MLflow SQLite store and artifact directory.

`CITADEL_LIVE_TESTS=1 uv run pytest tests/test_secret_surfaces_live.py` passes
against the running stack. The offline suite with the new custody test also
passes, and ruff/mypy are clean on both files.

## Not measured here

- A full `make up` from a fresh clone and fresh volumes was not re-run; it would
  tear down the running stack. The determinism check above covers the input
  half, and the v0.1 exit review already records `make up` starting all 17
  services.
- Container logs are not part of the sweep. The socket-proxy and sandbox tests
  keep secrets out of the process environment, and the DLP gates cover the
  recorded surfaces this issue names; a log sweep is a separate check.
