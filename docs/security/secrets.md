# Secrets: custody, rotation and the surfaces that must stay clean

Ground rule 7: no plaintext secret in the repository, a skill pack, a trace, an
audit event, an eval fixture, an approval view or the sandbox. This note is the
custody and rotation procedure behind that rule. Issue #132.

## Custody

`secrets/citadel.env` is the one tracked file under `secrets/`. It is
SOPS-encrypted: AES-256-GCM values under a data key that `.sops.yaml` wraps to an
age recipient. The age **private** key lives in
`~/.config/sops/age/keys.txt` (mode 0600) and is never committed; `.gitignore`
also covers `*.age.key`.

`make up` and `make rebuild` run inside `sops exec-env`, so decrypted values
exist only in the provisioning process environment. `scripts/provision-secrets.sh`
writes the gitignored files under `secrets/`, and Compose mounts those as files.
No service reads a credential from its container environment (`Config.Env` is
readable through the socket proxy; see `issue-21-secrets.md`).

Two values are derived rather than stored twice:

- `db_dsn` comes from `CITADEL_DB_PASSWORD` and `POSTGRES_DB`.
- `openfga_pgpass` comes from `POSTGRES_USER` and `POSTGRES_PASSWORD`.

The files are mode 0644 because Compose mounts them as bind files and the
container user is uid 10001. This is a single-user host; the `secrets/`
directory stays out of git.

Check the invariant:

```bash
git ls-files secrets/                 # only secrets/citadel.env
sops -d secrets/citadel.env | sed 's/=.*/=<redacted>/'   # names, never values
uv run pytest tests/test_secrets_custody.py
```

## Rotating one value

The source of truth is the SOPS file; the mounted files are generated. Rotating a
value is therefore an edit plus a re-run, never a code change:

```bash
sops edit secrets/citadel.env
make up                      # rewrites secrets/ from the edited file
```

`docker compose up -d` does **not** recreate a container just because a mounted
file changed. A process that read the value at startup keeps the old one, so
restart the consumers named below (or `docker compose up -d --force-recreate
<service>`). Services that call `citadel.env.secret()` per request pick the new
file up without a restart, but restarting is the safe default.

### age key

`age-keygen -o /tmp/age-new.key` prints the public key. Put that recipient in
`.sops.yaml`, then re-wrap the file's data key:

```bash
sops updatekeys -y secrets/citadel.env
SOPS_AGE_KEY_FILE=/tmp/age-new.key sops -d secrets/citadel.env > /dev/null
mv /tmp/age-new.key ~/.config/sops/age/keys.txt && chmod 600 ~/.config/sops/age/keys.txt
```

`updatekeys` re-wraps the data key; it does not change the secret values. A
retired private key still decrypts every commit made before the rotation, so keep
it until the old ciphertext no longer matters. Treat the age-key rotation as a
custody change, and rotate the values themselves (below) if the old key may have
leaked.

### Database password

`CITADEL_DB_PASSWORD` is the `citadel_app` role password; `POSTGRES_PASSWORD` is
the `POSTGRES_USER` superuser password. Both are applied by the Postgres init
scripts **on a fresh volume only**. On an existing volume, change the role first,
then the SOPS value:

```bash
# POSTGRES_USER and POSTGRES_DB default to `citadel`; substitute the real names.
docker exec -it citadel-postgres-1 psql -U citadel -d citadel \
  -c "ALTER ROLE citadel_app PASSWORD '<new>'"
sops edit secrets/citadel.env        # CITADEL_DB_PASSWORD
make up
docker compose restart api approval-ui operator \
  worker-orchestrator worker-docker worker-github
```

For the superuser, `ALTER ROLE citadel PASSWORD '<new>'` against the `postgres`
database, then update `POSTGRES_PASSWORD`, `make up`, and recreate `postgres`,
`keycloak`, `temporal`, `openfga` and `omniroute`
(`docker compose up -d --force-recreate <services>`; `make up` alone does not
restart a container whose config did not change). Expect a brief gap between the
database change and the restart; a service that restarts in between still
presents the old password.

### Run-token keypair

The API signs with `CITADEL_RUN_TOKEN_PRIVATE_KEY` (a Docker secret); workers
verify with `CITADEL_RUN_TOKEN_PUBLIC_KEY` (public, supplied as an environment
variable). Both are DER, base64-encoded:

```bash
python3 - <<'PY'
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

key = Ed25519PrivateKey.generate()
private = key.private_bytes(
    serialization.Encoding.DER,
    serialization.PrivateFormat.PKCS8,
    serialization.NoEncryption(),
)
public = key.public_key().public_bytes(
    serialization.Encoding.DER,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
print("CITADEL_RUN_TOKEN_PRIVATE_KEY=" + base64.b64encode(private).decode())
print("CITADEL_RUN_TOKEN_PUBLIC_KEY=" + base64.b64encode(public).decode())
PY
```

Update both keys in the same edit, `make up`, then restart `api` and every
worker. Tokens minted with the old key stop verifying immediately, so rotate
between runs; a run in flight fails closed rather than continuing with an
unverifiable identity.

### GitHub tokens

`GH_READ_TOKEN` is the sandbox's read-only token (mapped to `GH_TOKEN` for the
call); `GH_WRITE_TOKEN` belongs to the operator and is never exposed to the
sandbox. Replace the token in GitHub, update the matching SOPS value, `make up`,
then restart `operator` and `worker-github`. The read token is re-read on each
sandbox call, so it takes the new file without a restart.

### Console session key

`CITADEL_CONSOLE_SESSION_KEY` signs the approval console's cookie. Update it,
`make up`, and restart `approval-ui`; every console session is logged out.

### Keycloak admin and OmniRoute

`KEYCLOAK_ADMIN_PASSWORD` is a bootstrap value
(`KC_BOOTSTRAP_ADMIN_PASSWORD`). Changing it in SOPS does not change an existing
realm; change it in Keycloak first, then record it in SOPS.

The OmniRoute entrypoint reads `OMNIROUTE_JWT_SECRET`, `OMNIROUTE_API_KEY_SECRET`,
`OMNIROUTE_STORAGE_ENCRYPTION_KEY` and `OMNIROUTE_ADMIN_PASSWORD` at start.
Rotating the JWT or API-key secret invalidates issued sessions and keys;
rotating the storage key makes the existing SQLite store unreadable, so re-enter
provider credentials (or start from a fresh volume). `OMNIROUTE_API_KEY` is
Citadel's client key: rotate it in the OmniRoute dashboard and in SOPS together,
then restart the workers and the orchestrator.

## Surfaces and what proves each one

| Surface | Control | Check |
|---|---|---|
| Repository and secret store | only the SOPS ciphertext is tracked | `tests/test_secrets_custody.py`, gitleaks CI |
| Skill packs | content only; the loader refuses changes by hash | gitleaks, sweep |
| Eval fixtures | authored, not captured from a live run | gitleaks, sweep |
| Traces | every tool output passes `dlp.gate(surface="output")` before it is recorded | `tests/test_dlp.py`, sweep of MLflow |
| Audit events | the `record` surface redacts PII and blocks a credential | `tests/test_dlp.py`, `tests/test_approval_route.py`, sweep |
| Approval console | arguments are gated on the `input` surface before `record_request`; the view escapes what the row holds | `tests/test_activities.py::test_a_secret_in_t1_arguments_denies_before_recording`, `tests/test_dlp.py::test_input_is_blocked_instead_of_rewritten` |
| Sandbox | no secret is mounted; only the read token is placed in the call environment | `tests/test_socket_proxy_live.py`, `issue-21-secrets.md` |

The live sweep for issue #132
(`tests/test_secret_surfaces_live.py`, `CITADEL_LIVE_TESTS=1`) reads the
provisioned values from the files without printing them and searches the source,
tests, eval fixtures, skill packs, docs, policy, migrations, the Postgres
audit/approval/tool tables and the MLflow database and artifacts. Result: no
value found on any surface (`docs/implementation-notes/issue-132-secrets.md`).

CI enforces the repository half on every push: the `gitleaks` job scans full
history with `.gitleaks.toml`. A planted PAT exits 1; `.env.example` with its
placeholders exits 0. Keep the two narrow allowlists empty of anything but the
synthetic DLP fixtures.
