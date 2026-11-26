#!/usr/bin/env bash
# Materialise the Docker secrets that read-only services mount as files.
#
# `make up` runs this inside `sops exec-env`, so the values arrive through the
# environment and no plaintext copy is committed. The files are gitignored.
set -euo pipefail

dir="${CITADEL_SECRETS_DIR:-./secrets}"
mkdir -p "$dir"
# Compose mounts a file secret as a bind mount, so the container user reads the
# host mode: 0644 is required for uid 10001. This host is single-user; the
# directory stays out of git.
umask 022

# The DSN is derived rather than stored a second time: one password to rotate.
if [ -z "${CITADEL_DB_DSN:-}" ]; then
    : "${CITADEL_DB_PASSWORD:?CITADEL_DB_PASSWORD must be set}"
    : "${POSTGRES_DB:?POSTGRES_DB must be set}"
    export CITADEL_DB_DSN="postgresql://citadel_app:${CITADEL_DB_PASSWORD}@postgres:5432/${POSTGRES_DB}"
fi

write() {
    local name="$1" var="$2"
    : "${!var:?$var must be set to provision secrets/$name}"
    printf '%s' "${!var}" > "$dir/$name"
    chmod 0644 "$dir/$name"
}

write db_dsn CITADEL_DB_DSN
write run_token_private_key CITADEL_RUN_TOKEN_PRIVATE_KEY
write console_session_key CITADEL_CONSOLE_SESSION_KEY
write gh_write_token GH_WRITE_TOKEN
write gh_read_token GH_READ_TOKEN
write postgres_password POSTGRES_PASSWORD
write citadel_db_password CITADEL_DB_PASSWORD
write keycloak_admin_password KEYCLOAK_ADMIN_PASSWORD
write omniroute_jwt_secret OMNIROUTE_JWT_SECRET
write omniroute_api_key_secret OMNIROUTE_API_KEY_SECRET
write omniroute_storage_encryption_key OMNIROUTE_STORAGE_ENCRYPTION_KEY
write omniroute_admin_password OMNIROUTE_ADMIN_PASSWORD
write omniroute_api_key OMNIROUTE_API_KEY

# pgx (OpenFGA) reads this instead of taking the password in argv or env.
# Format: host:port:database:user:password (libpq escapes `\` and `:`).
pgpass_pw=${POSTGRES_PASSWORD//\\/\\\\}
pgpass_pw=${pgpass_pw//:/\\:}
printf 'postgres:5432:openfga:%s:%s\n' "$POSTGRES_USER" "$pgpass_pw" \
    > "$dir/openfga_pgpass"
chmod 0644 "$dir/openfga_pgpass"

echo "provisioned the Docker secrets in $dir"
