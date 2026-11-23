#!/bin/bash
# Runs once, on an empty data directory.
#
# The app must NOT connect as POSTGRES_USER: that role is a superuser and
# superusers bypass row-level security entirely. citadel_app is a plain
# LOGIN role with NOBYPASSRLS, so the tenant policy actually applies.
set -euo pipefail

: "${CITADEL_DB_PASSWORD:?CITADEL_DB_PASSWORD must be set}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v pw="$CITADEL_DB_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE citadel_app LOGIN NOBYPASSRLS PASSWORD %L', :'pw')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'citadel_app')
\gexec
SQL

for migration in /migrations/*.sql; do
    echo "applying $migration"
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" -f "$migration"
done
