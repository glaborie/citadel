#!/usr/bin/env bash
# The one definition of how the policy drift check is invoked (#287).
#
# `make policy-drift` and the scheduled wrapper both call this, so the human
# target and the timer cannot run different commands.
#
# Why a script and not the make target: GNU make turns ANY failed recipe into
# exit 2, so a real drift verdict (1) reached the wrapper as "could not compare"
# and fired the warning alert instead of the critical one. Nothing that needs the
# verdict's exact code may sit behind make.
#
# Why sops is inside: the compose file interpolates ${KEYCLOAK_ADMIN_USER} and the
# one-shot mounts the Keycloak admin password, both from secrets/citadel.env. The
# command is ONE sops argument because sops 3.13 reads any further positional as
# another file to decrypt ("error: missing file to decrypt").
#
# Exit codes are the check's own: 0 clean, 1 drift, 2 could not compare.
set -euo pipefail
cd "$(dirname "$0")/.."

exec sops exec-env secrets/citadel.env \
  'docker compose --profile tools run --rm policy-bootstrap python -m citadel.policy.drift'
