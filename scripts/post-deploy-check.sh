#!/usr/bin/env bash
# Post-deploy gate (#296): prove a real drift verdict still reaches the wrapper.
#
# `make up` and `make rebuild` end here, with the stack up and `--wait` passed.
# The verdict crosses sops, compose and the policy-bootstrap image, so no offline
# test can say whether this host still turns a drift into exit 1 — #287 did not,
# and `make check` stayed green for a day. The case lives in
# tests/test_policy_drift_live.py; this wrapper exists for the message, because
# `make` rewrites a failed recipe to exit 2 and would eat the reason.
#
# A worktree has no secrets/ of its own: point CITADEL_SECRETS_DIR at the
# checkout that does, and the case unwraps from there.
set -euo pipefail
cd "$(dirname "$0")/.."

# The case skips itself when it cannot reach sops or the secrets, which is right
# for a fresh clone and wrong for a gate: a skip here would report the path as
# proven without running it. Refuse instead, so the reason is the gate's own.
if ! command -v sops >/dev/null 2>&1; then
  echo "post-deploy: FAILED - sops is not installed, so the check cannot be proven." >&2
  exit 1
fi
if [ ! -f "${CITADEL_SECRETS_DIR:-secrets}/citadel.env" ]; then
  echo "post-deploy: FAILED - no ${CITADEL_SECRETS_DIR:-secrets}/citadel.env." >&2
  echo "  A worktree needs its own secrets/ or CITADEL_SECRETS_DIR pointed at the" >&2
  echo "  checkout that has them." >&2
  exit 1
fi

if ! CITADEL_LIVE_TESTS=1 uv run pytest tests/test_policy_drift_live.py -q; then
  echo "post-deploy: FAILED - the drift verdict path is broken on this stack." >&2
  echo "  The stack is up, but a scheduled drift report may never reach the" >&2
  echo "  wrapper or its alert. See docs/operations/policy-drift-check.md and" >&2
  echo "  the failure above." >&2
  exit 1
fi

echo "post-deploy: drift verdict path ok (drift -> 1, clean -> 0)"
