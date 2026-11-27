#!/usr/bin/env bash
# Open the MLflow UI on loopback for inspection, and close it again.
#
# Why this is not a `ports:` line in compose.yaml: `citadel_internal` is `internal: true`
# (ADR-017; tests/test_mlflow_exposure.py enforces that MLflow publishes nothing), and
# Docker ignores published ports on an internal network - `-p` on the mlflow container
# binds nothing at all. The sidecar therefore sits on the default bridge, where publishing
# works, and is joined to the internal network so it can resolve `mlflow`.
#
# Loopback only: nothing on the LAN or the internet can reach it, and the tracked compose
# file stays closed. This is an inspection tool, not a deployment change - MLflow still
# needs the Keycloak proxy before anyone else may see it.
#
#   scripts/mlflow-ui.sh --on          # http://localhost:5000
#   scripts/mlflow-ui.sh --status
#   scripts/mlflow-ui.sh --off
#   PORT=5050 scripts/mlflow-ui.sh --on
set -euo pipefail

NAME="citadel-mlflow-ui"
PORT="${PORT:-5000}"
NETWORK="${NETWORK:-citadel_internal}"
IMAGE="${IMAGE:-alpine/socat@sha256:5aa280c6fc5bee94dbd2bbdf2a58d30f50396eaa110be84b03636945b157ae68}"
UPSTREAM="${UPSTREAM:-mlflow:5000}"

usage() {
  cat <<EOF
Open the MLflow UI on 127.0.0.1:${PORT} through a socat sidecar.

  --on       start the sidecar and wait until MLflow answers
  --off      remove the sidecar (the container is the only state)
  --status   say whether it is up, and whether MLflow answers through it
  --help     this text

Environment: PORT (default ${PORT}), NETWORK (${NETWORK}), IMAGE (${IMAGE}),
             UPSTREAM (${UPSTREAM}).

Why a sidecar: ${NETWORK} is an internal network, and Docker ignores published ports on
those, so the mlflow container itself cannot be reached from the host. The sidecar joins
both networks. It listens on loopback only.
EOF
}

running() {
  [ "$(docker inspect -f '{{.State.Running}}' "$NAME" 2>/dev/null || echo false)" = "true" ]
}

answering() {
  curl -fsS -o /dev/null --max-time 3 "http://127.0.0.1:${PORT}/health"
}

status() {
  if running; then
    echo "sidecar: up   (127.0.0.1:${PORT} -> ${UPSTREAM})"
  else
    echo "sidecar: down"
  fi
  if answering; then
    echo "mlflow:  answering at http://localhost:${PORT}"
    curl -fsS --max-time 5 "http://127.0.0.1:${PORT}/api/2.0/mlflow/experiments/search?max_results=5" \
      | python3 -c 'import json,sys; print("experiments:", [e["name"] for e in json.load(sys.stdin).get("experiments", [])])' \
      || true
  else
    echo "mlflow:  not answering"
  fi
}

turn_on() {
  if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
    echo "no '${NETWORK}' network: is the stack up? (make up)" >&2
    exit 1
  fi
  if running && answering; then
    echo "already up: http://localhost:${PORT}"
    return 0
  fi
  docker rm -f "$NAME" >/dev/null 2>&1 || true
  # Same baseline as compose.yaml (#228): a helper container is still a container,
  # and a fork bomb in it would hit this host's pid table.
  docker run -d --name "$NAME" --restart unless-stopped \
    --pids-limit 64 --security-opt no-new-privileges \
    --network bridge -p "127.0.0.1:${PORT}:${PORT}" "$IMAGE" \
    "tcp-listen:${PORT},fork,reuseaddr" "tcp-connect:${UPSTREAM}" >/dev/null
  docker network connect "$NETWORK" "$NAME"

  for _ in $(seq 1 20); do
    if answering; then
      echo "up: http://localhost:${PORT}"
      return 0
    fi
    sleep 1
  done
  echo "started, but MLflow did not answer on 127.0.0.1:${PORT}; see: docker logs ${NAME}" >&2
  exit 1
}

turn_off() {
  if running; then
    docker rm -f "$NAME" >/dev/null
    echo "closed: nothing listens on 127.0.0.1:${PORT} any more"
  else
    echo "already down"
  fi
}

case "${1:---help}" in
  --on) turn_on ;;
  --off) turn_off ;;
  --status) status ;;
  --help | -h | help) usage ;;
  *)
    echo "unknown option: $1" >&2
    usage >&2
    exit 2
    ;;
esac
