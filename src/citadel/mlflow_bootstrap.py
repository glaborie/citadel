"""Create the Citadel MLflow experiment if it is absent. Idempotent.

python -m citadel.mlflow_bootstrap
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from citadel.net import open_url

BASE = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000").rstrip("/")
NAME = os.environ.get("MLFLOW_EXPERIMENT_NAME", "citadel-trajectories")
# The id the workers write spans to. Empty means "do not check".
EXPECTED = os.environ.get("MLFLOW_EXPERIMENT_ID", "")


def _call(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if body is not None else "GET",
    )
    with open_url(request, timeout=10) as response:
        payload: dict[str, Any] = json.loads(response.read())
    return payload


def ensure_experiment() -> str:
    query = urllib.parse.quote(NAME, safe="")
    try:
        found = _call(f"/api/2.0/mlflow/experiments/get-by-name?experiment_name={query}")
        return str(found["experiment"]["experiment_id"])
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    created = _call("/api/2.0/mlflow/experiments/create", {"name": NAME})
    return str(created["experiment_id"])


def check_expected(found: str, expected: str) -> str | None:
    """The drift that a silent drop hides: the volume has one id, the workers write to another.

    A volume restored from a backup, or one whose experiments were created in a different
    order, can hold `citadel-trajectories` under an id the workers are not configured with.
    MLflow answers a span for a missing experiment with 404 and the exporter drops it, so
    the failure has to be loud, and it has to happen before any worker starts.
    """
    if not expected or expected == found:
        return None
    return (
        f"experiment {NAME!r} is id {found} on this volume but MLFLOW_EXPERIMENT_ID={expected}; "
        f"set MLFLOW_EXPERIMENT_ID={found} (or delete the volume) before starting the stack"
    )


def main() -> int:
    try:
        found = ensure_experiment()
    except (OSError, KeyError, ValueError) as exc:
        print(f"could not ensure MLflow experiment: {exc}", file=sys.stderr)
        return 1
    problem = check_expected(found, EXPECTED)
    if problem:
        print(problem, file=sys.stderr)
        return 1
    print(found)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
