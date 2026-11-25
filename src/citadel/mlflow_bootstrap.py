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

BASE = os.environ.get("MLFLOW_TRACKING_URI", "http://mlflow:5000").rstrip("/")
NAME = os.environ.get("MLFLOW_EXPERIMENT_NAME", "citadel-trajectories")


def _call(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    request = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method="POST" if body is not None else "GET",
    )
    with urllib.request.urlopen(request, timeout=10) as response:
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


def main() -> int:
    try:
        print(ensure_experiment())
    except (OSError, KeyError, ValueError) as exc:
        print(f"could not ensure MLflow experiment: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
