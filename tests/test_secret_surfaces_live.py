"""Live check: no provisioned secret on a surface ground rule 7 names.

The offline guard (`test_secrets_custody.py`) covers the repository and the
secret store. This one covers what only a running stack can show: the source
tree, the eval and skill content, the Postgres audit/approval/tool tables (the
console renders straight from `approval_requests`) and MLflow's trace store.

    CITADEL_LIVE_TESTS=1 uv run pytest tests/test_secret_surfaces_live.py
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 with the Compose stack running",
)

SKIP_DIRS = {".git", ".venv", "__pycache__", ".mypy_cache", ".ruff_cache", "secrets"}

# The tables whose text reaches an audit reader, the approval console or a
# trajectory. `tool_outputs` holds bytes; `encode(..., 'escape')` makes them
# searchable without decoding.
POSTGRES_SURFACES = {
    "audit_events": "payload::text",
    "approval_requests": "arguments::text || coalesce(reason, '')",
    "tool_calls": "coalesce(result::text, '')",
    "tool_outputs": "encode(body, 'escape')",
}


def provisioned_values() -> set[str]:
    values: set[str] = set()
    for path in (ROOT / "secrets").glob("*"):
        if path.name == "citadel.env" or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="replace").strip()
        if path.name == "openfga_pgpass":
            text = text.rsplit(":", 1)[-1]
        values.add(text)
    # A short value can be a substring of unrelated config; every real
    # credential in this repo is long.
    return {value for value in values if len(value) >= 8}


def container(suffix: str) -> str:
    names = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], check=True, capture_output=True, text=True
    ).stdout.split()
    matches = [name for name in names if name.endswith(suffix)]
    assert matches, f"no running container ends with {suffix}"
    return matches[0]


def container_env(name: str, variable: str) -> str:
    return subprocess.run(
        ["docker", "exec", name, "printenv", variable],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def postgres_dump() -> str:
    name = container("-postgres-1")
    user = container_env(name, "POSTGRES_USER")
    database = container_env(name, "POSTGRES_DB")
    chunks: list[str] = []
    for table, expression in POSTGRES_SURFACES.items():
        sql = f"SELECT coalesce(string_agg({expression}, E'\\n'), '') FROM {table}"
        chunks.append(
            subprocess.run(
                ["docker", "exec", "-i", name, "psql", "-U", user, "-d", database, "-tAc", sql],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
    return "".join(chunks)


def mlflow_dump() -> str:
    name = container("-mlflow-1")
    script = (
        "cat /mlflow/mlflow.db; "
        "(find /mlflow/artifacts -type f -exec cat {} \\; 2>/dev/null || true)"
    )
    return subprocess.run(
        ["docker", "exec", name, "sh", "-c", script],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", "ignore")


def tree_dump() -> str:
    chunks: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        chunks.append(path.read_text(encoding="utf-8", errors="ignore"))
    return "".join(chunks)


def leaked(surface: str, text: str, values: set[str]) -> list[str]:
    return [surface] if any(value in text for value in values) else []


def test_no_provisioned_secret_reaches_a_named_surface() -> None:
    values = provisioned_values()
    assert values, "no provisioned secret values found to check"
    surfaces = {
        "source tree, eval fixtures, skill packs, docs": tree_dump(),
        "postgres audit/approval/tool tables": postgres_dump(),
        "mlflow traces and artifacts": mlflow_dump(),
    }
    exposed = [hit for name, text in surfaces.items() for hit in leaked(name, text, values)]
    assert not exposed, f"a provisioned secret reached: {exposed}"
