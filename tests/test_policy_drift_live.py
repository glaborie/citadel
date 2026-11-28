"""Issue #292: a real drift verdict, produced on the live stack, reaches the wrapper.

The offline suite pins the plumbing with stand-ins; this proves the verdict
itself. The check is handed a deliberately mutated copy of the committed model
and has to answer "drift" and exit 1 - not 2, which means "could not compare"
and fires the warning alert instead of the critical one (#287).

    CITADEL_LIVE_TESTS=1 uv run pytest tests/test_policy_drift_live.py -v

The mutation is a file mounted over the image's own through a throwaway
`COMPOSE_FILE`; nothing is written to the checkouts and nothing to the store, and
the clean run afterwards still reports every tuple present. The gauge is pushed to
a closed port on purpose: a test run must never publish a drift verdict to the
pushgateway the real timer feeds, or it would page someone about a file in /tmp.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SECRETS = Path(os.environ.get("CITADEL_SECRETS_DIR", str(ROOT / "secrets")))
CLOSED_PORT = "http://127.0.0.1:9"

pytestmark = pytest.mark.skipif(
    os.environ.get("CITADEL_LIVE_TESTS") != "1",
    reason="set CITADEL_LIVE_TESTS=1 with the Compose stack running",
)


def _base_env() -> dict[str, str]:
    """The timer's environment, minus any `COMPOSE_FILE` the caller happens to have."""
    return {
        "CITADEL_REPO_DIR": str(ROOT),
        "CITADEL_SECRETS_DIR": str(SECRETS),
        "CITADEL_PUSHGATEWAY_URL": CLOSED_PORT,
        **{key: value for key, value in os.environ.items() if key != "COMPOSE_FILE"},
    }


def _wrapper(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/policy-drift-alert.py"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )


def _mounted_model(tmp_path: Path) -> dict[str, str]:
    """The committed model plus one type, mounted over the image's copy."""
    model = json.loads((ROOT / "policy" / "model.json").read_text(encoding="utf-8"))
    model["type_definitions"].append({"type": "service_account"})
    mutated = tmp_path / "model.json"
    mutated.write_text(json.dumps(model), encoding="utf-8")

    override = tmp_path / "compose.override.yaml"
    override.write_text(
        "services:\n"
        "  policy-bootstrap:\n"
        "    volumes:\n"
        f"      - {mutated}:/app/policy/model.json:ro\n",
        encoding="utf-8",
    )
    return {"COMPOSE_FILE": f"{ROOT / 'compose.yaml'}:{override}"}


def test_a_mutated_model_reaches_the_wrapper_as_drift(tmp_path: Path) -> None:
    if shutil.which("sops") is None or not (SECRETS / "citadel.env").exists():
        pytest.skip("needs sops and secrets/citadel.env, like the systemd timer")

    drifted = _wrapper({**_base_env(), **_mounted_model(tmp_path)})
    report = drifted.stdout + drifted.stderr

    assert "model: DRIFTED" in report, report
    assert "service_account" in report, "the report has to name what differs"
    assert drifted.returncode == 1, (
        "a real drift has to arrive as 1; 2 is 'could not compare' and fires the "
        f"warning alert instead of the critical one (#287)\n{report}"
    )

    clean = _wrapper(_base_env())
    assert clean.returncode == 0, clean.stdout + clean.stderr
    assert "policy drift: none" in clean.stdout
    assert "0 unexpected" in clean.stdout, "the check must never repair what it reports"
