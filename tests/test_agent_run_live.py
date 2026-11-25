"""A prompt-driven run against the live stack: prompt, pack, policy, DLP, tool.

Opt-in twice: `CITADEL_LIVE_TESTS=1` needs the stack, and `CITADEL_LLM_TESTS=1`
acknowledges the spend (about two cents for this run, two model calls).

    set -a; . ./.env; set +a
    CITADEL_LIVE_TESTS=1 CITADEL_LLM_TESTS=1 uv run pytest tests/test_agent_run_live.py -v
"""

from __future__ import annotations

import os
import time

import pytest

from tests.test_tenancy_live import api_call, psql_as_app, user_token

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        os.environ.get("CITADEL_LIVE_TESTS") != "1" or os.environ.get("CITADEL_LLM_TESTS") != "1",
        reason="set CITADEL_LIVE_TESTS=1 and CITADEL_LLM_TESTS=1 to spend on a real run",
    ),
]

RUN_TIMEOUT_SECONDS = 240


def test_a_prompt_drives_the_whole_runtime() -> None:
    token = user_token("alice")
    status, created = api_call(
        "POST",
        "/runs",
        token,
        {
            "agent_id": "docker",
            "risk_tier": "T0",
            "prompt_pack_version": "docker-1.0.0",
            "model_alias": "auto/best-fast",
            "prompt": "Use inspect_containers, then name one running container.",
        },
    )
    assert status == 201, created
    run_id = created["run_id"]

    deadline = time.time() + RUN_TIMEOUT_SECONDS
    outcome: str | None = None
    while time.time() < deadline:
        _, listing = api_call("GET", "/runs", token)
        outcome = {row["id"]: row["status"] for row in listing["runs"]}.get(run_id)
        if outcome not in (None, "created"):
            break
        time.sleep(2)

    assert outcome == "completed", f"run {run_id} ended {outcome}"

    kinds = psql_as_app(
        "BEGIN; SELECT set_config('app.tenant_id','lab-a',true);"
        " SELECT event_type FROM audit_events"
        f" WHERE payload->>'run_id' = '{run_id}' ORDER BY seq; COMMIT;"
    ).split()
    assert "model.call" in kinds
    assert "policy.decision" in kinds
    assert "dlp.event" in kinds
    assert "tool.call" in kinds
    assert kinds[-1] == "COMMIT", kinds
    assert kinds[-2] == "run.end", kinds
