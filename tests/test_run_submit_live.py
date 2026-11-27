"""A submitted run, end to end: POST /runs, workflow, model, tool, answer.

Opt-in twice: `CITADEL_LIVE_TESTS=1` needs the stack, and `CITADEL_LLM_TESTS=1`
acknowledges the spend (fractions of a cent for two model calls).

    set -a; . ./.env; set +a
    CITADEL_LIVE_TESTS=1 CITADEL_LLM_TESTS=1 uv run pytest tests/test_run_submit_live.py -v
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


def test_a_submitted_task_runs_to_an_answer() -> None:
    token = user_token("alice")
    status, created = api_call(
        "POST",
        "/runs",
        token,
        {
            "agent_id": "docker",
            "risk_tier": "T0",
            "prompt_pack_version": "docker-1.1.0",
            "model_alias": "auto/best-fast",
            "task": "Call inspect_containers once, then name one running container.",
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

    events = psql_as_app(
        "BEGIN; SELECT set_config('app.tenant_id','lab-a',true);"
        " SELECT event_type, payload->>'answer' FROM audit_events"
        f" WHERE payload->>'run_id' = '{run_id}' ORDER BY seq; COMMIT;"
    ).splitlines()
    kinds = [line.split("|")[0] for line in events if "|" in line]

    assert kinds[0] == "run.start"
    assert kinds[-1] == "run.end"
    assert "model.call" in kinds
    assert "policy.decision" in kinds
    assert "tool.call" in kinds

    answer = next(line.split("|", 1)[1] for line in events if line.startswith("run.end|"))
    assert len(answer) > 20, "the submitted run must record what it concluded"
