"""Three cases that only mean something against the running stack.

Each test records its outcome in ``harness.COLLECTED`` so the generated report
covers live results in the same table as the offline ones, with the detail
naming the live surface it exercised.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from tests.redteam import harness
from tests.redteam.live.conftest import API, Tokens, http_json

pytestmark = pytest.mark.live


def _runs(token: str) -> list[dict[str, object]]:
    body = http_json(f"{API}/runs", token=token)
    rows = body.get("runs", body) if isinstance(body, dict) else body
    assert isinstance(rows, list)
    return rows


def test_tenant_isolation_on_runs(live: None, tokens: Tokens, seeded_runs: dict[str, str]) -> None:
    """RT-AUTHZ-01: a run row in another tenant is invisible over the real API."""
    foreign = seeded_runs["foreign_lab_b"]

    alice_ids = {str(row["id"]) for row in _runs(tokens.alice)}
    bob_ids = {str(row["id"]) for row in _runs(tokens.bob)}

    leaked = foreign in alice_ids
    bob_tenants = {str(row["tenant_id"]) for row in _runs(tokens.bob)}

    harness.LIVE["RT-AUTHZ-01"] = (
        "pass" if (not leaked and foreign in bob_ids) else "fail",
        f"live /runs: alice sees foreign={leaked}; bob tenants={sorted(bob_tenants)}",
    )
    assert not leaked, "lab-b run visible to a lab-a user"
    assert foreign in bob_ids, "the seeded run is missing for its own tenant"
    assert bob_tenants <= {"lab-b"}, f"bob saw rows from {bob_tenants - {'lab-b'}}"


def test_self_approval_rejected_live(
    live: None, tokens: Tokens, seeded_runs: dict[str, str]
) -> None:
    """RT-HITL-01: separation of duties, through Keycloak, the API and Postgres RLS."""
    run_id = seeded_runs["owned_by_carol"]
    response_status, detail = _approve(tokens.carol, run_id)

    harness.LIVE["RT-HITL-01"] = (
        "pass" if response_status == 403 and "own run" in detail else "fail",
        f"live /approvals: {response_status} {detail[:50]}",
    )
    assert response_status == 403, f"self-approval was not refused ({response_status})"
    assert "own run" in detail


def test_unknown_tool_denied_live(live: None, tokens: Tokens) -> None:
    """RT-AUTHZ-03: the catalog check holds against live OpenFGA."""
    runs = _runs(tokens.alice)
    assert runs, "alice has no runs to authorise against"
    run_id = str(runs[0]["id"])
    body = http_json(
        f"{API}/policy/authorize",
        token=tokens.alice,
        payload={"agent_id": "docker", "tool": "docker_prune_images", "run_id": run_id},
    )
    outcome = str(body.get("outcome", ""))
    rule = str(body.get("rule_id", ""))
    harness.LIVE["RT-AUTHZ-03"] = (
        "pass" if outcome == "deny" and rule == "tool.unknown" else "fail",
        f"live /policy/authorize: {outcome}/{rule}",
    )
    assert outcome == "deny", body
    assert rule == "tool.unknown", body


def _approve(token: str, run_id: str) -> tuple[int, str]:
    payload = {
        "run_id": run_id,
        "tool": "restart_service",
        "agent_id": "docker",
        "arguments": {"service": "checkout-api"},
        "approved": True,
        "reason": "looks fine to me",
    }
    request = urllib.request.Request(
        f"{API}/approvals",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            return response.status, str(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, str(exc.read())
