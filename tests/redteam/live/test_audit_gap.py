"""RT-DUR-02 against the real database.

Two failures, asked for separately:

* a tool recorded as executed with no ``tool.call`` event behind it - invisible
  to the hash chain, so it needs the gap query;
* a row written outside the ledger - visible only because the chain is verified.

The tenant is created for the test and removed afterwards, so no real chain is
touched.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from citadel.audit import UNAUDITED_SQL
from tests.redteam import harness
from tests.redteam.live.conftest import MAIN, psql

pytestmark = pytest.mark.live

TENANT = "lab-dur02"


def verify_in_container(tenant: str) -> tuple[bool, int]:
    """Run the ledger's own verify() inside the api container, where the DSN works."""
    script = (
        "import json, os;"
        "from citadel.audit import AuditLedger;"
        f"ok, n = AuditLedger(os.environ['CITADEL_DB_DSN']).verify({tenant!r});"
        "print(json.dumps([ok, n]))"
    )
    completed = subprocess.run(
        ["docker", "compose", "exec", "-T", "api", "python", "-c", script],
        cwd=MAIN,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        pytest.skip(f"verify() unavailable in the container: {completed.stderr.strip()[:160]}")
    payload = completed.stdout.strip().splitlines()[-1]
    ok, count = json.loads(payload)
    return bool(ok), int(count)


def gap_keys(tenant: str) -> list[str]:
    sql = UNAUDITED_SQL.replace("%s", f"'{tenant}'")
    output = psql(sql)
    return [line.strip() for line in output.splitlines() if line.strip()]


@pytest.fixture
def seeded(  # noqa: ANN201
    live: None,
) -> object:
    psql(f"DELETE FROM audit_events WHERE tenant_id = '{TENANT}'")
    psql(f"DELETE FROM tool_calls WHERE tenant_id = '{TENANT}'")
    yield
    psql(f"DELETE FROM audit_events WHERE tenant_id = '{TENANT}'")
    psql(f"DELETE FROM tool_calls WHERE tenant_id = '{TENANT}'")


def test_a_tool_that_ran_without_an_audit_row_is_reported(live: None, seeded: object) -> None:
    """The gap the chain cannot see, found by the query that asks for it."""
    psql(
        "INSERT INTO tool_calls (idempotency_key, tenant_id, run_id, tool, status) VALUES "
        f"('{TENANT}:restart_service', '{TENANT}', gen_random_uuid(),"
        " 'restart_service', 'executed')"
    )
    keys = gap_keys(TENANT)

    harness.LIVE["RT-DUR-02"] = (
        "pass" if keys == [f"{TENANT}:restart_service"] else "fail",
        f"live unaudited(): {len(keys)} gap(s) for an executed call with no event",
    )
    assert keys == [f"{TENANT}:restart_service"]


def test_an_audited_call_is_not_reported(live: None, seeded: object) -> None:
    """A matching tool.call event closes the gap, so the query is not just a count."""
    key = f"{TENANT}:read_logs"
    psql(
        "INSERT INTO tool_calls (idempotency_key, tenant_id, run_id, tool, status) VALUES "
        f"('{key}', '{TENANT}', gen_random_uuid(), 'read_logs', 'executed')"
    )
    psql(
        "INSERT INTO audit_events (tenant_id, seq, event_type, actor_type, actor_id, payload,"
        f" prev_hash, hash) VALUES ('{TENANT}', 1, 'tool.call', 'agent', 'docker',"
        f" '{{\"idempotency_key\": \"{key}\"}}'::jsonb, repeat('0', 64), repeat('a', 64))"
    )
    assert gap_keys(TENANT) == []


def test_a_row_written_outside_the_ledger_breaks_verification(live: None, seeded: object) -> None:
    """Tamper evidence: the chain notices a row it did not produce."""
    clean, _ = verify_in_container(TENANT)
    assert clean, "an empty tenant should verify clean"

    psql(
        "INSERT INTO audit_events (tenant_id, seq, event_type, actor_type, actor_id, payload,"
        f" prev_hash, hash) VALUES ('{TENANT}', 1, 'policy.decision', 'user', 'mallory',"
        " '{}'::jsonb, repeat('f', 64), repeat('e', 64))"
    )
    forged, count = verify_in_container(TENANT)
    assert count == 1
    assert forged is False, "a row with a fabricated prev_hash verified"
