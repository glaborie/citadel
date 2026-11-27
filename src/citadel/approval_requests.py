"""The pending-approval row: written by the specialist, closed by the API.

The row is what the console lists and reads, so the arguments in it have
already passed the DLP gate. Nothing here decides anything; the API remains
the only writer of a decision and the workflow stays the only enforcer.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from citadel import metrics
from citadel.db import tenant_connection

if TYPE_CHECKING:
    from citadel.workflows.types import ToolCall


def record_request(*, dsn: str, call: ToolCall, tier: str, rule_id: str) -> None:
    """A T1 call is waiting; a retry must not add a second row.

    The row carries `call.workflow_id`, the parked child's own runtime id.
    """
    with tenant_connection(dsn, call.tenant_id) as conn:
        conn.execute(
            "INSERT INTO approval_requests"
            " (tenant_id, run_id, tool, agent_id, arguments, tier, rule_id,"
            " requested_by, workflow_id)"
            " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)"
            " ON CONFLICT (run_id, tool) DO NOTHING",
            (
                call.tenant_id,
                call.run_id,
                call.tool,
                call.agent_id,
                json.dumps(call.arguments, ensure_ascii=False),
                tier,
                rule_id,
                call.user_id,
                call.workflow_id,
            ),
        )


def close_request(
    *,
    dsn: str,
    tenant_id: str,
    run_id: str,
    tool: str,
    approved: bool,
    approver: str,
    reason: str,
) -> None:
    """Mirror the decision onto the row so the console stops listing it.

    The elapsed time comes back from the database, whose clock both timestamps
    use: a worker with a skewed clock must not decide how long a human took.
    """
    with tenant_connection(dsn, tenant_id) as conn:
        closed = conn.execute(
            "UPDATE approval_requests"
            " SET status = %s, decided_by = %s, reason = %s, decided_at = now()"
            " WHERE run_id = %s::uuid AND tool = %s AND status = 'pending'"
            " RETURNING EXTRACT(EPOCH FROM (now() - created_at))",
            ("approved" if approved else "denied", approver, reason, run_id, tool),
        ).fetchone()
    if closed is not None:
        metrics.approval_decision("approved" if approved else "denied", float(closed[0]))
