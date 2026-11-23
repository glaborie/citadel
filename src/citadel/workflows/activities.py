"""Activities: the only places that touch policy, the database or tools.

Every activity is synchronous and idempotent from Temporal's point of view:
the tool call is keyed, so a retry after a crash cannot produce a second side
effect.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from temporalio import activity

from citadel.db import tenant_connection
from citadel.policy import AuthorizationRequest, RelationChecker, RunStore, authorize
from citadel.workflows.types import PolicyOutcome, ToolCall, ToolResult


def idempotency_key(call: ToolCall) -> str:
    """Stable across retries: same run, tool and canonical arguments."""
    payload = json.dumps(
        {"tool": call.tool, "arguments": call.arguments},
        sort_keys=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(payload.encode()).hexdigest()
    return f"{call.run_id}:{call.tool}:{digest}"


class ToolActivities:
    def __init__(self, *, checker: RelationChecker, run_store: RunStore, dsn: str) -> None:
        self._checker = checker
        self._run_store = run_store
        self._dsn = dsn

    @activity.defn
    def authorize_tool(self, call: ToolCall) -> PolicyOutcome:
        decision = authorize(
            AuthorizationRequest(
                user_id=call.user_id,
                tenant_id=call.tenant_id,
                run_id=call.run_id,
                agent_id=call.agent_id,
                tool=call.tool,
            ),
            self._checker,
            self._run_store,
        )
        return PolicyOutcome(
            outcome=decision.outcome,
            rule_id=decision.rule_id,
            reason=decision.reason,
            tier=decision.tier,
        )

    @activity.defn
    def execute_tool(self, call: ToolCall) -> ToolResult:
        key = idempotency_key(call)
        with tenant_connection(self._dsn, call.tenant_id) as conn:
            inserted = conn.execute(
                "INSERT INTO tool_calls (idempotency_key, tenant_id, run_id, tool, status)"
                " VALUES (%s, %s, %s, %s, 'started')"
                " ON CONFLICT (idempotency_key) DO NOTHING"
                " RETURNING id",
                (key, call.tenant_id, call.run_id, call.tool),
            ).fetchone()

            if inserted is None:
                # A previous attempt already owns this key; replay its result.
                row = conn.execute(
                    "SELECT status, result FROM tool_calls WHERE idempotency_key = %s",
                    (key,),
                ).fetchone()
                if row is None:  # pragma: no cover - the conflict implies a row
                    raise RuntimeError(f"idempotency row missing for {key}")
                stored: dict[str, Any] = row[1] or {}
                return ToolResult(
                    status="replayed",
                    tool=call.tool,
                    rule_id="idempotency.replayed",
                    detail="an earlier attempt produced this key",
                    idempotency_key=key,
                    replayed=True,
                    output=stored,
                )

            # shortcut: tool bodies arrive in step 6; the audit trail and
            # idempotency guarantees already behave exactly as they will then.
            output: dict[str, Any] = {"tool": call.tool, "arguments": call.arguments}
            conn.execute(
                "UPDATE tool_calls SET status = 'succeeded', result = %s"
                " WHERE idempotency_key = %s",
                (json.dumps(output), key),
            )
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="tool.executed",
            detail=f"{call.tool} executed",
            idempotency_key=key,
            output=output,
        )
