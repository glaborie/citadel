"""Specialist child workflows: authorise, gate T1, then execute exactly once."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

from citadel.workflows import activities
from citadel.workflows.types import (
    APPROVAL_TTL,
    MAX_ATTEMPTS,
    ApprovalDecision,
    ToolCall,
    ToolResult,
)


@workflow.defn
class SpecialistWorkflow:
    def __init__(self) -> None:
        self._approval: ApprovalDecision | None = None

    @workflow.signal
    def approve(self, decision: ApprovalDecision) -> None:
        self._approval = decision

    @workflow.run
    async def run(self, call: ToolCall) -> ToolResult:
        outcome = await workflow.execute_activity_method(
            activities.ToolActivities.authorize_tool,
            call,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=2),
        )

        if outcome.outcome == "deny":
            return ToolResult(
                status="denied",
                tool=call.tool,
                rule_id=outcome.rule_id,
                detail=outcome.reason,
            )

        if outcome.outcome == "requires_approval":
            try:
                await workflow.wait_condition(
                    lambda: self._approval is not None,
                    timeout=timedelta(seconds=APPROVAL_TTL),
                )
            except TimeoutError:
                # TTL expiry is an automatic deny, never an implicit approval.
                return ToolResult(
                    status="denied",
                    tool=call.tool,
                    rule_id="approval.expired",
                    detail="no decision before the approval TTL elapsed",
                )
            assert self._approval is not None
            if not self._approval.approved:
                return ToolResult(
                    status="denied",
                    tool=call.tool,
                    rule_id="approval.denied",
                    detail=self._approval.reason,
                )
            # Only a signed approval may reach a writer.
            call = ToolCall(
                run_id=call.run_id,
                tenant_id=call.tenant_id,
                user_id=call.user_id,
                agent_id=call.agent_id,
                tool=call.tool,
                arguments=call.arguments,
                approval_token=self._approval.token,
            )

        # Retries exhausted: report a structured failure rather than letting the
        # child workflow die without a result the run can record.
        try:
            return await workflow.execute_activity_method(
                activities.ToolActivities.execute_tool,
                call,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=RetryPolicy(maximum_attempts=MAX_ATTEMPTS),
            )
        except ActivityError as exc:
            return ToolResult(
                status="failed",
                tool=call.tool,
                rule_id="tool.no_result",
                detail=f"{call.tool} produced no result after {MAX_ATTEMPTS} attempts: {exc}",
            )
