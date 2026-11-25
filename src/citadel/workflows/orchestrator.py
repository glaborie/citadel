"""Orchestrator workflow: owns delegation and holds no side-effecting tools."""

from __future__ import annotations

from datetime import timedelta

from temporalio import workflow
from temporalio.common import RetryPolicy

from citadel.workflows import activities
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import TASK_QUEUES, RunEnd, RunInput, ToolCall, ToolResult


def child_workflow_id(run_id: str, tool: str) -> str:
    return f"run-{run_id}-{tool}"


def _outcome(result: ToolResult) -> str:
    if result.status in {"executed", "replayed"}:
        return "completed"
    if result.status == "denied":
        return "denied"
    return "failed"


def _safety_flags(result: ToolResult) -> list[str]:
    return ["dlp_blocked"] if result.rule_id.startswith("dlp.") else []


@workflow.defn
class RunWorkflow:
    @workflow.run
    async def run(self, item: RunInput) -> ToolResult:
        queue = TASK_QUEUES.get(item.agent_id)
        if queue is None:
            result = ToolResult(
                status="denied",
                tool=item.tool,
                rule_id="delegation.unknown_agent",
                detail=f"no specialist worker for agent {item.agent_id!r}",
            )
        else:
            call = ToolCall(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                user_id=item.user_id,
                agent_id=item.agent_id,
                tool=item.tool,
                arguments=item.arguments,
            )
            result = await workflow.execute_child_workflow(
                SpecialistWorkflow.run,
                call,
                id=child_workflow_id(item.run_id, item.tool),
                task_queue=queue,
            )

        # run.end is written by an activity, never by the workflow itself, so a
        # retried finish cannot fork the trajectory.
        await workflow.execute_activity_method(
            activities.RunActivities.finish_run,
            RunEnd(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                outcome=_outcome(result),
                safety_flags=_safety_flags(result),
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return result
