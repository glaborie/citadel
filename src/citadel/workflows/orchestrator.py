"""Orchestrator workflow: owns delegation and holds no side-effecting tools."""

from __future__ import annotations

from temporalio import workflow

from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import TASK_QUEUES, RunInput, ToolCall, ToolResult


def child_workflow_id(run_id: str, tool: str) -> str:
    return f"run-{run_id}-{tool}"


@workflow.defn
class RunWorkflow:
    @workflow.run
    async def run(self, item: RunInput) -> ToolResult:
        queue = TASK_QUEUES.get(item.agent_id)
        if queue is None:
            return ToolResult(
                status="denied",
                tool=item.tool,
                rule_id="delegation.unknown_agent",
                detail=f"no specialist worker for agent {item.agent_id!r}",
            )

        call = ToolCall(
            run_id=item.run_id,
            tenant_id=item.tenant_id,
            user_id=item.user_id,
            agent_id=item.agent_id,
            tool=item.tool,
            arguments=item.arguments,
        )
        return await workflow.execute_child_workflow(
            SpecialistWorkflow.run,
            call,
            id=child_workflow_id(item.run_id, item.tool),
            task_queue=queue,
        )
