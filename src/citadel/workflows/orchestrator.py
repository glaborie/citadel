"""Orchestrator workflow: owns delegation and holds no side-effecting tools.

Two run shapes, one workflow:

* **model-driven** (`RunInput.prompt` is set) — the loop asks the model, policy
  answers each requested tool, and an allowed call executes on the specialist's
  queue. The prompt comes from the agent's hash-verified pack plus the tool
  catalog, both assembled by an activity.
* **tool-driven** (no prompt) — one named tool, which is the drill path.

The loop itself is `citadel.model.run_agent`, unchanged: this file only supplies
its four callbacks as activities, so the same code that the unit and red-team
suites drive is the code that runs here.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import timedelta
from typing import Any, cast

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

from citadel import dlp
from citadel.model import Budget, ModelUnavailable, run_agent
from citadel.model.types import Reply, Trajectory
from citadel.policy import Decision
from citadel.policy.authorize import Outcome
from citadel.workflows import activities
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import (
    MAX_ATTEMPTS,
    TASK_QUEUES,
    ModelRequest,
    RunEnd,
    RunInput,
    ToolCall,
    ToolResult,
)


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
        if item.prompt:
            trajectory = await self._agent(item)
            result = ToolResult(
                status=_status(trajectory.outcome),
                tool="",
                rule_id=f"run.{trajectory.outcome}",
                detail=trajectory.text[:4000],
            )
            end = RunEnd(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                outcome=trajectory.outcome,
                safety_flags=["dlp_blocked"] if trajectory.outcome == "dlp_blocked" else [],
                answer=trajectory.text[:4000],
            )
        else:
            result = await self._tool(item)
            end = RunEnd(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                outcome=_outcome(result),
                safety_flags=_safety_flags(result),
            )

        # run.end is written by an activity, never by the workflow itself, so a
        # retried finish cannot fork the trajectory.
        await workflow.execute_activity_method(
            activities.RunActivities.finish_run,
            end,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )
        return result

    async def _tool(self, item: RunInput) -> ToolResult:
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

    async def _agent(self, item: RunInput) -> Trajectory:
        queue = TASK_QUEUES[item.agent_id]
        system = await workflow.execute_activity_method(
            activities.ModelActivities.system_prompt,
            item.agent_id,
            start_to_close_timeout=timedelta(seconds=30),
        )
        tools = await workflow.execute_activity_method(
            activities.ModelActivities.tools,
            item.agent_id,
            start_to_close_timeout=timedelta(seconds=30),
        )

        def call_for(tool: str, arguments: Mapping[str, Any]) -> ToolCall:
            return ToolCall(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                user_id=item.user_id,
                agent_id=item.agent_id,
                tool=tool,
                arguments=dict(arguments),
            )

        async def complete(**kwargs: Any) -> Reply:
            request = ModelRequest(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                agent_id=item.agent_id,
                alias=kwargs.get("alias") or item.model_alias,
                messages=list(kwargs["messages"]),
                tools=list(kwargs.get("tools") or []),
            )
            turn = await workflow.execute_activity_method(
                activities.ModelActivities.complete,
                request,
                start_to_close_timeout=timedelta(seconds=120),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            if turn.blocked == "dlp":
                # Same exception the in-process loop expects, raised here
                # because the activity boundary cannot carry it.
                raise dlp.DlpBlocked("dlp_blocked", {})
            if turn.reply is None:
                raise ModelUnavailable(turn.detail or turn.blocked)
            return turn.reply

        async def authorize(tool: str, arguments: Mapping[str, Any]) -> Decision:
            outcome = await workflow.execute_activity_method(
                activities.ToolActivities.authorize_tool,
                call_for(tool, arguments),
                task_queue=queue,
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            decided = outcome.outcome
            if decided not in {"allow", "requires_approval", "deny"}:
                # A value this code cannot interpret is a denial, never a pass.
                decided = "deny"
            return Decision(
                outcome=cast(Outcome, decided),
                rule_id=outcome.rule_id,
                reason=outcome.reason,
                tier=outcome.tier,
            )

        async def execute(tool: str, arguments: Mapping[str, Any]) -> str:
            try:
                result: ToolResult = await workflow.execute_activity_method(
                    activities.ToolActivities.execute_tool,
                    call_for(tool, arguments),
                    task_queue=queue,
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=RetryPolicy(maximum_attempts=MAX_ATTEMPTS),
                )
            except ActivityError as exc:
                # Feed the failure back rather than killing the run without a
                # recorded end; the model may still answer around it.
                return json.dumps({"status": "failed", "detail": str(exc)[:300]})
            if result.output:
                return json.dumps(result.output, sort_keys=True)
            return result.detail

        async def gate(text: str, surface: str) -> str:
            return await workflow.execute_activity_method(
                activities.ModelActivities.gate,
                args=[text, surface],
                start_to_close_timeout=timedelta(seconds=30),
            )

        return await run_agent(
            complete=complete,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": item.prompt},
            ],
            authorize=authorize,
            execute=execute,
            gate=gate,
            tools=tools,
            # A real turn is ~1.5k prompt tokens and the tool output comes back
            # in the next one, so the loop's smoke-test default ($0.01) stops
            # an honest run before it answers. Hardcoded because workflow code
            # must be deterministic across replays; make it configurable when a
            # tenant needs its own ceiling.
            budget=Budget(max_steps=6, max_tokens=32000, max_cost_usd=0.25),
            alias=item.model_alias or None,
            run_id=item.run_id,
        )


def _status(outcome: str) -> str:
    if outcome == "completed":
        return "executed"
    if outcome in {"refused", "policy_denied", "dlp_blocked"}:
        return "denied"
    return "failed"

