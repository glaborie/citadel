"""A model-driven run: the workflow supplies the loop's four callbacks.

The activities are stubs, so this asserts the wiring rather than the model: the
prompt comes from the pack, the requested tool goes through policy, the allowed
call executes on the specialist queue, and the gated answer lands on run.end.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from citadel.model.types import Reply, RequestedTool, Usage
from citadel.workflows.orchestrator import RunWorkflow
from citadel.workflows.types import (
    ModelRequest,
    ModelTurn,
    PolicyOutcome,
    RunEnd,
    RunInput,
    ToolCall,
    ToolResult,
)

RUN = "11111111-1111-1111-1111-111111111111"


def item(prompt: str = "which containers are running?") -> RunInput:
    return RunInput(
        run_id=RUN,
        tenant_id="lab-a",
        user_id="user-alice",
        agent_id="docker",
        prompt=prompt,
        model_alias="auto/best-fast",
    )


def run(prompt: str = "which containers are running?") -> dict[str, Any]:
    seen: dict[str, Any] = {"completions": 0}

    @activity.defn
    def system_prompt(agent: str) -> str:
        seen["agent"] = agent
        return f"PACK:{agent}"

    @activity.defn
    def tools(agent: str) -> list[dict[str, Any]]:
        return [{"type": "function", "function": {"name": "inspect_containers", "parameters": {}}}]

    @activity.defn
    def complete(request: ModelRequest) -> ModelTurn:
        seen["completions"] += 1
        seen.setdefault("messages", request.messages)
        seen.setdefault("tools", request.tools)
        if seen["completions"] == 1:
            return ModelTurn(
                reply=Reply(
                    content="",
                    tools=(RequestedTool("inspect_containers", {}, "c1"),),
                    usage=Usage.zero(),
                    model="auto",
                    latency_ms=5,
                )
            )
        return ModelTurn(
            reply=Reply(
                content="two containers are running",
                tools=(),
                usage=Usage.zero(),
                model="auto",
                latency_ms=5,
            )
        )

    @activity.defn
    def gate(text: str, surface: str) -> str:
        seen.setdefault("gated", []).append(surface)
        return text

    @activity.defn
    def authorize_tool(call: ToolCall) -> PolicyOutcome:
        seen.setdefault("authorized", []).append(call.tool)
        return PolicyOutcome("allow", "policy.allowed", "allowed", "T0")

    @activity.defn
    def execute_tool(call: ToolCall) -> ToolResult:
        seen.setdefault("executed", []).append(call.tool)
        return ToolResult(
            status="executed",
            tool=call.tool,
            rule_id="tool.executed",
            detail="ok",
            output={"stdout": "citadel-api running"},
        )

    @activity.defn
    def finish_run(end: RunEnd) -> None:
        seen["end"] = end

    async def drive() -> ToolResult:
        env = await WorkflowEnvironment.start_time_skipping()
        executor = ThreadPoolExecutor(max_workers=4)
        try:
            async with (
                Worker(
                    env.client,
                    task_queue="orchestrator",
                    workflows=[RunWorkflow],
                    activities=[system_prompt, tools, complete, gate, finish_run],
                    activity_executor=executor,
                ),
                Worker(
                    env.client,
                    task_queue="docker",
                    activities=[authorize_tool, execute_tool],
                    activity_executor=executor,
                ),
            ):
                handle = await env.client.start_workflow(
                    RunWorkflow.run, item(prompt), id=f"run-{RUN}", task_queue="orchestrator"
                )
                return await handle.result()
        finally:
            executor.shutdown(wait=False)
            await env.shutdown()

    seen["result"] = asyncio.run(drive())
    return seen


def test_the_prompt_is_built_from_the_pack_and_the_tool_manifest() -> None:
    seen = run()

    assert seen["agent"] == "docker"
    assert seen["messages"][0] == {"role": "system", "content": "PACK:docker"}
    assert seen["messages"][1] == {"role": "user", "content": "which containers are running?"}
    assert [tool["function"]["name"] for tool in seen["tools"]] == ["inspect_containers"]


def test_the_requested_tool_is_authorized_then_executed_once() -> None:
    seen = run()

    assert seen["authorized"] == ["inspect_containers"]
    assert seen["executed"] == ["inspect_containers"]
    assert seen["gated"] == ["output"]
    assert seen["result"].status == "executed"


def test_the_answer_and_outcome_reach_run_end() -> None:
    seen = run()

    assert seen["end"].outcome == "completed"
    assert seen["end"].answer == "two containers are running"
    assert seen["end"].safety_flags == []


def test_a_prompt_blocked_by_dlp_never_reaches_a_tool() -> None:
    seen: dict[str, Any] = {"completions": 0}

    @activity.defn
    def system_prompt(agent: str) -> str:
        return "PACK"

    @activity.defn
    def tools(agent: str) -> list[dict[str, Any]]:
        return []

    @activity.defn
    def complete(request: ModelRequest) -> ModelTurn:
        seen["completions"] += 1
        return ModelTurn(blocked="dlp", detail="dlp_blocked")

    @activity.defn
    def gate(text: str, surface: str) -> str:
        return text

    @activity.defn
    def authorize_tool(call: ToolCall) -> PolicyOutcome:
        raise AssertionError("authorization must not happen for a blocked prompt")

    @activity.defn
    def execute_tool(call: ToolCall) -> ToolResult:
        raise AssertionError("execution must not happen for a blocked prompt")

    @activity.defn
    def finish_run(end: RunEnd) -> None:
        seen["end"] = end

    async def drive() -> ToolResult:
        env = await WorkflowEnvironment.start_time_skipping()
        executor = ThreadPoolExecutor(max_workers=4)
        try:
            async with (
                Worker(
                    env.client,
                    task_queue="orchestrator",
                    workflows=[RunWorkflow],
                    activities=[system_prompt, tools, complete, gate, finish_run],
                    activity_executor=executor,
                ),
                Worker(
                    env.client,
                    task_queue="docker",
                    activities=[authorize_tool, execute_tool],
                    activity_executor=executor,
                ),
            ):
                handle = await env.client.start_workflow(
                    RunWorkflow.run, item(), id=f"run-{RUN}", task_queue="orchestrator"
                )
                return await handle.result()
        finally:
            executor.shutdown(wait=False)
            await env.shutdown()

    seen["result"] = asyncio.run(drive())
    assert seen["end"].outcome == "dlp_blocked"
    assert seen["end"].safety_flags == ["dlp_blocked"]
    assert seen["result"].status == "denied"
