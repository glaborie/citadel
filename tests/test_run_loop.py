"""The run loop: ask the model, delegate what it asks for, stop on an answer or a budget.

Uses Temporal's time-skipping environment with the model step and the specialist
activities stubbed by name, so this tests the *sequencing* - which is the only
thing the workflow decides - without a gateway, a database or a policy server.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from citadel import dlp
from citadel.audit import AuditLedger
from citadel.model import Reply, ScriptedClient, Usage
from citadel.retrieval.types import RetrievalOutcome, RetrievalRequest
from citadel.workflows.activities import _run_outputs
from citadel.workflows.model_step import (
    ModelActivities,
    ModelStepRequest,
    ModelStepResult,
)
from citadel.workflows.orchestrator import RunWorkflow, child_workflow_id
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import PolicyOutcome, RunEnd, RunInput, ToolCall, ToolResult

QUEUE = "orchestrator"
SPECIALIST_QUEUE = "docker"


class _Audit(AuditLedger):
    def append(self, **kwargs: Any) -> Any:  # noqa: ANN401 - test double
        from types import SimpleNamespace

        return SimpleNamespace(audit_id="audit-1")


class _Detector:
    """The DLP gate's opener: answers with no findings."""

    def __call__(self, request: Any, timeout: Any = None) -> _Detector:  # noqa: ANN401
        self._body = b"[]"
        return self

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Detector:
        return self

    def __exit__(self, *_: object) -> None:
        return None


class _BlockedClient:
    def complete(self, **kwargs: Any) -> Any:  # noqa: ANN401 - raises before a reply
        raise dlp.DlpBlocked(
            "dlp_blocked", {"surface": "input", "action": "block", "categories": []}
        )


def task_input(**overrides: Any) -> RunInput:
    base: dict[str, Any] = {
        "run_id": "22222222-2222-2222-2222-222222222222",
        "tenant_id": "lab-a",
        "user_id": "user-alice",
        "agent_id": "docker",
        "tool": "",
        "task": "why is checkout-api restarting?",
        "max_steps": 3,
    }
    base.update(overrides)
    return RunInput(**base)


def answered(content: str = "it restarted twice") -> ModelStepResult:
    return ModelStepResult(
        status="answered",
        rule_id="model.answered",
        detail="answered",
        content=content,
        prompt_digest="d" * 64,
        prompt_pack="docker-1.0.0@1.0.0",
        prompt_tokens=100,
        completion_tokens=20,
        cost_usd=0.001,
        cost_source="reported",
    )


def wants(tool: str = "read_logs") -> ModelStepResult:
    return ModelStepResult(
        status="tool_requested",
        rule_id="model.tool_requested",
        detail="asked for a tool",
        content="checking",
        tool=tool,
        arguments={"service": "checkout-api"},
        prompt_tokens=120,
        completion_tokens=30,
        cost_usd=0.002,
        cost_source="reported",
    )


async def run_task(
    steps: list[ModelStepResult] | None = None,
    *,
    next_step: Callable[[ModelStepRequest], ModelStepResult] | None = None,
    policy: PolicyOutcome | None = None,
    tool_status: str = "executed",
) -> tuple[ToolResult, list[ModelStepRequest], list[ToolCall], list[RunEnd]]:
    """Model step answers are taken in order; the last one repeats."""
    seen_requests: list[ModelStepRequest] = []
    seen_calls: list[ToolCall] = []
    ends: list[RunEnd] = []
    queue = list(steps or [])
    decision = policy or PolicyOutcome(
        outcome="allow", rule_id="policy.allowed", reason="stub", tier="T0"
    )

    @activity.defn(name="next_step")
    def stub_next_step(request: ModelStepRequest) -> ModelStepResult:
        seen_requests.append(request)
        if next_step is not None:
            return next_step(request)
        return queue.pop(0) if len(queue) > 1 else queue[0]

    @activity.defn(name="retrieve")
    def stub_retrieve(_request: RetrievalRequest) -> RetrievalOutcome:
        return RetrievalOutcome(status="refused", rule_id="retrieval.stubbed", detail="no evidence")

    @activity.defn(name="finish_run")
    def stub_finish_run(end: RunEnd) -> None:
        ends.append(end)

    @activity.defn(name="authorize_tool")
    def stub_authorize(_call: ToolCall) -> PolicyOutcome:
        return decision

    @activity.defn(name="execute_tool")
    def stub_execute(item: ToolCall) -> ToolResult:
        seen_calls.append(item)
        return ToolResult(
            status=tool_status, tool=item.tool, rule_id="tool.executed", detail="stub"
        )

    env = await WorkflowEnvironment.start_time_skipping()
    executor = ThreadPoolExecutor(max_workers=6)
    try:
        async with (
            Worker(
                env.client,
                task_queue=QUEUE,
                workflows=[RunWorkflow],
                activities=[stub_retrieve, stub_next_step, stub_finish_run],
                activity_executor=executor,
            ),
            Worker(
                env.client,
                task_queue=SPECIALIST_QUEUE,
                workflows=[SpecialistWorkflow],
                activities=[stub_authorize, stub_execute],
                activity_executor=executor,
            ),
        ):
            handle = await env.client.start_workflow(
                RunWorkflow.run, task_input(), id="run-loop-1", task_queue=QUEUE
            )
            result: ToolResult = await handle.result()
            return result, seen_requests, seen_calls, ends
    finally:
        executor.shutdown(wait=False)
        await env.shutdown()


def test_an_answer_ends_the_run_without_a_tool() -> None:
    result, requests, calls, ends = asyncio.run(run_task([answered()]))

    assert (result.status, result.rule_id) == ("executed", "model.answered")
    assert result.output["answer"] == "it restarted twice"
    assert calls == [], "the model asked for nothing, so nothing ran"
    assert len(requests) == 1
    assert ends[0].outcome == "completed"


def test_a_tool_request_is_delegated_then_answered() -> None:
    """The loop's whole shape: one step requests, the next answers."""
    result, requests, calls, ends = asyncio.run(run_task([wants(), answered("two restarts")]))

    assert result.status == "executed"
    assert result.output["answer"] == "two restarts"
    assert [call.tool for call in calls] == ["read_logs"]
    assert "service" in calls[0].arguments
    assert len(requests) == 2, "the tool result has to reach a second model step"
    assert requests[1].history, "step two must see what step one said"
    assert requests[1].history[0]["role"] == "assistant"
    assert ends[0].outcome == "completed"


def test_the_specialist_reports_the_child_id_the_orchestrator_minted() -> None:
    """The approval row records this id, so it must be the one the orchestrator used."""
    _, _, calls, _ = asyncio.run(run_task([wants("restart_service"), answered()]))

    assert calls[0].workflow_id == child_workflow_id(task_input().run_id, "restart_service", 1)


def test_a_denied_tool_is_fed_back_not_hidden() -> None:
    """A refusal is an answer the model has to work with, and the run still ends."""
    result, requests, calls, _ = asyncio.run(
        run_task(
            [wants(), answered("I cannot read the logs")],
            policy=PolicyOutcome(outcome="deny", rule_id="policy.denied", reason="no", tier="T1"),
            tool_status="denied",
        )
    )

    assert result.output["answer"] == "I cannot read the logs"
    assert calls == [], "a policy deny never reaches the sandbox"
    tool_turn = requests[1].history[1]
    assert tool_turn["role"] == "user"
    assert "policy.denied" in tool_turn["content"]


def test_no_answer_within_the_budget_is_a_failure_not_a_hang() -> None:
    result, requests, calls, ends = asyncio.run(run_task([wants("read_logs")]))

    assert result.status == "failed"
    assert result.rule_id == "budget.exceeded"
    assert len(requests) == 3, "three steps, no answer"
    assert len(calls) == 3
    assert ends[0].outcome == "failed"
    assert "budget_exceeded" in ends[0].safety_flags


def test_a_dlp_blocked_step_denies_the_run() -> None:
    blocked = ModelStepResult(
        status="dlp_blocked", rule_id="dlp.blocked", detail="refused at the output surface"
    )
    result, _, calls, ends = asyncio.run(run_task([blocked]))

    assert (result.status, result.rule_id) == ("denied", "dlp.blocked")
    assert calls == []
    assert ends[0].outcome == "denied"
    assert "dlp_blocked" in ends[0].safety_flags


def test_a_dlp_refusal_inside_complete_denies_the_run_and_writes_run_end() -> None:
    """#169: the input gate raises from `complete`; that must be a step result."""
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=_Audit("postgres://unused"),
        client_factory=lambda alias: _BlockedClient(),
        analyzer=_Detector(),
    )

    result, requests, calls, ends = asyncio.run(run_task(next_step=activities.next_step))

    assert (result.status, result.rule_id) == ("denied", "dlp.blocked")
    assert len(requests) == 1, "the refusal is a result, not a retried activity failure"
    assert calls == []
    assert ends[0].outcome == "denied"
    assert "dlp_blocked" in ends[0].safety_flags


def test_a_plan_from_an_acting_pack_denies_the_run_and_flags_it() -> None:
    """#209 end to end: `tr-84819553` recorded `completed`; it must record `denied`."""
    plan = Reply(
        content="I'll start with the read-only checks, since they don't depend on each other.",
        tools=(),
        usage=Usage(
            prompt_tokens=1090, completion_tokens=193, cost_usd=0.001, cost_source="reported"
        ),
        model="auto/best-fast",
        latency_ms=9,
    )
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=_Audit("postgres://unused"),
        client_factory=lambda alias: ScriptedClient([plan]),
        analyzer=_Detector(),
    )

    result, requests, calls, ends = asyncio.run(run_task(next_step=activities.next_step))

    assert (result.status, result.rule_id) == ("denied", "model.no_tool_call")
    assert result.output.get("answer", "") == "", "the plan is not the run's answer"
    assert len(requests) == 1, "a refusal ends the run; it is not retried into a result"
    assert calls == []
    assert ends[0].outcome == "denied"
    # The trace's root span is built from this same end row, so it cannot disagree.
    outputs = _run_outputs(ends[0])
    assert (outputs["outcome"], outputs["answer"], outputs["safety_flags"]) == (
        "denied",
        "",
        ["model.no_tool_call"],
    )


async def run_failing_task(error: Exception) -> list[RunEnd]:
    ends: list[RunEnd] = []

    @activity.defn(name="next_step")
    def failing_next_step(_request: ModelStepRequest) -> ModelStepResult:
        raise error

    @activity.defn(name="retrieve")
    def stub_retrieve(_request: RetrievalRequest) -> RetrievalOutcome:
        return RetrievalOutcome(status="refused", rule_id="retrieval.stubbed", detail="no evidence")

    @activity.defn(name="finish_run")
    def stub_finish_run(end: RunEnd) -> None:
        ends.append(end)

    env = await WorkflowEnvironment.start_time_skipping()
    executor = ThreadPoolExecutor(max_workers=4)
    try:
        async with Worker(
            env.client,
            task_queue=QUEUE,
            workflows=[RunWorkflow],
            activities=[stub_retrieve, failing_next_step, stub_finish_run],
            activity_executor=executor,
        ):
            handle = await env.client.start_workflow(
                RunWorkflow.run, task_input(), id="run-failing-1", task_queue=QUEUE
            )
            try:
                await handle.result()
            except Exception:
                pass
            else:
                raise AssertionError("a crashing activity must surface as a workflow failure")
            return ends
    finally:
        executor.shutdown(wait=False)
        await env.shutdown()


def test_an_unexpected_activity_failure_still_writes_run_end() -> None:
    ends = asyncio.run(run_failing_task(RuntimeError("boom")))

    assert len(ends) == 1
    assert ends[0].outcome == "failed"
    assert ends[0].safety_flags == ["workflow_error"]


def test_a_gateway_outage_fails_the_run() -> None:
    down = ModelStepResult(status="unavailable", rule_id="model.unavailable", detail="no answer")
    result, _, _, ends = asyncio.run(run_task([down]))

    assert (result.status, result.rule_id) == ("failed", "model.unavailable")
    assert ends[0].outcome == "failed"
