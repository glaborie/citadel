"""Workflow behaviour: approval gating, TTL auto-deny, retries, idempotency.

Uses Temporal's time-skipping test environment, so the 15-minute approval TTL
elapses instantly. Activities are stubbed by name; no database or OpenFGA is
needed.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from typing import Any

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from citadel.workflows import orchestrator
from citadel.workflows.activities import idempotency_key
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import (
    ApprovalDecision,
    PolicyOutcome,
    RunInput,
    ToolCall,
    ToolResult,
)

QUEUE = "docker"


def call() -> ToolCall:
    return ToolCall(
        run_id="11111111-1111-1111-1111-111111111111",
        tenant_id="lab-a",
        user_id="user-alice",
        agent_id="docker",
        tool="read_logs",
        arguments={"container": "checkout-api"},
    )


def outcome(name: str, tier: str = "T0") -> PolicyOutcome:
    return PolicyOutcome(outcome=name, rule_id=f"policy.{name}", reason="scripted", tier=tier)


async def run_workflow(
    *,
    policy: PolicyOutcome,
    approve: ApprovalDecision | None = None,
    execute_failures: int = 0,
    start: ToolCall | None = None,
) -> tuple[ToolResult, list[ToolCall]]:
    executed: list[ToolCall] = []
    remaining = {"failures": execute_failures}

    @activity.defn(name="authorize_tool")
    def stub_authorize(_call: ToolCall) -> PolicyOutcome:
        return policy

    @activity.defn(name="execute_tool")
    def stub_execute(item: ToolCall) -> ToolResult:
        if remaining["failures"] > 0:
            remaining["failures"] -= 1
            raise RuntimeError("transient tool failure")
        executed.append(item)
        return ToolResult(
            status="executed", tool=item.tool, rule_id="tool.executed", detail="stub ran"
        )

    # Sync activities need an executor; the same requirement applies in worker.py.
    env = await WorkflowEnvironment.start_time_skipping()
    executor = ThreadPoolExecutor(max_workers=4)
    try:
        async with Worker(
            env.client,
            task_queue=QUEUE,
            workflows=[SpecialistWorkflow],
            activities=[stub_authorize, stub_execute],
            activity_executor=executor,
        ):
            handle = await env.client.start_workflow(
                SpecialistWorkflow.run, start or call(), id="wf-1", task_queue=QUEUE
            )
            if approve is not None:
                await handle.signal(SpecialistWorkflow.approve, approve)
            result: ToolResult = await handle.result()
            return result, executed
    finally:
        executor.shutdown(wait=False)
        await env.shutdown()


def test_denied_by_policy_never_executes() -> None:
    result, executed = asyncio.run(run_workflow(policy=outcome("deny")))
    assert result.status == "denied"
    assert executed == []


def test_t0_executes_immediately() -> None:
    result, executed = asyncio.run(run_workflow(policy=outcome("allow")))
    assert result.status == "executed"
    assert len(executed) == 1


def test_t1_waits_for_approval_then_executes() -> None:
    approved = ApprovalDecision(approved=True, approver="user-carol", reason="looks fine")
    result, executed = asyncio.run(
        run_workflow(policy=outcome("requires_approval", "T1"), approve=approved)
    )
    assert result.status == "executed"
    assert len(executed) == 1


def test_t1_denied_by_approver_does_not_execute() -> None:
    refused = ApprovalDecision(approved=False, approver="user-carol", reason="not now")
    result, executed = asyncio.run(
        run_workflow(policy=outcome("requires_approval", "T1"), approve=refused)
    )
    assert result.status == "denied"
    assert result.rule_id == "approval.denied"
    assert executed == []


def test_an_approved_call_keeps_its_content_flags() -> None:
    """The approved rebuild must not launder the taint out of the call (ADR-028)."""
    tainted = replace(call(), content_flags=["untrusted_external", "prompt_injection"])
    approved = ApprovalDecision(approved=True, approver="user-carol", reason="seen the flags")
    result, executed = asyncio.run(
        run_workflow(policy=outcome("requires_approval", "T1"), approve=approved, start=tainted)
    )
    assert result.status == "executed"
    assert len(executed) == 1
    assert executed[0].content_flags == ["untrusted_external", "prompt_injection"]


def test_t1_without_a_decision_expires_to_deny() -> None:
    """TTL expiry must auto-deny, never auto-approve."""
    result, executed = asyncio.run(run_workflow(policy=outcome("requires_approval", "T1")))
    assert result.status == "denied"
    assert result.rule_id == "approval.expired"
    assert executed == []


def test_transient_tool_failure_is_retried() -> None:
    result, executed = asyncio.run(run_workflow(policy=outcome("allow"), execute_failures=2))
    assert result.status == "executed"
    assert len(executed) == 1, "the side effect must happen once despite two retries"


def test_idempotency_key_is_stable_and_argument_order_independent() -> None:
    a = ToolCall("run-1", "lab-a", "u", "docker", "read_logs", {"b": 2, "a": 1})
    b = ToolCall("run-1", "lab-a", "u", "docker", "read_logs", {"a": 1, "b": 2})
    assert idempotency_key(a) == idempotency_key(b)


def test_idempotency_key_differs_per_tool_and_run() -> None:
    base: dict[str, Any] = {"container": "x"}
    keys = {
        idempotency_key(ToolCall("run-1", "lab-a", "u", "docker", "read_logs", base)),
        idempotency_key(ToolCall("run-1", "lab-a", "u", "docker", "restart_service", base)),
        idempotency_key(ToolCall("run-2", "lab-a", "u", "docker", "read_logs", base)),
    }
    assert len(keys) == 3


def test_a_fetched_page_label_survives_into_run_end_flags() -> None:
    result = ToolResult(
        status="executed",
        tool="fetch_page",
        rule_id="research.fetch",
        detail="stub",
        content_flags=["untrusted_external", "prompt_injection"],
    )
    assert orchestrator._safety_flags(result) == ["prompt_injection", "untrusted_external"]


def test_a_task_run_gets_the_documented_step_ceiling() -> None:
    """#274: three steps ran out mid-tool-use, so the model never answered.

    `Budget` and docs/security/llm-top10-mapping.md both say six; only this
    default disagreed, and it is the one a submitted task actually gets.
    """
    run = RunInput(run_id="run-1", tenant_id="lab-a", user_id="u", agent_id="docker", tool="")
    assert run.max_steps == 6, (
        "three steps let a model call three tools and never a fourth step to answer"
    )


def test_a_dlp_refusal_still_adds_its_own_flag() -> None:
    result = ToolResult(
        status="denied",
        tool="fetch_page",
        rule_id="dlp.blocked",
        detail="stub",
        content_flags=["untrusted_external"],
    )
    assert orchestrator._safety_flags(result) == ["dlp_blocked", "untrusted_external"]
