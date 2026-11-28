"""Orchestrator workflow: owns sequencing and holds no side-effecting tools.

Two shapes of run, one code path for finishing:

* a **tool run** names a tool and its arguments, and the orchestrator delegates
  that single call to a specialist - the pre-loop behaviour, kept because the red
  team exercises it directly;
* a **task run** carries a task instead, and the orchestrator iterates: ask the
  model for one step, delegate whatever tool it requests to a specialist, feed the
  result back, and stop on an answer or on the budget.

The workflow decides *how many* steps and *what order*; every model call and every
tool call is an activity or a child workflow, so nothing here is replayed
non-deterministically.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from temporalio import workflow
from temporalio.common import RetryPolicy

# Budget/Usage are pure, but the module also holds the gateway client, which
# imports DLP and (through it) prometheus_client. Keep that chain unsandboxed.
with workflow.unsafe.imports_passed_through():
    from citadel.model import Budget, Usage
from citadel.retrieval.types import RetrievalOutcome, RetrievalRequest
from citadel.workflows import activities
from citadel.workflows.model_step import (
    ModelActivities,
    ModelStepRequest,
    assistant_turn,
    tool_turn,
)
from citadel.workflows.specialist import SpecialistWorkflow
from citadel.workflows.types import TASK_QUEUES, RunEnd, RunInput, ToolCall, ToolResult


def child_workflow_id(run_id: str, tool: str, step: int = 0) -> str:
    """Step-scoped: two calls to the same tool are two child workflows."""
    return f"run-{run_id}-{step}-{tool}"


def _outcome(result: ToolResult) -> str:
    if result.status in {"executed", "replayed"}:
        return "completed"
    if result.status == "denied":
        return "denied"
    return "failed"


def _safety_flags(result: ToolResult) -> list[str]:
    flags = set(result.content_flags)
    if result.rule_id.startswith("dlp."):
        flags.add("dlp_blocked")
    if result.rule_id.startswith("budget."):
        flags.add("budget_exceeded")
    if result.rule_id == "model.no_tool_call":
        # The run refused the answer; the trace's root output says why too.
        flags.add("model.no_tool_call")
    return sorted(flags)


@dataclass(frozen=True)
class RunAnswer:
    """What a run produced: the text, and the documents behind it.

    Three parallel parameters said one thing badly - `_finish` took the answer, the citation ids
    and the sources separately, and every caller had to keep them in step. One object, built from
    the activity's output, is the shape the trace and the ledger both read.
    """

    text: str = ""
    citation_ids: tuple[str, ...] = ()
    sources: tuple[dict[str, Any], ...] = ()

    @classmethod
    def from_output(cls, output: Mapping[str, Any] | None) -> RunAnswer:
        payload = output or {}
        citations = payload.get("citations")
        rows = (
            [item for item in citations if isinstance(item, dict)]
            if isinstance(citations, list)
            else []
        )
        return cls(
            text=str(payload.get("answer", ""))[:4000],
            citation_ids=tuple(str(citation) for citation in payload.get("citation_ids", [])),
            sources=tuple(
                {
                    "id": str(row.get("chunk_id", "")),
                    "source_uri": str(row.get("source_uri", "")),
                    "revision": str(row.get("revision", ""))[:12],
                    "score": row.get("score"),
                }
                for row in rows
            ),
        )


@workflow.defn
class RunWorkflow:
    @workflow.run
    async def run(self, item: RunInput) -> ToolResult:
        try:
            result = await self._task_run(item) if item.task else await self._tool_run(item)
        except Exception:
            # An activity that dies must not leave the row at `created` with no
            # trajectory end. Close it, then keep the failure visible.
            await self._finish(item, outcome="failed", safety_flags=["workflow_error"])
            raise

        # run.end is written by an activity, never by the workflow itself, so a
        # retried finish cannot fork the trajectory.
        await self._finish(
            item,
            outcome=_outcome(result),
            safety_flags=_safety_flags(result),
            answer=RunAnswer.from_output(result.output),
        )
        return result

    async def _finish(
        self,
        item: RunInput,
        *,
        outcome: str,
        safety_flags: list[str],
        answer: RunAnswer | None = None,
    ) -> None:
        await workflow.execute_activity_method(
            activities.RunActivities.finish_run,
            RunEnd(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                outcome=outcome,
                citation_ids=list(answer.citation_ids) if answer else [],
                sources=list(answer.sources) if answer else [],
                safety_flags=safety_flags,
                answer=answer.text if answer else "",
                task=item.task,
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=RetryPolicy(maximum_attempts=3),
        )

    async def _tool_run(self, item: RunInput) -> ToolResult:
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
            run_token=item.run_token,
        )
        return await workflow.execute_child_workflow(
            SpecialistWorkflow.run,
            call,
            id=child_workflow_id(item.run_id, item.tool),
            task_queue=queue,
        )

    async def _task_run(self, item: RunInput) -> ToolResult:
        budget = Budget(max_steps=item.max_steps)
        usage = Usage.zero()
        history: list[dict[str, Any]] = []
        # A label earned by one fetched page describes the run, not just that
        # step: the answer that follows must still carry it to run.end, and the
        # tool call that follows must show it to the approver (ADR-028).
        flags: set[str] = set()
        tool_name = item.tool or "model"
        # One search before the first step: the evidence joins the task, so every
        # step of the run sees the same retrieved context.
        evidence, citations = await _retrieve(item)
        task = f"{item.task}\n\n{evidence}" if evidence else item.task

        for step_no in range(1, item.max_steps + 1):
            step = await workflow.execute_activity_method(
                ModelActivities.next_step,
                ModelStepRequest(
                    run_id=item.run_id,
                    tenant_id=item.tenant_id,
                    user_id=item.user_id,
                    agent_id=item.agent_id,
                    task=task,
                    model_alias=item.model_alias,
                    pack_version=item.prompt_pack_version,
                    entitlements=list(item.entitlements),
                    history=history,
                ),
                start_to_close_timeout=timedelta(minutes=3),
                retry_policy=RetryPolicy(maximum_attempts=2),
            )
            usage = usage.add(
                Usage(
                    prompt_tokens=step.prompt_tokens,
                    completion_tokens=step.completion_tokens,
                    cost_usd=step.cost_usd,
                    cost_source="reported" if step.cost_source == "reported" else "unreported",
                )
            )

            if step.status == "answered":
                return ToolResult(
                    status="executed",
                    tool=tool_name,
                    rule_id="model.answered",
                    detail=step.detail,
                    output={
                        "answer": step.content,
                        "prompt_pack": step.prompt_pack,
                        "prompt_digest": step.prompt_digest,
                        "steps": step_no,
                        "tokens": usage.total,
                        "cost_usd": usage.cost_usd,
                        "cost_source": usage.cost_source,
                        "citation_ids": citations,
                    },
                    content_flags=sorted(flags),
                )
            if step.status in {"refused", "dlp_blocked"}:
                return ToolResult(
                    status="denied",
                    tool=tool_name,
                    rule_id=step.rule_id,
                    detail=step.detail,
                    output={"citation_ids": citations},
                    content_flags=sorted(flags),
                )
            if step.status != "tool_requested":
                return ToolResult(
                    status="failed",
                    tool=tool_name,
                    rule_id=step.rule_id,
                    detail=step.detail,
                    output={"citation_ids": citations},
                    content_flags=sorted(flags),
                )

            queue = TASK_QUEUES.get(item.agent_id)
            if queue is None:
                return ToolResult(
                    status="denied",
                    tool=step.tool,
                    rule_id="delegation.unknown_agent",
                    detail=f"no specialist worker for agent {item.agent_id!r}",
                    output={"citation_ids": citations},
                    content_flags=sorted(flags),
                )

            call = ToolCall(
                run_id=item.run_id,
                tenant_id=item.tenant_id,
                user_id=item.user_id,
                agent_id=item.agent_id,
                tool=step.tool,
                arguments=step.arguments,
                content_flags=sorted(flags),
                run_token=item.run_token,
            )
            tool_result = await workflow.execute_child_workflow(
                SpecialistWorkflow.run,
                call,
                id=child_workflow_id(item.run_id, step.tool, step_no),
                task_queue=queue,
            )
            flags.update(tool_result.content_flags)

            # The model needs the observation, not the rule that produced it.
            # Without the tool's own output the next step can only ask again,
            # and a repeated call replays on its idempotency key.
            observation = (
                tool_result.output.get("stdout")
                or tool_result.output.get("stderr")
                or tool_result.detail
            )
            history.extend(
                (
                    assistant_turn(step),
                    tool_turn(
                        {
                            "detail": f"{tool_result.rule_id}: {observation}",
                            "status": tool_result.status,
                        }
                    ),
                )
            )
            exceeded = budget.exceeded(usage, step_no)
            if exceeded is not None:
                return ToolResult(
                    status="failed",
                    tool=tool_name,
                    rule_id="budget.exceeded",
                    detail=f"stopped after {step_no} steps: {exceeded}",
                    output={
                        "steps": step_no,
                        "tokens": usage.total,
                        "cost_usd": usage.cost_usd,
                        "citation_ids": citations,
                    },
                    content_flags=sorted(flags),
                )

        return ToolResult(
            status="failed",
            tool=tool_name,
            rule_id="budget.exceeded",
            detail=f"no answer within {item.max_steps} steps",
            output={
                "steps": item.max_steps,
                "tokens": usage.total,
                "cost_usd": usage.cost_usd,
                "citation_ids": citations,
            },
            content_flags=sorted(flags),
        )


async def _retrieve(item: RunInput) -> tuple[str, list[str]]:
    """The evidence block and citation ids for this run, or nothing on refusal.

    Retrieval is not a security gate: a refusal leaves the run without evidence,
    exactly the trajectory a run had before it had a caller.
    """
    outcome = await workflow.execute_activity(
        "retrieve",
        _retrieval_request(item),
        result_type=RetrievalOutcome,
        start_to_close_timeout=timedelta(minutes=2),
        retry_policy=RetryPolicy(maximum_attempts=2),
    )
    if outcome.status != "answered" or not outcome.chunks:
        return "", []
    return _evidence(outcome), [str(chunk["chunk_id"]) for chunk in outcome.chunks]


def _retrieval_request(item: RunInput) -> RetrievalRequest:
    return RetrievalRequest(
        run_id=item.run_id,
        tenant_id=item.tenant_id,
        user_id=item.user_id,
        agent_id=item.agent_id,
        query=item.task,
        # The run's ACL tag set. Roles partition the answer cache; the corpus
        # entitlement a run holds is its tenant, and the activity refuses a set
        # that does not carry this tenant's tag.
        entitlements=[f"tenant:{item.tenant_id}"],
    )


def _evidence(outcome: RetrievalOutcome) -> str:
    """Retrieved chunks as one message the model can cite; text is DLP-cleaned."""
    blocks = [
        f"chunk_id={chunk['chunk_id']} source_uri={chunk['source_uri']}"
        f" revision={chunk['revision']} score={float(chunk['score']):.3f}\n{chunk['text']}"
        for chunk in outcome.chunks
    ]
    header = "[retrieved evidence - cite a chunk_id or source_uri you rely on]"
    return "\n\n".join([header, *blocks])
