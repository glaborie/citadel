"""The bounded agent loop.

The loop is where an injection stops being an opinion. A model that obeys an
override still cannot act: every requested tool goes through `authorize`, a T1
tool without an approval is refused, and tool output is gated before it becomes
context again. The loop also owns the budget, so a model that keeps calling
tools is stopped by arithmetic rather than by hope.

The trajectory is the product. Each step is one event with a stable kind, so a
red-team case can assert on `policy.decision` or `budget.exceeded` without
parsing prose.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from citadel import dlp
from citadel.model.client import ModelUnavailable, contains_tool_markup
from citadel.model.types import (
    Budget,
    Outcome,
    Reply,
    Step,
    Trajectory,
    Usage,
)
from citadel.policy import Decision, load_catalog
from citadel.research.labels import external_flags

Authorize = Callable[[str], Decision]
Execute = Callable[[str, Mapping[str, Any]], str]
Gate = Callable[[str, str], str]
Complete = Callable[..., Reply]


def run_agent(
    *,
    complete: Complete,
    messages: Sequence[Mapping[str, Any]],
    authorize: Authorize,
    execute: Execute,
    gate: Gate,
    tools: Sequence[Mapping[str, Any]] = (),
    budget: Budget | None = None,
    alias: str | None = None,
    run_id: str = "",
    requires_tool: bool = False,
) -> Trajectory:
    plan = budget or Budget()
    steps: list[Step] = []
    usage = Usage.zero()
    conversation: list[dict[str, Any]] = [dict(message) for message in messages]

    for step_index in range(1, plan.max_steps + 1):
        try:
            reply = complete(messages=conversation, tools=tools, alias=alias, run_id=run_id)
        except dlp.DlpBlocked as exc:
            steps.append(Step("dlp.blocked", f"surface=input reason={exc.reason}"))
            steps.append(Step("run.end", "no model call: prompt blocked"))
            return Trajectory("dlp_blocked", tuple(steps), usage)
        except ModelUnavailable as exc:
            steps.append(Step("model.unavailable", str(exc)[:160]))
            steps.append(Step("run.end", "no model answer"))
            return Trajectory("refused", tuple(steps), usage)

        usage = usage.add(reply.usage)
        steps.append(
            Step(
                "model.call",
                f"step={step_index} model={reply.model} tokens={reply.usage.total} "
                f"cost={_cost(reply.usage)}",
                tokens=reply.usage.total,
                cost_usd=reply.usage.cost_usd,
            )
        )

        ceiling = plan.exceeded(usage, step_index)
        if ceiling is not None:
            steps.append(
                Step(
                    "budget.exceeded",
                    f"{ceiling} cost={_cost(usage)} source={usage.cost_source}",
                    tokens=usage.total,
                    cost_usd=usage.cost_usd,
                )
            )
            steps.append(Step("run.end", "aborted at budget"))
            return Trajectory("budget_exceeded", tuple(steps), usage)

        if not reply.tools and contains_tool_markup(reply.content):
            # A request in prose never reached `authorize`; completing here would
            # report the task done with the markup as its answer.
            steps.append(Step("run.end", "refused tool-call markup in content"))
            return Trajectory("refused", tuple(steps), usage)

        if not reply.tools:
            # Same rule as `ModelActivities.next_step`: an acting pack's answer
            # with no tool call and no observation behind it is a plan, not a
            # result. A plain chat loop keeps answering directly.
            if requires_tool and not any(step.kind == "tool.call" for step in steps):
                steps.append(
                    Step(
                        "run.end",
                        "refused: the pack requires a tool call and this reply asked for none",
                        flags=("model.no_tool_call",),
                    )
                )
                return Trajectory("refused", tuple(steps), usage)
            steps.append(Step("run.end", "answered without tools"))
            return Trajectory("completed", tuple(steps), usage, reply.content)

        conversation.append(_assistant_turn(reply))
        for requested in reply.tools:
            decision = authorize(requested.name)
            steps.append(
                Step(
                    "policy.decision",
                    f"{decision.outcome}/{decision.rule_id}",
                    tool=requested.name,
                    rule_id=decision.rule_id,
                    tier=decision.tier,
                )
            )
            if decision.outcome != "allow":
                outcome: Outcome = "policy_denied" if decision.outcome == "deny" else "refused"
                steps.append(Step("run.end", f"{requested.name} not executed: {decision.outcome}"))
                return Trajectory(outcome, tuple(steps), usage)

            output = execute(requested.name, requested.arguments)
            steps.append(Step("tool.call", requested.name, tool=requested.name))
            try:
                gated = gate(output, "output")
            except dlp.DlpBlocked as exc:
                steps.append(
                    Step("dlp.blocked", f"surface=output reason={exc.reason}", tool=requested.name)
                )
                steps.append(Step("run.end", "tool output blocked before context"))
                return Trajectory("dlp_blocked", tuple(steps), usage or Usage())
            steps.append(
                Step(
                    "dlp.scanned",
                    f"surface=output action=pass {len(gated)} chars",
                    tool=requested.name,
                )
            )
            flags = _content_flags(requested.name, gated)
            steps.append(
                Step("tool.result", f"{len(gated)} chars", tool=requested.name, flags=flags)
            )
            conversation.append(
                {
                    "role": "tool",
                    "tool_call_id": requested.call_id,
                    "name": requested.name,
                    "content": gated,
                }
            )

    steps.append(
        Step(
            "budget.exceeded",
            f"steps={plan.max_steps} exhausted without an answer cost={_cost(usage)}",
            tokens=usage.total,
            cost_usd=usage.cost_usd,
        )
    )
    steps.append(Step("run.end", "aborted at budget"))
    return Trajectory("budget_exceeded", tuple(steps), usage)


def _assistant_turn(reply: Reply) -> dict[str, Any]:
    """Echo the requested calls back, so the next turn has a coherent history."""
    return {
        "role": "assistant",
        "content": reply.content,
        "tool_calls": [
            {
                "id": call.call_id,
                "type": "function",
                "function": {"name": call.name, "arguments": _json(call.arguments)},
            }
            for call in reply.tools
        ],
    }


def _json(arguments: Mapping[str, Any]) -> str:
    return json.dumps(dict(arguments), sort_keys=True)


def _content_flags(tool: str, text: str) -> tuple[str, ...]:
    """Label web content in the loop exactly as the researcher activity does.

    A CLI tool's output is not `untrusted_external`: it came from the tenant's
    own infrastructure. The catalog decides, so the loop and the runtime agree.
    """
    spec = load_catalog().get(tool)
    if spec is None or spec.transport != "http":
        return ()
    return tuple(external_flags(text))


def _cost(usage: Usage) -> str:
    if usage.cost_source != "reported" or usage.cost_usd is None:
        return "unreported"
    return f"${usage.cost_usd:.6f}"
