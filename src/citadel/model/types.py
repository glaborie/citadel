"""Types shared by the client, the scripted double and the loop.

Cost is deliberately not a float that defaults to zero. A gateway that reports
`usage.cost` gives a real number; one that does not gives `None`, and every
total that mixes a reported call with an unreported one is `None` too. The
report then says "unreported" instead of claiming a run was free.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

CostSource = Literal["reported", "unreported"]
Outcome = Literal["completed", "refused", "policy_denied", "dlp_blocked", "budget_exceeded"]


@dataclass(frozen=True)
class Usage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0
    cost_usd: float | None = None
    cost_source: CostSource = "unreported"

    @classmethod
    def zero(cls) -> Usage:
        """The identity for `add`: zero cost, but reported, not unknown."""
        return cls(cost_usd=0.0, cost_source="reported")

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, other: Usage) -> Usage:
        """Totals propagate doubt: one unreported call makes the total unreported."""
        both_reported = self.cost_source == "reported" and other.cost_source == "reported"
        cost = (
            (self.cost_usd or 0.0) + (other.cost_usd or 0.0)
            if both_reported
            else None
        )
        return Usage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            cached_tokens=self.cached_tokens + other.cached_tokens,
            cost_usd=cost,
            cost_source="reported" if both_reported else "unreported",
        )


@dataclass(frozen=True)
class RequestedTool:
    name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass(frozen=True)
class Reply:
    content: str
    tools: tuple[RequestedTool, ...]
    usage: Usage
    model: str
    latency_ms: int


@dataclass(frozen=True)
class Budget:
    """Per-run ceiling. Steps are counted, tokens and cost are measured."""

    max_steps: int = 6
    max_tokens: int = 8000
    max_cost_usd: float | None = 0.01

    def exceeded(self, usage: Usage, steps: int) -> str | None:
        if steps > self.max_steps:
            return f"steps={steps} > max_steps={self.max_steps}"
        if usage.total > self.max_tokens:
            return f"tokens={usage.total} > max_tokens={self.max_tokens}"
        if (
            self.max_cost_usd is not None
            and usage.cost_usd is not None
            and usage.cost_usd > self.max_cost_usd
        ):
            return f"cost={usage.cost_usd:.6f} > max_cost_usd={self.max_cost_usd}"
        return None


StepKind = Literal[
    "model.call",
    "model.unavailable",
    "dlp.scanned",
    "dlp.blocked",
    "policy.decision",
    "tool.call",
    "tool.result",
    "budget.exceeded",
    "run.end",
]


@dataclass(frozen=True)
class Step:
    kind: StepKind
    detail: str
    tool: str | None = None
    rule_id: str | None = None
    tier: str | None = None
    tokens: int = 0
    cost_usd: float | None = None


@dataclass(frozen=True)
class Trajectory:
    outcome: Outcome
    steps: tuple[Step, ...]
    usage: Usage
    text: str = ""

    def events(self) -> tuple[str, ...]:
        return tuple(step.kind for step in self.steps)

    def tools_executed(self) -> tuple[str, ...]:
        return tuple(
            step.tool for step in self.steps if step.kind == "tool.call" and step.tool is not None
        )

    def summary(self) -> dict[str, Any]:
        """What the report may print: outcomes, counts and cost, never payloads."""
        return {
            "outcome": self.outcome,
            "steps": len(self.steps),
            "tokens": self.usage.total,
            "cost_usd": self.usage.cost_usd,
            "cost_source": self.usage.cost_source,
            "events": list(self.events()),
            "tools_executed": list(self.tools_executed()),
        }
