"""Prometheus metrics for the controls and the money.

This is service-level telemetry, not a security control (ADR-015): a metrics
failure never changes a decision, and nothing here is a substitute for the audit
ledger. Every label is a closed set defined in this module - tenant, user, run
id, prompt text, tool arguments and rule text never become labels. A value that
is not in its set lands in `other` rather than creating a new time series.

Model cost is deliberately two counters. A gateway that reported `0.0` increments
the reported counter, and the USD counter gets a real zero. A gateway that
reported nothing increments the unreported counter and leaves the USD counter
alone, so "cost us nothing" and "we do not know" cannot become the same number.
"""

from __future__ import annotations

from typing import Final

from prometheus_client import Counter, Histogram, generate_latest, start_http_server
from prometheus_client.core import CollectorRegistry
from prometheus_client.exposition import CONTENT_TYPE_LATEST

REGISTRY: Final = CollectorRegistry(auto_describe=True)
CONTENT_TYPE: Final = CONTENT_TYPE_LATEST

RUN_OUTCOMES: Final = frozenset({"completed", "denied", "failed", "cancelled"})
MODEL_OUTCOMES: Final = frozenset({"ok", "unavailable", "dlp_blocked"})
DLP_SURFACES: Final = frozenset({"input", "output", "record"})
DLP_REASONS: Final = frozenset({"dlp_blocked", "dlp_unavailable"})
CACHE_RESULTS: Final = frozenset({"exact", "semantic", "miss"})
APPROVAL_DECISIONS: Final = frozenset({"approved", "denied"})
# The denial set is the one this deployment can emit. A new rule still counts,
# under `other`, until it is named here; a rule id from a request never does.
POLICY_RULES: Final = frozenset(
    {
        "identity.missing_tenant",
        "identity.missing_user",
        "identity.missing_run",
        "identity.missing_agent",
        "identity.unknown_run",
        "tool.unknown",
        "tool.tier_denied",
        "tool.agent_mismatch",
        "policy.denied",
        "policy.unavailable",
        "approval.tier_denied",
        "approval.self_approval_denied",
        "approval.relation_denied",
    }
)

RUNS: Final = Counter(
    "citadel_runs_total", "Finished runs, by bounded outcome.", ["outcome"], registry=REGISTRY
)
MODEL_CALLS: Final = Counter(
    "citadel_model_calls_total",
    "Model calls to the gateway, by bounded outcome.",
    ["outcome"],
    registry=REGISTRY,
)
MODEL_TOKENS: Final = Counter(
    "citadel_model_tokens_total",
    "Tokens reported by the gateway, by kind.",
    ["kind"],
    registry=REGISTRY,
)
MODEL_COST_REPORTED: Final = Counter(
    "citadel_model_cost_reported_total",
    "Model calls whose gateway reported a cost, zero included.",
    registry=REGISTRY,
)
MODEL_COST_UNREPORTED: Final = Counter(
    "citadel_model_cost_unreported_total",
    "Model calls whose gateway did not report a cost.",
    registry=REGISTRY,
)
MODEL_COST_USD: Final = Counter(
    "citadel_model_cost_usd_total",
    "Reported model cost in USD.",
    registry=REGISTRY,
)
DLP_BLOCKS: Final = Counter(
    "citadel_dlp_blocks_total",
    "DLP refusals, by surface and reason.",
    ["surface", "reason"],
    registry=REGISTRY,
)
POLICY_DENIALS: Final = Counter(
    "citadel_policy_denials_total",
    "Policy denials, by bounded rule id.",
    ["rule"],
    registry=REGISTRY,
)
CACHE_LOOKUPS: Final = Counter(
    "citadel_cache_lookups_total",
    "Cache lookups, by bounded result.",
    ["result"],
    registry=REGISTRY,
)
APPROVAL_WAIT: Final = Histogram(
    "citadel_approval_wait_seconds",
    "Seconds from approval request to decision.",
    ["decision"],
    buckets=(5, 15, 30, 60, 120, 300, 600, 1800, 3600),
    registry=REGISTRY,
)


def _label(value: str, allowed: frozenset[str]) -> str:
    return value if value in allowed else "other"


def run_finished(outcome: str) -> None:
    RUNS.labels(outcome=_label(outcome, RUN_OUTCOMES)).inc()


def model_call(outcome: str) -> None:
    MODEL_CALLS.labels(outcome=_label(outcome, MODEL_OUTCOMES)).inc()


def model_usage(
    *, prompt_tokens: int, completion_tokens: int, cost_usd: float | None, cost_source: str
) -> None:
    """Tokens and cost from one successful model reply."""
    MODEL_TOKENS.labels(kind="prompt").inc(max(prompt_tokens, 0))
    MODEL_TOKENS.labels(kind="completion").inc(max(completion_tokens, 0))
    if cost_usd is None or cost_source != "reported":
        MODEL_COST_UNREPORTED.inc()
        return
    MODEL_COST_REPORTED.inc()
    if cost_usd > 0:  # a counter cannot go down; a credit is not a cost observation
        MODEL_COST_USD.inc(cost_usd)


def dlp_block(*, surface: str, reason: str) -> None:
    DLP_BLOCKS.labels(
        surface=_label(surface, DLP_SURFACES), reason=_label(reason, DLP_REASONS)
    ).inc()


def policy_denial(rule_id: str) -> None:
    POLICY_DENIALS.labels(rule=_label(rule_id, POLICY_RULES)).inc()


def cache_lookup(result: str) -> None:
    CACHE_LOOKUPS.labels(result=_label(result, CACHE_RESULTS)).inc()


def approval_decision(decision: str, seconds: float) -> None:
    APPROVAL_WAIT.labels(decision=_label(decision, APPROVAL_DECISIONS)).observe(max(seconds, 0.0))


def render() -> bytes:
    return generate_latest(REGISTRY)


def serve(port: int) -> int:
    """Expose this process's registry on `port`, returning the bound port."""
    server, _thread = start_http_server(port, registry=REGISTRY)
    return int(server.server_address[1])
