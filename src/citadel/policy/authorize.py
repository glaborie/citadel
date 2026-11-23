"""The single authorisation chokepoint.

Every tool call passes through `authorize`. Nothing else may read policy, and
no caller may supply its own tenant: the tenant comes from the verified token.

Fail-closed rules, in the order they are enforced (docs/security/tool-tiers.md):

1. missing tenant, user, run or agent        -> deny
2. tool absent from the catalog             -> deny
3. T2 tier                                  -> deny
4. requesting agent != owning agent         -> deny
5. run id does not exist in this tenant     -> deny
6. policy service unreachable or erroring   -> deny
7. OpenFGA says no                          -> deny
8. allowed and T1                           -> requires_approval
9. allowed and T0                           -> allow
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from citadel.policy.catalog import ToolSpec, load_catalog

Outcome = Literal["allow", "requires_approval", "deny"]

POLICY_USER_PREFIX = "user:"


def tool_object(tenant_id: str, tool: str) -> str:
    # OpenFGA object ids cannot contain ":": the second colon breaks parsing.
    return f"tool:{tenant_id}/{tool}"


@dataclass(frozen=True)
class AuthorizationRequest:
    user_id: str
    tenant_id: str
    run_id: str
    agent_id: str
    tool: str


@dataclass(frozen=True)
class Decision:
    outcome: Outcome
    rule_id: str
    reason: str
    tier: str


class RelationChecker(Protocol):
    """Seam over OpenFGA so tests never need a live policy server."""

    def can_call(self, *, user: str, obj: str) -> bool: ...


class RunStore(Protocol):
    """Proves the run belongs to the caller's tenant before anything is authorised.

    Required, not optional: an optional check is a bypass waiting to happen.
    """

    def exists(self, *, tenant_id: str, run_id: str) -> bool: ...


def _deny(rule_id: str, reason: str, tier: str = "unknown") -> Decision:
    return Decision(outcome="deny", rule_id=rule_id, reason=reason, tier=tier)


def authorize(
    request: AuthorizationRequest,
    checker: RelationChecker,
    run_store: RunStore,
    catalog: dict[str, ToolSpec] | None = None,
) -> Decision:
    tools = catalog if catalog is not None else load_catalog()

    if not request.tenant_id.strip():
        return _deny("identity.missing_tenant", "no tenant on the authorisation request")
    if not request.user_id.strip():
        return _deny("identity.missing_user", "no user on the authorisation request")
    if not request.run_id.strip():
        return _deny("identity.missing_run", "no run id on the authorisation request")
    if not request.agent_id.strip():
        return _deny("identity.missing_agent", "no agent on the authorisation request")

    spec = tools.get(request.tool)
    if spec is None:
        # Unknown tools are denied, never passed through to the executor.
        return _deny("tool.unknown", f"tool {request.tool!r} is not in the catalog")

    if spec.tier == "T2":
        return _deny("tool.tier_denied", f"{request.tool} is T2 and denied in v0.1", spec.tier)

    if spec.agent != request.agent_id:
        return _deny(
            "tool.agent_mismatch",
            f"{request.tool} belongs to the {spec.agent} agent, not {request.agent_id}",
            spec.tier,
        )

    try:
        known_run = run_store.exists(tenant_id=request.tenant_id, run_id=request.run_id)
    except Exception as exc:  # noqa: BLE001 - a broken lookup must not authorise
        return _deny("identity.unknown_run", f"run lookup failed: {exc}", spec.tier)
    if not known_run:
        return _deny("identity.unknown_run", "run does not exist in this tenant", spec.tier)

    try:
        allowed = checker.can_call(
            user=f"{POLICY_USER_PREFIX}{request.user_id}",
            obj=tool_object(request.tenant_id, request.tool),
        )
    except Exception as exc:  # noqa: BLE001 - any policy failure must deny
        return _deny("policy.unavailable", f"policy check failed: {exc}", spec.tier)

    if not allowed:
        return _deny("policy.denied", "no can_call relationship for this user and tool", spec.tier)

    if spec.tier == "T1":
        return Decision(
            outcome="requires_approval",
            rule_id="policy.tier_requires_approval",
            reason=f"{request.tool} is T1 and needs human approval",
            tier=spec.tier,
        )

    return Decision(outcome="allow", rule_id="policy.allowed", reason="allowed", tier=spec.tier)
