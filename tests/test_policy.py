"""Policy chokepoint: every path must fail closed.

The checker is faked so these run without OpenFGA; the live equivalents are in
tests/test_tenancy_live.py.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from citadel.policy import (
    ApprovalAuthorization,
    AuthorizationRequest,
    Decision,
    authorize,
    authorize_approval,
    load_catalog,
)


@dataclass
class FakeRunStore:
    known: bool = True
    error: Exception | None = None

    def exists(self, *, tenant_id: str, run_id: str) -> bool:
        if self.error is not None:
            raise self.error
        return self.known


STORE = FakeRunStore()


@dataclass
class FakeChecker:
    allowed: bool = True
    error: Exception | None = None
    calls: int = 0

    def can_call(self, *, user: str, obj: str) -> bool:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.allowed

    def can_approve(self, *, agent: str, obj: str) -> bool:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.allowed


def request(**overrides: str) -> AuthorizationRequest:
    base = {
        "user_id": "user-alice",
        "tenant_id": "lab-a",
        "run_id": "run-1",
        "agent_id": "docker",
        "tool": "read_logs",
    }
    base.update(overrides)
    return AuthorizationRequest(**base)


def test_t0_allowed_for_authorised_user() -> None:
    checker = FakeChecker()
    assert authorize(request(), checker, STORE) == Decision(
        outcome="allow", rule_id="policy.allowed", reason="allowed", tier="T0"
    )
    assert checker.calls == 1


def test_t1_requires_approval() -> None:
    decision = authorize(request(tool="restart_service"), FakeChecker(), STORE)
    assert decision.outcome == "requires_approval"
    assert decision.tier == "T1"


@pytest.mark.parametrize("tool", ["delete_volume", "force_push"])
def test_t2_is_denied_without_consulting_policy(tool: str) -> None:
    checker = FakeChecker()
    decision = authorize(request(tool=tool), checker, STORE)
    assert decision.outcome == "deny"
    assert decision.rule_id == "tool.tier_denied"
    assert checker.calls == 0, "T2 must be refused before any relationship lookup"


def test_unknown_tool_is_denied() -> None:
    decision = authorize(request(tool="exfiltrate_secrets"), FakeChecker(), STORE)
    assert decision.rule_id == "tool.unknown"


def test_agent_cannot_call_another_agents_tool() -> None:
    """Red team: the docker agent asking for a GitHub tool."""
    decision = authorize(request(agent_id="docker", tool="search_code"), FakeChecker(), STORE)
    assert decision.outcome == "deny"
    assert decision.rule_id == "tool.agent_mismatch"


@pytest.mark.parametrize(
    ("field", "rule"),
    [
        ("tenant_id", "identity.missing_tenant"),
        ("user_id", "identity.missing_user"),
        ("run_id", "identity.missing_run"),
        ("agent_id", "identity.missing_agent"),
    ],
)
@pytest.mark.parametrize("blank", ["", "   "])
def test_missing_identity_fields_are_denied(field: str, rule: str, blank: str) -> None:
    assert authorize(request(**{field: blank}), FakeChecker(), STORE).rule_id == rule


def test_policy_says_no() -> None:
    decision = authorize(request(), FakeChecker(allowed=False), STORE)
    assert decision.outcome == "deny"
    assert decision.rule_id == "policy.denied"


def test_policy_service_error_fails_closed() -> None:
    """Red team: an unreachable policy service must never allow."""
    checker = FakeChecker(error=RuntimeError("connection refused"))
    decision = authorize(request(), checker, STORE)
    assert decision.outcome == "deny"
    assert decision.rule_id == "policy.unavailable"


def test_empty_catalog_denies_everything() -> None:
    for tool in load_catalog():
        assert authorize(request(tool=tool), FakeChecker(), STORE, catalog={}).outcome == "deny"


def test_catalog_covers_the_documented_tiers() -> None:
    catalog = load_catalog()
    assert catalog["read_logs"].tier == "T0"
    assert catalog["restart_service"].tier == "T1"
    assert catalog["open_remediation_pr"].tier == "T1"
    assert catalog["delete_volume"].tier == "T2"
    assert {spec.agent for spec in catalog.values()} == {"docker", "github", "researcher"}


def test_the_researcher_owns_only_the_two_web_tools() -> None:
    catalog = load_catalog()
    owned = {name for name, spec in catalog.items() if spec.agent == "researcher"}
    assert owned == {"search_web", "fetch_page"}
    allowed = authorize(request(agent_id="researcher", tool="search_web"), FakeChecker(), STORE)
    assert (allowed.outcome, allowed.rule_id) == ("allow", "policy.allowed")
    denied = authorize(request(agent_id="researcher", tool="restart_service"), FakeChecker(), STORE)
    assert (denied.outcome, denied.rule_id) == ("deny", "tool.agent_mismatch")


def test_t1_tools_are_exactly_the_two_allowed() -> None:
    """v0.1 permits exactly two write tools; a third must not slip in."""
    t1 = sorted(name for name, spec in load_catalog().items() if spec.tier == "T1")
    assert t1 == ["open_remediation_pr", "restart_service"]


def test_unknown_run_is_denied() -> None:
    """The run must exist in the caller's tenant before any tool is authorised."""
    decision = authorize(request(), FakeChecker(), FakeRunStore(known=False))
    assert decision.outcome == "deny"
    assert decision.rule_id == "identity.unknown_run"


def test_broken_run_lookup_fails_closed() -> None:
    decision = authorize(request(), FakeChecker(), FakeRunStore(error=RuntimeError("db down")))
    assert decision.rule_id == "identity.unknown_run"


def test_run_lookup_is_skipped_for_t2() -> None:
    """T2 is refused on the tier alone, before touching the database."""
    store = FakeRunStore(error=RuntimeError("must not be called"))
    decision = authorize(request(tool="delete_volume"), FakeChecker(), store)
    assert decision.rule_id == "tool.tier_denied"


def approval(**overrides: Any) -> ApprovalAuthorization:
    base: dict[str, Any] = {
        "tenant_id": "lab-a",
        "approving_agent": "researcher",
        "origin_agent": "docker",
        "approving_user": "user-bob",
        "origin_user": "user-alice",
        "tool": "restart_service",
    }
    base.update(overrides)
    return ApprovalAuthorization(**base)


def test_an_agent_with_can_approve_may_approve_another_agents_t1_call() -> None:
    checker = FakeChecker()
    decision = authorize_approval(approval(), checker)
    assert decision.outcome == "allow"
    assert decision.rule_id == "approval.agent_allowed"
    assert checker.calls == 1


def test_an_agent_cannot_approve_its_own_run() -> None:
    checker = FakeChecker()
    decision = authorize_approval(approval(approving_agent="docker"), checker)
    assert decision.outcome == "deny"
    assert decision.rule_id == "approval.self_approval_denied"
    assert checker.calls == 0, "self-approval is refused before any policy lookup"


def test_an_agent_cannot_approve_the_run_of_the_user_it_runs_for() -> None:
    checker = FakeChecker()
    decision = authorize_approval(
        approval(origin_user="user-bob", approving_user="user-bob"),
        checker,
    )
    assert decision.outcome == "deny"
    assert decision.rule_id == "approval.self_approval_denied"
    assert checker.calls == 0


def test_agent_approval_needs_the_relation() -> None:
    decision = authorize_approval(approval(), FakeChecker(allowed=False))
    assert decision.rule_id == "approval.relation_denied"


def test_an_agent_cannot_approve_a_prompt_injection_tainted_call() -> None:
    checker = FakeChecker()
    decision = authorize_approval(approval(content_flags=["prompt_injection"]), checker)
    assert decision.outcome == "deny"
    assert decision.rule_id == "approval.prompt_injection"
    assert checker.calls == 0, "the taint is refused before any policy lookup"


def test_untrusted_external_alone_does_not_refuse_an_agent_approver() -> None:
    """Every research run carries untrusted_external; only prompt_injection taints."""
    decision = authorize_approval(approval(content_flags=["untrusted_external"]), FakeChecker())
    assert decision.outcome == "allow"
    assert decision.rule_id == "approval.agent_allowed"


def test_agent_approval_fails_closed_when_policy_is_unavailable() -> None:
    decision = authorize_approval(approval(), FakeChecker(error=RuntimeError("down")))
    assert decision.rule_id == "policy.unavailable"


@pytest.mark.parametrize("tool", ["read_logs", "delete_volume"])
def test_agents_approve_t1_only(tool: str) -> None:
    decision = authorize_approval(approval(tool=tool), FakeChecker())
    assert decision.rule_id == "approval.tier_denied"
