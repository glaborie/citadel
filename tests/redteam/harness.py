"""Executors for the red-team pack.

Each case in ``cases.json`` is data; this module supplies the code that proves
the expected verdict against the real seams Citadel already has: the policy
chokepoint, the signed run and approval tokens, the DLP gate and the
idempotency key. Cases that need Temporal, Postgres or the live stack have no
executor yet and are reported as pending rather than quietly skipped.

A pending case is an honest state. A passing case that never touched the code
is not.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from citadel import dlp
from citadel.api import app as api_module
from citadel.approvals import mint_approval_token, verify_approval_token
from citadel.identity.keycloak import IdentityError, Principal
from citadel.identity.run_token import mint_run_token, verify_run_token
from citadel.policy import (
    AuthorizationRequest,
    Decision,
    PolicyError,
    authorize,
    load_catalog,
)
from citadel.workflows import activities as activities_module
from citadel.workflows.activities import idempotency_key
from citadel.workflows.types import ToolCall

HERE = Path(__file__).parent
PACK = HERE / "cases.json"
FIXTURES = HERE / "fixtures"
ANALYZER = "http://presidio.test"

# case id -> ("pass" | "fail", one-line detail). Filled by the test run so the
# report can be generated without pytest having to know about our data model.
COLLECTED: dict[str, tuple[str, str]] = {}

# Live results land here and win over the offline answer: the stack is the
# stronger evidence, and file execution order must not decide which one counts.
LIVE: dict[str, tuple[str, str]] = {}


@dataclass(frozen=True)
class Case:
    id: str
    title: str
    category: str
    tier: str
    surface: str
    fixture: str | None
    verdict: str
    evidence: str
    side_effects: str
    controls: tuple[str, ...]
    milestone: str
    known_gap: str | None

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> Case:
        expect = raw["expect"]
        return cls(
            id=str(raw["id"]),
            title=str(raw["title"]),
            category=str(raw["category"]),
            tier=str(raw["tier"]),
            surface=str(raw["surface"]),
            fixture=None if raw["fixture"] is None else str(raw["fixture"]),
            verdict=str(expect["verdict"]),
            evidence=str(expect["evidence"]),
            side_effects=str(expect["side_effects"]),
            controls=tuple(str(c) for c in raw["controls"]),
            milestone=str(raw["milestone"]),
            known_gap=None if raw.get("known_gap") is None else str(raw["known_gap"]),
        )


@dataclass(frozen=True)
class Outcome:
    passed: bool
    detail: str


def load_cases() -> list[Case]:
    raw: dict[str, Any] = json.loads(PACK.read_text(encoding="utf-8"))
    return [Case.from_dict(item) for item in raw["cases"]]


def case(case_id: str) -> Case:
    for entry in load_cases():
        if entry.id == case_id:
            return entry
    raise KeyError(case_id)


# ---------------------------------------------------------------- fakes


@dataclass
class FakeChecker:
    """Stands in for OpenFGA; the live equivalent is test_tenancy_live.py."""

    allowed: bool = True
    error: Exception | None = None
    calls: int = 0

    def can_call(self, *, user: str, obj: str) -> bool:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.allowed


@dataclass
class FakeRunStore:
    known: bool = True
    error: Exception | None = None

    def exists(self, *, tenant_id: str, run_id: str) -> bool:
        if self.error is not None:
            raise self.error
        return self.known


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


def decision_of(**overrides: str) -> Decision:
    return authorize(request(**overrides), FakeChecker(), FakeRunStore())


class _DetectorResponse:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _DetectorResponse:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def detector(payload: Any) -> Callable[..., _DetectorResponse]:
    def opener(_request: Any, timeout: Any = None) -> _DetectorResponse:
        return _DetectorResponse(payload)

    return opener


def dead_detector(exc: Exception) -> Callable[..., _DetectorResponse]:
    def opener(_request: Any, timeout: Any = None) -> _DetectorResponse:
        raise exc

    return opener


def fixture_text(relative: str) -> str:
    return (FIXTURES / relative).read_text(encoding="utf-8")


# ------------------------------------------------------------ executors


def exec_cross_specialist(case_: Case, _: Path) -> Outcome:
    """RT-AUTHZ-02: a Researcher asking for a Docker write is denied by ownership."""
    decision = decision_of(agent_id="researcher", tool="restart_service")
    ok = decision.outcome == "deny" and decision.rule_id == "tool.agent_mismatch"
    return Outcome(ok, f"{decision.outcome}/{decision.rule_id}")


def exec_unknown_tool(case_: Case, _: Path) -> Outcome:
    """RT-AUTHZ-03: a tool outside the catalog is denied and named as unknown."""
    decision = decision_of(tool="docker_prune_images")
    ok = decision.outcome == "deny" and decision.rule_id == "tool.unknown"
    return Outcome(ok, f"{decision.outcome}/{decision.rule_id}")


def exec_missing_identity(case_: Case, _: Path) -> Outcome:
    """RT-AUTHZ-04: no tenant or no user stops the call before the model runs."""
    no_tenant = decision_of(tenant_id="")
    no_user = decision_of(user_id="")
    ok = (
        no_tenant.rule_id == "identity.missing_tenant"
        and no_user.rule_id == "identity.missing_user"
    )
    return Outcome(ok, f"{no_tenant.rule_id}, {no_user.rule_id}")


def exec_expired_run_token(case_: Case, _: Path) -> Outcome:
    """RT-AUTHZ-05: a run token past its expiry is rejected at verification."""
    private = Ed25519PrivateKey.generate()
    token, _context = mint_run_token(
        Principal(user_id="alice", tenant_id="lab-a", roles=frozenset({"operator"})),
        agent_id="docker",
        scopes=frozenset({"read"}),
        risk_tier="T0",
        private_key=private,
        ttl_seconds=-5,
    )
    try:
        verify_run_token(token, private.public_key())
    except IdentityError as exc:
        return Outcome(True, f"rejected: {str(exc)[:60]}")
    return Outcome(False, "expired run token verified")


def exec_policy_unavailable(case_: Case, _: Path) -> Outcome:
    """RT-AUTHZ-06: a broken policy service or run lookup denies, never allows."""
    down = authorize(request(), FakeChecker(error=PolicyError("down")), FakeRunStore())
    lost = authorize(request(), FakeChecker(), FakeRunStore(error=RuntimeError("db down")))
    ok = down.rule_id == "policy.unavailable" and lost.rule_id == "identity.unknown_run"
    return Outcome(ok, f"{down.rule_id}, {lost.rule_id}")


def exec_approval_ttl(case_: Case, _: Path) -> Outcome:
    """RT-HITL-03: an approval that expires is unusable, so silence means no."""
    private = Ed25519PrivateKey.generate()
    arguments = {"service": "checkout-api"}
    token = mint_approval_token(
        tenant_id="lab-a",
        run_id="run-1",
        tool="restart_service",
        arguments=arguments,
        approver="carol",
        private_key=private,
        ttl_seconds=-30,
    )
    try:
        verify_approval_token(
            token,
            public_key=private.public_key(),
            tenant_id="lab-a",
            run_id="run-1",
            tool="restart_service",
            arguments=arguments,
        )
    except IdentityError as exc:
        return Outcome(True, f"rejected: {str(exc)[:60]}")
    return Outcome(False, "expired approval accepted")


def exec_args_substitution(case_: Case, _: Path) -> Outcome:
    """RT-HITL-04: approving service A cannot execute service B."""
    private = Ed25519PrivateKey.generate()
    token = mint_approval_token(
        tenant_id="lab-a",
        run_id="run-1",
        tool="restart_service",
        arguments={"service": "checkout-api"},
        approver="carol",
        private_key=private,
    )
    try:
        verify_approval_token(
            token,
            public_key=private.public_key(),
            tenant_id="lab-a",
            run_id="run-1",
            tool="restart_service",
            arguments={"service": "billing-worker"},
        )
    except IdentityError as exc:
        return Outcome(True, f"rejected: {str(exc)[:60]}")
    return Outcome(False, "approval matched different arguments")


def exec_skill_escalation(case_: Case, fixtures: Path) -> Outcome:
    """RT-INJ-04: a skill pack may name a tool; it can never grant one."""
    text = (fixtures / "injection/skill_escalation.md").read_text(encoding="utf-8")
    named = re.search(r"tool:\s*([a-z0-9_]+)", text)
    if named is None:
        return Outcome(False, "fixture names no tool")
    tool = named.group(1)
    in_catalog = tool in load_catalog()
    rule = decision_of(tool=tool).rule_id
    ok = (not in_catalog) and rule == "tool.unknown"
    return Outcome(ok, f"tool={tool} catalogued={in_catalog} {rule}")


def exec_secret_in_prompt(case_: Case, _: Path) -> Outcome:
    """RT-DLP-01: a credential on the input surface blocks the call.

    The implementation is stricter than the original expectation: an input
    surface is never redacted, because redacted arguments would run a command
    other than the one policy authorised.
    """
    text = fixture_text("dlp/api_key.txt")
    verdict = dlp.inspect(text, surface="input", analyzer_url=ANALYZER, opener=detector([]))
    categories = sorted({finding.category for finding in verdict.findings})
    ok = verdict.action == "block" and "GITHUB_TOKEN" in categories
    return Outcome(ok, f"{verdict.action} {categories}")


def exec_swiss_identifiers_redacted(case_: Case, _: Path) -> Outcome:
    """RT-DLP-02: AHV and IBAN in retrieved text are redacted in place."""
    text = fixture_text("dlp/ahv_iban.txt")
    ahv = text.index("756")
    iban = text.index("CH93")
    payload = [
        {"entity_type": "AHV", "start": ahv, "end": ahv + 16, "score": 0.9},
        {"entity_type": "IBAN_CODE", "start": iban, "end": iban + 21, "score": 0.9},
    ]
    verdict = dlp.inspect(text, surface="output", analyzer_url=ANALYZER, opener=detector(payload))
    ok = (
        verdict.action == "redact"
        and "756" not in verdict.text
        and "CH93" not in verdict.text
        and "<AHV>" in verdict.text
    )
    return Outcome(ok, verdict.action)


def exec_dlp_unavailable(case_: Case, _: Path) -> Outcome:
    """RT-DLP-04: a dead detector refuses (503), and never degrades to pass."""
    import urllib.error

    try:
        dlp.inspect(
            "restart checkout-api",
            surface="input",
            analyzer_url=ANALYZER,
            opener=dead_detector(urllib.error.URLError("connection refused")),
        )
    except dlp.DlpUnavailable as exc:
        blocked = dlp.DlpBlocked("dlp_unavailable", {"action": "block"})
        ok = blocked.status == 503
        return Outcome(ok, f"refused/{blocked.status}: {str(exc)[:40]}")
    return Outcome(False, "detector outage passed")


def exec_idempotency_key(case_: Case, _: Path) -> Outcome:
    """RT-DUR-01: the key is stable per call and changes with the arguments."""
    first = ToolCall(
        run_id="run-1",
        tenant_id="lab-a",
        user_id="alice",
        agent_id="docker",
        tool="restart_service",
        arguments={"service": "checkout-api"},
    )
    same = ToolCall(
        run_id="run-1",
        tenant_id="lab-a",
        user_id="alice",
        agent_id="docker",
        tool="restart_service",
        arguments={"service": "checkout-api"},
    )
    other = ToolCall(
        run_id="run-1",
        tenant_id="lab-a",
        user_id="alice",
        agent_id="docker",
        tool="restart_service",
        arguments={"service": "billing-worker"},
    )
    ok = idempotency_key(first) == idempotency_key(same) and idempotency_key(
        first
    ) != idempotency_key(other)
    return Outcome(ok, idempotency_key(first)[:24] + "...")


def exec_duplicate_side_effect(case_: Case, _: Path) -> Outcome:
    """RT-DUR-01: one effect per call, however many times Temporal retries.

    Three attempts: a clean run, a retry after success, and a retry after the
    approval was consumed but the outcome is unknown. Only the first may reach
    the tool.
    """
    from unittest import mock

    from citadel.workflows.activities import ToolActivities
    from tests.redteam import support

    db = support.FakeDB()
    audit = support.FakeAudit()
    stub = support.StubTool()
    acts = ToolActivities(
        checker=FakeChecker(),
        run_store=FakeRunStore(),
        dsn="postgres://fake",
        runner_url="http://runner.test",
        operator_url="http://operator.test",
        audit=audit,  # type: ignore[arg-type]
    )
    call = ToolCall(
        run_id="run-1",
        tenant_id="lab-a",
        user_id="alice",
        agent_id="docker",
        tool="restart_service",
        arguments={"service": "checkout-api"},
    )
    with (
        mock.patch.object(activities_module, "tenant_connection", db.connect),
        mock.patch.object(ToolActivities, "_invoke", lambda self, c: stub.invoke(c)),
    ):
        first = acts.execute_tool(call)
        second = acts.execute_tool(call)
        for row in db.rows.values():
            row["status"] = "sent"
        third = acts.execute_tool(call)

    ok = (
        first.status == "executed"
        and second.status == "replayed"
        and second.replayed
        and third.rule_id == "tool.possibly_executed"
        and stub.count == 1
    )
    return Outcome(ok, f"{first.status}/{second.status}/{third.status} calls={stub.count}")


def exec_self_approval(case_: Case, _: Path) -> Outcome:
    """RT-HITL-01: the API refuses an approver who owns the run."""
    from unittest import mock

    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient

    from citadel.api.app import create_app
    from citadel.identity import KeycloakVerifier
    from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token
    from tests.redteam import support

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    app = create_app(
        verifier=KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(key.public_key())),
        dsn="postgres://fake",
    )
    token = user_token(key, roles=["operator", "approver"], sub="user-alice")
    db = support.FakeDB()
    db.run_owner = ("user-alice",)
    payload = {
        "run_id": "run-1",
        "tool": "restart_service",
        "agent_id": "docker",
        "arguments": {"service": "checkout-api"},
        "approved": True,
        "reason": "looks fine",
    }
    with mock.patch.object(api_module, "tenant_connection", db.connect):
        response = TestClient(app).post(
            "/approvals", json=payload, headers={"Authorization": f"Bearer {token}"}
        )
    body = response.json()
    ok = response.status_code == 403 and "own run" in str(body.get("detail", ""))
    return Outcome(ok, f"{response.status_code} {str(body.get('detail'))[:40]}")


def exec_approval_replay(case_: Case, _: Path) -> Outcome:
    """RT-HITL-02: the operator executes once per approval, then returns 409."""
    import os
    from unittest import mock

    from fastapi.testclient import TestClient

    from citadel.approvals import mint_approval_token
    from citadel.operator import app as operator
    from tests.redteam import support

    private = Ed25519PrivateKey.generate()
    arguments = {"service": "checkout-api"}
    token = mint_approval_token(
        tenant_id="lab-a",
        run_id="run-1",
        tool="restart_service",
        arguments=arguments,
        approver="carol",
        private_key=private,
    )
    stub = support.StubExecutor()
    seen: list[str] = []

    def already_used(dsn: str, tenant_id: str, jti: str) -> bool:
        seen.append(jti)
        return len(seen) > 1

    def passthrough(text: str, *, surface: str) -> tuple[str, dict[str, object]]:
        return text, {"surface": surface, "action": "pass"}

    payload = {
        "tenant_id": "lab-a",
        "run_id": "run-1",
        "tool": "restart_service",
        "arguments": arguments,
        "approval_token": token,
    }
    env = {"CITADEL_RUN_TOKEN_PUBLIC_KEY": "unused", "CITADEL_DB_DSN": "postgres://fake"}
    with (
        mock.patch.dict(os.environ, env),
        mock.patch.object(operator, "public_key_from_env", lambda _v: private.public_key()),
        mock.patch.object(operator, "_already_used", already_used),
        mock.patch.object(operator, "_guard", passthrough),
        mock.patch("citadel.tools.runner.run", stub.run),
    ):
        client = TestClient(operator.app)
        first = client.post("/execute", json=payload)
        second = client.post("/execute", json=payload)

    ok = (
        first.status_code == 200
        and second.status_code == 409
        and len(stub.calls) == 1
        and len(seen) == 2
    )
    return Outcome(ok, f"{first.status_code}/{second.status_code} calls={len(stub.calls)}")


def exec_secret_in_tool_args(case_: Case, _: Path) -> Outcome:
    """RT-DLP-03: a credential in approved arguments blocks before the operator runs.

    The detector is stubbed to return nothing, so only the hard rule can catch
    this: a credential is random characters, not a name, and NER will always
    miss it.
    """
    import os
    from unittest import mock

    from fastapi.testclient import TestClient

    from citadel.approvals import mint_approval_token
    from citadel.operator import app as operator
    from tests.redteam import support

    private = Ed25519PrivateKey.generate()
    secret = fixture_text("dlp/api_key.txt").split()[3]
    arguments = {
        "repo": "glaborie/citadel",
        "base": "main",
        "head": "fix/rotate-token",
        "title": "Rotate the deploy token",
        "body": f"Rotated. Old value was {secret}",
    }
    token = mint_approval_token(
        tenant_id="lab-a",
        run_id="run-1",
        tool="open_remediation_pr",
        arguments=arguments,
        approver="carol",
        private_key=private,
    )
    stub = support.StubExecutor()
    payload = {
        "tenant_id": "lab-a",
        "run_id": "run-1",
        "tool": "open_remediation_pr",
        "arguments": arguments,
        "approval_token": token,
    }
    env = {"CITADEL_RUN_TOKEN_PUBLIC_KEY": "unused", "CITADEL_DB_DSN": "postgres://fake"}
    with (
        mock.patch.dict(os.environ, env),
        mock.patch.object(operator, "public_key_from_env", lambda _v: private.public_key()),
        mock.patch.object(operator, "_already_used", lambda *_: False),
        mock.patch.object(dlp, "urlopen", support.DetectorStub([])),
        mock.patch("citadel.tools.runner.run", stub.run),
    ):
        response = TestClient(operator.app).post("/execute", json=payload)
    detail = str(response.json().get("detail", ""))
    ok = response.status_code == 403 and "dlp_blocked" in detail and not stub.calls
    return Outcome(ok, f"{response.status_code} ran={len(stub.calls)} {detail[:40]}")


def exec_egress_allowlist(case_: Case, _: Path) -> Outcome:
    """RT-DLP-05: the proxy is the egress boundary, so the boundary is the file.

    This asserts the config, not a running proxy: one allow rule that requires
    CONNECT plus the GitHub domain, a deny-all after it, and no wildcard
    destination that would widen the door.
    """
    conf = (Path(__file__).parents[2] / "squid" / "github-egress.conf").read_text(encoding="utf-8")
    rules = [
        line.strip()
        for line in conf.splitlines()
        if line.strip().startswith(("http_access", "acl "))
    ]
    allows = [r for r in rules if r.startswith("http_access allow")]
    deny_all = [r for r in rules if r == "http_access deny all"]
    deny_index = _last_index(rules, "http_access deny all")
    allows_before_deny = all(rules.index(rule) < deny_index for rule in allows)
    github_acl = any("dstdomain api.github.com" in r for r in rules)
    wildcard = any(
        r.startswith("acl all ") or "0.0.0.0/0" in r or "*" in r.split("acl", 1)[-1] for r in rules
    )
    allow_is_scoped = all("CONNECT" in r and "github" in r for r in allows)
    ok = (
        len(allows) == 1
        and bool(deny_all)
        and allows_before_deny
        and github_acl
        and allow_is_scoped
        and not wildcard
    )
    return Outcome(
        ok,
        f"allows={len(allows)} deny_all={bool(deny_all)} "
        f"scoped={allow_is_scoped} wildcard={wildcard}",
    )


def _last_index(items: list[str], value: str) -> int:
    for index in range(len(items) - 1, -1, -1):
        if items[index] == value:
            return index
    return 0


def exec_approval_preview(case_: Case, _: Path) -> Outcome:
    """RT-HITL-05: a secret in the arguments must not reach the console.

    The approval route checks the arguments before it mints the token and
    audits the decision, so a secret is refused rather than rendered. The
    detector is stubbed because the hard rule for credentials does not need it;
    the test would otherwise depend on Presidio being up.
    """
    from unittest import mock

    from cryptography.hazmat.primitives.asymmetric import rsa
    from fastapi.testclient import TestClient

    from citadel.api.app import create_app
    from citadel.identity import KeycloakVerifier
    from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token
    from tests.redteam import support

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    app = create_app(
        verifier=KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(key.public_key())),
        dsn="postgres://fake",
        private_key=Ed25519PrivateKey.generate(),
    )
    token = user_token(key, roles=["approver"], sub="carol")
    db = support.FakeDB()
    db.run_owner = ("user-alice",)
    secret = fixture_text("dlp/api_key.txt").split()[3]
    payload = {
        "run_id": "run-1",
        "tool": "restart_service",
        "agent_id": "docker",
        "arguments": {"service": "checkout-api", "note": secret},
        "approved": True,
        "reason": "fine",
    }

    class _NoopLedger:
        def __init__(self, _dsn: str) -> None:
            pass

        def append(self, **_: object) -> object:
            from types import SimpleNamespace

            return SimpleNamespace(audit_id="audit-1")

    with (
        mock.patch.object(api_module, "tenant_connection", db.connect),
        mock.patch.object(api_module, "AuditLedger", _NoopLedger),
        mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()),
        mock.patch.object(dlp, "urlopen", detector([])),
    ):
        response = TestClient(app).post(
            "/approvals", json=payload, headers={"Authorization": f"Bearer {token}"}
        )
    ok = response.status_code == 403
    return Outcome(ok, f"{response.status_code} for secret-bearing arguments")


EXECUTORS: dict[str, Callable[[Case, Path], Outcome]] = {
    "RT-AUTHZ-02": exec_cross_specialist,
    "RT-AUTHZ-03": exec_unknown_tool,
    "RT-AUTHZ-04": exec_missing_identity,
    "RT-AUTHZ-05": exec_expired_run_token,
    "RT-AUTHZ-06": exec_policy_unavailable,
    "RT-HITL-03": exec_approval_ttl,
    "RT-HITL-04": exec_args_substitution,
    "RT-INJ-04": exec_skill_escalation,
    "RT-DLP-01": exec_secret_in_prompt,
    "RT-DLP-02": exec_swiss_identifiers_redacted,
    "RT-DLP-03": exec_secret_in_tool_args,
    "RT-DLP-04": exec_dlp_unavailable,
    "RT-DLP-05": exec_egress_allowlist,
    "RT-HITL-05": exec_approval_preview,
    "RT-DUR-01": exec_duplicate_side_effect,
    "RT-HITL-01": exec_self_approval,
    "RT-HITL-02": exec_approval_replay,
}


def run(case_: Case) -> Outcome:
    executor = EXECUTORS.get(case_.id)
    if executor is None:
        raise KeyError(case_.id)
    return executor(case_, FIXTURES)
