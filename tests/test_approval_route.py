"""The approval route checks arguments before it audits the decision."""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from typing import Any
from unittest import mock

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from citadel import approval_requests, dlp
from citadel.api import app as api_module
from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier, Principal, mint_run_token
from tests.conftest import AUDIENCE, ISSUER, AnalyzerResponse, StaticKeys, user_token
from tests.redteam.support import FakeDB

SECRET = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


@pytest.fixture
def env(
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    analyzer: dict[str, list[dict[str, Any]]],
) -> tuple[TestClient, list[dict[str, Any]], str]:
    db = FakeDB()
    events: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(events)}")

    monkeypatch.setattr(api_module, "tenant_connection", db.connect)
    monkeypatch.setattr(approval_requests, "tenant_connection", db.connect)
    monkeypatch.setattr(api_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    client = TestClient(
        create_app(
            verifier=verifier, dsn="postgres://fake", private_key=Ed25519PrivateKey.generate()
        )
    )
    return client, events, user_token(rsa_key, roles=["approver"], sub="carol")


def _post(client: TestClient, token: str, arguments: dict[str, Any]) -> Any:
    return client.post(
        "/approvals",
        json={
            "run_id": "run-1",
            "tool": "restart_service",
            "agent_id": "docker",
            "arguments": arguments,
            "approved": True,
            "reason": "looks fine",
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def test_clean_arguments_are_approved_and_audited(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    client, events, token = env
    # The approval signal needs a live Temporal; the route logic under test does not.
    with mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()):
        response = _post(client, token, {"service": "checkout-api"})
    assert response.status_code == 200
    assert [event["event_type"] for event in events] == ["approval.decision"]


def test_the_signal_target_is_the_workflow_the_row_records(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    """The row's id carries the step; rebuilding it from run and tool loses it."""
    client, _events, token = env
    targets: list[str] = []

    def capture(coro: Any) -> None:
        targets.append(coro.cr_frame.f_locals["workflow_id"])
        coro.close()

    with mock.patch("citadel.api.app.asyncio.run", capture):
        assert _post(client, token, {"service": "checkout-api"}).status_code == 200

    assert targets == ["run-run-1-0-restart_service"]


def test_a_failed_signal_leaves_the_approval_pending(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    """An approval consumed for a workflow nobody resumed is a lost run."""
    client, _events, token = env

    def boom(coro: Any) -> None:
        coro.close()
        raise RuntimeError("workflow not found")

    with (
        mock.patch("citadel.api.app.asyncio.run", boom),
        mock.patch("citadel.api.app.close_request") as mirrored,
    ):
        response = _post(client, token, {"service": "checkout-api"})

    assert response.status_code == 502
    mirrored.assert_not_called()


def test_secret_in_arguments_is_refused_before_mint(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    client, events, token = env
    response = _post(client, token, {"service": "checkout-api", "note": SECRET})
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    # No decision was recorded; the refusal itself is the only ledger row.
    assert [event["event_type"] for event in events] == ["dlp.event"]
    assert events[0]["payload"]["action"] == "block"
    assert events[0]["payload"]["categories"] == ["GITHUB_TOKEN"]
    assert SECRET not in str(events)


def test_unreachable_detector_refuses_rather_than_passing(
    monkeypatch: pytest.MonkeyPatch, env: tuple[TestClient, list[dict[str, Any]], str]
) -> None:
    client, events, token = env

    def down(_request: Any, timeout: Any = None) -> Any:
        raise OSError("detector down")

    monkeypatch.setattr(dlp, "urlopen", down)
    response = _post(client, token, {"service": "checkout-api"})
    assert response.status_code == 503
    assert response.json()["detail"]["reason"] == "dlp_unavailable"
    assert [event["event_type"] for event in events] == ["dlp.event"]
    assert events[0]["payload"]["action"] == "block"


CARD = "4111 1111 1111 1111"
REASON_WITH_CARD = f"the card {CARD} is on the customer record"
_CARD_SPAN = {
    "entity_type": "CREDIT_CARD",
    "start": REASON_WITH_CARD.index(CARD),
    "end": REASON_WITH_CARD.index(CARD) + len(CARD),
    "score": 0.95,
}


def _post_reason(client: TestClient, token: str, reason: str) -> Any:
    return client.post(
        "/approvals",
        json={
            "run_id": "run-1",
            "tool": "restart_service",
            "agent_id": "docker",
            "arguments": {"service": "checkout-api"},
            "approved": True,
            "reason": reason,
        },
        headers={"Authorization": f"Bearer {token}"},
    )


def test_a_benign_reason_round_trips_and_records_the_detector_decision(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    client, events, token = env
    with mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()):
        response = _post(client, token, {"service": "checkout-api"})

    assert response.status_code == 200
    payload = events[0]["payload"]
    assert payload["reason"] == "looks fine"
    assert payload["dlp_redactions"] == 0
    assert payload["dlp_categories"] == []
    assert payload["reason_chars"] == len("looks fine")
    assert payload["reason_sha256"] == hashlib.sha256(b"looks fine").hexdigest()


def test_both_the_arguments_and_the_reason_are_inspected(
    monkeypatch: pytest.MonkeyPatch, env: tuple[TestClient, list[dict[str, Any]], str]
) -> None:
    """Two round trips, arguments first: the reason is its own surface, not a suffix."""
    client, _events, token = env
    seen: list[str] = []

    def counting(request: Any, timeout: Any = None) -> AnalyzerResponse:
        seen.append(json.loads(request.data)["text"])
        return AnalyzerResponse([])

    monkeypatch.setattr(dlp, "urlopen", counting)
    with mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()):
        assert _post(client, token, {"service": "checkout-api"}).status_code == 200

    assert seen == ['{"service": "checkout-api"}', "looks fine"]


def test_pii_in_the_reason_is_redacted_before_it_reaches_the_ledger(
    analyzer: dict[str, list[dict[str, Any]]],
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    """The ledger is append-only: a card number written there cannot be removed."""
    client, events, token = env
    analyzer[REASON_WITH_CARD] = [_CARD_SPAN]
    signalled: list[Any] = []

    def capture(coro: Any) -> None:
        # The coroutine has not run yet, so its frame still holds the arguments.
        signalled.append(coro.cr_frame.f_locals["decision"])
        coro.close()

    with (
        mock.patch("citadel.api.app.asyncio.run", capture),
        mock.patch("citadel.api.app.close_request") as mirrored,
    ):
        response = _post_reason(client, token, REASON_WITH_CARD)

    assert response.status_code == 200
    assert [event["event_type"] for event in events] == ["dlp.event", "approval.decision"]

    redaction = events[0]["payload"]
    assert redaction["surface"] == "record"
    assert redaction["action"] == "redact"
    assert redaction["categories"] == ["CREDIT_CARD"]

    decided = events[1]["payload"]
    assert CARD not in json.dumps(decided)
    assert decided["reason"] == "the card <CREDIT_CARD> is on the customer record"
    assert decided["dlp_redactions"] == 1
    assert decided["dlp_categories"] == ["CREDIT_CARD"]
    assert decided["reason_chars"] == len(REASON_WITH_CARD)
    assert decided["reason_sha256"] == hashlib.sha256(REASON_WITH_CARD.encode()).hexdigest()

    # The ledger is not the only writer: the mirror row and the workflow signal
    # carry the same redacted text, or the raw reason leaks one hop later.
    assert mirrored.call_args.kwargs["reason"] == decided["reason"]
    assert signalled[0].reason == decided["reason"]


def test_a_credential_in_the_reason_is_refused(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    """A token in an append-only ledger is the one thing redaction cannot fix.

    Blocking costs the approver a sentence, not the decision: they retype the
    reason without the secret, and nothing was written in between.
    """
    client, events, token = env
    response = _post_reason(client, token, f"rotating {SECRET} because it leaked")

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    assert [event["event_type"] for event in events] == ["dlp.event"]
    assert events[0]["payload"]["surface"] == "record"
    assert events[0]["payload"]["categories"] == ["GITHUB_TOKEN"]
    assert SECRET not in str(events)


def test_a_detector_that_dies_on_the_reason_refuses_the_decision(
    monkeypatch: pytest.MonkeyPatch, env: tuple[TestClient, list[dict[str, Any]], str]
) -> None:
    """The arguments pass; the second call fails. Nothing may be recorded."""
    client, events, token = env
    calls = {"n": 0}

    def flaky(request: Any, timeout: Any = None) -> AnalyzerResponse:
        calls["n"] += 1
        if calls["n"] > 1:
            raise OSError("detector died on the reason")
        return AnalyzerResponse([])

    monkeypatch.setattr(dlp, "urlopen", flaky)
    response = _post_reason(client, token, "the card was rotated")

    assert calls["n"] == 2
    assert response.status_code == 503
    assert response.json()["detail"]["reason"] == "dlp_unavailable"
    assert [event["event_type"] for event in events] == ["dlp.event"]
    assert events[0]["payload"]["action"] == "block"


def test_policy_authorize_cannot_carry_free_text(
    env: tuple[TestClient, list[dict[str, Any]], str],
) -> None:
    """`/policy/authorize` audits ids only, and the model refuses anything else.

    That is why it needs no DLP gate: there is no free-text field to gate, and an
    extra one is a 422 rather than an unaudited write.
    """
    client, events, token = env
    response = client.post(
        "/policy/authorize",
        json={
            "run_id": "run-1",
            "tool": "restart_service",
            "agent_id": "docker",
            "reason": f"rotating {SECRET}",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 422
    assert events == []


class _ApprovalChecker:
    """OpenFGA stand-in: records the relation check, answers with one flag."""

    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.agents: list[tuple[str, str]] = []

    def can_call(self, *, user: str, obj: str) -> bool:
        return True

    def can_approve(self, *, agent: str, obj: str) -> bool:
        self.agents.append((agent, obj))
        return self.allowed


@pytest.fixture
def agent_env(
    monkeypatch: pytest.MonkeyPatch,
    rsa_key: rsa.RSAPrivateKey,
    run_private_key: Ed25519PrivateKey,
    analyzer: dict[str, list[dict[str, Any]]],
) -> tuple[TestClient, list[dict[str, Any]], _ApprovalChecker, Any]:
    db = FakeDB()
    db.run_owner = ("user-alice", "docker")
    events: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        events.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(events)}")

    monkeypatch.setattr(api_module, "tenant_connection", db.connect)
    monkeypatch.setattr(approval_requests, "tenant_connection", db.connect)
    monkeypatch.setattr(api_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    checker = _ApprovalChecker()
    client = TestClient(
        create_app(
            verifier=KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key())),
            dsn="postgres://fake",
            private_key=run_private_key,
            checker=checker,
        )
    )

    def token_for(agent: str) -> str:
        token, _context = mint_run_token(
            Principal(user_id="user-alice", tenant_id="lab-a", roles=frozenset()),
            agent_id=agent,
            scopes=frozenset(),
            risk_tier="T1",
            private_key=run_private_key,
        )
        return token

    return client, events, checker, token_for


def test_an_agent_approval_is_audited_as_agent(
    agent_env: tuple[TestClient, list[dict[str, Any]], _ApprovalChecker, Any],
) -> None:
    client, events, checker, token_for = agent_env
    with mock.patch("citadel.api.app.asyncio.run", lambda coro: coro.close()):
        response = _post(client, token_for("researcher"), {"service": "checkout-api"})

    assert response.status_code == 200
    assert [event["event_type"] for event in events] == ["approval.decision"]
    decided = events[0]
    assert decided["actor_type"] == "agent"
    assert decided["actor_id"] == "agent:lab-a/researcher"
    assert decided["payload"]["actor_type"] == "agent"
    assert decided["payload"]["approver"] == "agent:lab-a/researcher"
    assert decided["payload"]["on_behalf_of"] == "user-alice"
    assert decided["payload"]["relation"] == "can_approve"
    assert checker.agents == [("agent:lab-a/researcher", "tool:lab-a/restart_service")]


def test_an_agent_cannot_approve_the_run_it_proposed(
    agent_env: tuple[TestClient, list[dict[str, Any]], _ApprovalChecker, Any],
) -> None:
    client, events, checker, token_for = agent_env
    response = _post(client, token_for("docker"), {"service": "checkout-api"})

    assert response.status_code == 403
    assert response.json()["detail"]["rule_id"] == "approval.self_approval_denied"
    assert events == []
    assert checker.agents == []


def test_an_agent_without_the_relation_cannot_approve(
    agent_env: tuple[TestClient, list[dict[str, Any]], _ApprovalChecker, Any],
) -> None:
    client, events, checker, token_for = agent_env
    checker.allowed = False
    response = _post(client, token_for("researcher"), {"service": "checkout-api"})

    assert response.status_code == 403
    assert response.json()["detail"]["rule_id"] == "approval.relation_denied"
    assert events == []
