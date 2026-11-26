from __future__ import annotations

import time
import urllib.error
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from citadel import dlp
from citadel.approvals import validate_approval
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError
from citadel.operator import app as operator_module
from citadel.tools import runner

RUN_ID = "run-1"
TENANT = "lab-a"
REF = "2f0c1e2a-0000-4000-8000-000000000001"
PR_ARGS = {
    "repo": "acme/infra",
    "base": "main",
    "head": "fix/oom-restart",
    "title": "Restart checkout-api on OOM",
    "body": "Adds a restart policy so the container recovers on its own",
}


class Done:
    def __init__(self, returncode: int = 0) -> None:
        self.returncode = returncode
        self.stdout = "ok"
        self.stderr = ""


def record_for(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "run_id": RUN_ID,
        "tool": tool,
        "approver": "user-carol",
        "decision": "approved",
        "ttl": 300,
        "args_hash": arguments_hash(arguments),
    }


def approving(record: dict[str, Any]) -> Any:
    """Stand in for the ledger lookup with one fixed audited decision."""

    def resolve(**kwargs: Any) -> Any:
        if not kwargs["ref"]:
            raise IdentityError("approval reference is not valid")
        return validate_approval(
            record,
            created_at=time.time(),
            tenant_id=kwargs["tenant_id"],
            ref=kwargs["ref"],
            run_id=kwargs["run_id"],
            tool=kwargs["tool"],
            arguments=kwargs["arguments"],
        )

    return resolve


@pytest.fixture
def client(
    monkeypatch: pytest.MonkeyPatch,
    analyzer: dict[str, list[dict[str, Any]]],
) -> TestClient:
    monkeypatch.setenv("CITADEL_DB_DSN", "unused")
    monkeypatch.setattr(operator_module, "_already_used", lambda *_: False)
    # Approve exactly what the request asks for; mismatch tests override this.
    monkeypatch.setattr(
        operator_module,
        "resolve_approval",
        lambda **kw: approving(record_for(kw["tool"], kw["arguments"]))(**kw),
    )

    captured: dict[str, Any] = {}
    ledger: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        ledger.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(ledger)}")

    def fake_run(argv: list[str]) -> Done:
        captured["argv"] = argv
        return Done()

    monkeypatch.setattr(operator_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    monkeypatch.setattr(runner, "run", fake_run)
    test_client = TestClient(operator_module.app)
    test_client.captured = captured
    test_client.ledger = ledger
    return test_client


def body(tool: str, arguments: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "tenant_id": TENANT,
        "run_id": RUN_ID,
        "tool": tool,
        "arguments": arguments,
        "approval_ref": REF,
    }
    payload.update(overrides)
    return payload


def test_approved_pr_opens_as_a_draft_from_the_named_branch(client: TestClient) -> None:
    response = client.post("/execute", json=body("open_remediation_pr", PR_ARGS))
    assert response.status_code == 200
    assert response.json()["allowlist_id"] == "gh.pr.create"
    assert client.captured["argv"] == [
        "gh",
        "pr",
        "create",
        "--draft",
        "--repo",
        "acme/infra",
        "--base",
        "main",
        "--head",
        "fix/oom-restart",
        "--title",
        PR_ARGS["title"],
        "--body",
        PR_ARGS["body"],
    ]


def test_restart_argv_carries_the_derived_container_name(client: TestClient) -> None:
    """The approver authorised a service; the container name is derived, and the
    derived argv is the one that was validated."""
    response = client.post("/execute", json=body("restart_service", {"service": "checkout-api"}))
    assert response.status_code == 200
    assert client.captured["argv"] == ["docker", "restart", "citadel-checkout-api-1"]


def test_approval_for_other_arguments_is_refused(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Red team: approval for one branch redirected to another."""
    monkeypatch.setattr(
        operator_module, "resolve_approval", approving(record_for("open_remediation_pr", PR_ARGS))
    )
    payload = body("open_remediation_pr", {**PR_ARGS, "head": "fix/something-else"})
    assert client.post("/execute", json=payload).status_code == 403


def test_used_approval_is_refused(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(operator_module, "_already_used", lambda *_: True)
    assert client.post("/execute", json=body("open_remediation_pr", PR_ARGS)).status_code == 409


def test_read_only_tool_cannot_be_written_through_the_operator(client: TestClient) -> None:
    """Red team: a T0 tool smuggled in as a 'write'."""
    assert client.post("/execute", json=body("inspect_containers", {})).status_code == 403


def test_t2_tool_is_refused(client: TestClient) -> None:
    assert client.post("/execute", json=body("force_push", {})).status_code == 403


def test_missing_approval_is_refused(client: TestClient) -> None:
    payload = body("open_remediation_pr", PR_ARGS, approval_ref="")
    assert client.post("/execute", json=payload).status_code == 403


def test_a_credential_in_approved_input_never_reaches_the_command(client: TestClient) -> None:
    """Red team: approval for text that happens to carry a token."""
    arguments = {**PR_ARGS, "body": "leaked ghp_" + "a" * 36}
    response = client.post("/execute", json=body("open_remediation_pr", arguments))

    assert response.status_code == 403
    assert "argv" not in client.captured, "gh must not have run"
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    assert "ghp_" not in response.text
    # The refusal is recorded even though no command ran and no result exists.
    assert [event["event_type"] for event in client.ledger] == ["dlp.event"]
    assert client.ledger[0]["payload"]["action"] == "block"
    assert "ghp_" not in str(client.ledger)


def test_detector_outage_refuses_the_operator_too(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise urllib.error.URLError("name resolution")

    monkeypatch.setattr(dlp, "urlopen", boom)
    response = client.post("/execute", json=body("restart_service", {"service": "checkout-api"}))

    assert response.status_code == 503
    assert "argv" not in client.captured
    assert [event["event_type"] for event in client.ledger] == ["dlp.event"]
    assert client.ledger[0]["payload"]["error"]


def test_a_secret_in_an_illegal_argument_is_refused_by_the_gate(
    client: TestClient,
) -> None:
    """A PR title with a metacharacter and a token: the gate must answer, not the parser."""
    secret = "ghp_" + "A1b2" * 8
    arguments = {**PR_ARGS, "title": f"rotate {secret}; now"}
    response = client.post("/execute", json=body("open_remediation_pr", arguments))

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    assert secret not in response.text
    # A refusal is also an event the auditor must see.
    assert [event["event_type"] for event in client.ledger] == ["dlp.event"]


def test_a_metacharacter_without_a_secret_names_the_position(client: TestClient) -> None:
    """No value, no command: the caller learns where the problem is, not what it was."""
    arguments = {**PR_ARGS, "title": "Restart; rm -rf /"}
    response = client.post("/execute", json=body("open_remediation_pr", arguments))

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert "shell metacharacter in argument" in detail
    assert "rm -rf" not in response.text
    assert client.ledger == []
