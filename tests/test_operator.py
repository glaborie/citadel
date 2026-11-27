from __future__ import annotations

import base64
import time
import urllib.error
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from citadel import dlp
from citadel.approvals import validate_approval
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError, Principal, mint_run_token
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
def tokens(run_private_key: Ed25519PrivateKey) -> Callable[..., str]:
    def mint(run_id: str = RUN_ID, tenant: str = TENANT) -> str:
        token, _ = mint_run_token(
            Principal("user-alice", tenant, frozenset()),
            agent_id="docker",
            scopes=frozenset(),
            risk_tier="T1",
            private_key=run_private_key,
            run_id=run_id,
        )
        return token

    return mint


@pytest.fixture
def client(
    monkeypatch: pytest.MonkeyPatch,
    analyzer: dict[str, list[dict[str, Any]]],
    run_public_key: Ed25519PublicKey,
    tokens: Callable[..., str],
) -> TestClient:
    public = run_public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    monkeypatch.setenv("CITADEL_RUN_TOKEN_PUBLIC_KEY", base64.b64encode(public).decode())
    monkeypatch.setenv("CITADEL_DB_DSN", "unused")
    monkeypatch.setattr(operator_module, "_already_used", lambda *_: False)
    # Approve exactly what the request asks for; mismatch tests override this.
    resolved: list[dict[str, Any]] = []

    def resolve(**kw: Any) -> Any:
        resolved.append(kw)
        return approving(record_for(kw["tool"], kw["arguments"]))(**kw)

    monkeypatch.setattr(operator_module, "resolve_approval", resolve)

    captured: dict[str, Any] = {}
    ledger: list[dict[str, Any]] = []

    def append(**kwargs: Any) -> SimpleNamespace:
        ledger.append(kwargs)
        return SimpleNamespace(audit_id=f"audit-{len(ledger)}")

    def fake_run(argv: list[str]) -> Done:
        captured["argv"] = argv
        # Read the body the way `gh` would, while the file still exists.
        if "--body-file" in argv:
            captured["body"] = Path(argv[argv.index("--body-file") + 1]).read_text()
        return Done()

    monkeypatch.setattr(operator_module, "AuditLedger", lambda _dsn: SimpleNamespace(append=append))
    monkeypatch.setattr(runner, "run", fake_run)
    test_client = TestClient(
        operator_module.app, headers={"Authorization": f"Bearer {tokens()}"}
    )
    test_client.captured = captured
    test_client.ledger = ledger
    test_client.resolved = resolved
    return test_client


def body(tool: str, arguments: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    """No tenant: the operator takes it from the run token's claims."""
    payload: dict[str, Any] = {
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
    argv = client.captured["argv"]
    assert argv[:13] == [
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
        "--body-file",
    ]
    # The body travelled as a file, and `gh` read the approved text from it.
    assert client.captured["body"] == PR_ARGS["body"]
    assert PR_ARGS["body"] not in " ".join(argv)


def test_the_body_file_is_gone_once_the_command_has_run(client: TestClient) -> None:
    """It is a hand-off, not a cache: the operator deletes what it wrote."""
    client.post("/execute", json=body("open_remediation_pr", PR_ARGS))
    path = Path(client.captured["argv"][client.captured["argv"].index("--body-file") + 1])

    assert not path.exists()


def test_a_multiline_body_opens_the_pr(client: TestClient) -> None:
    """The limitation lifted: newlines and a version range survive the hand-off."""
    text = "Fixes 0.1..0.2\n\n- restart on OOM\n- keep the logs\n"
    client.post("/execute", json=body("open_remediation_pr", {**PR_ARGS, "body": text}))

    assert client.captured["body"] == text
    assert "0.1..0.2" not in " ".join(client.captured["argv"])


def test_a_body_over_the_limit_is_refused_before_a_file_is_written(
    client: TestClient,
) -> None:
    response = client.post(
        "/execute", json=body("open_remediation_pr", {**PR_ARGS, "body": "x" * 4001})
    )

    assert response.status_code == 403
    assert "exceeds 4000 characters" in response.json()["detail"]


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


def test_execute_without_a_token_is_refused(client: TestClient) -> None:
    """Red team: a peer on the internal network presenting no credential at all.

    Before #237 this route took a credential-free body and drove the T1 writer.
    """
    anonymous = TestClient(operator_module.app)
    response = anonymous.post(
        "/execute", json=body("restart_service", {"service": "checkout-api"})
    )
    assert response.status_code == 401
    assert client.captured == {}, "nothing may run for an unidentified caller"


def test_a_token_for_another_run_is_refused(
    client: TestClient, tokens: Callable[..., str]
) -> None:
    """Red team: a stolen approval spent under a token minted for a different run."""
    other_run = "11111111-1111-1111-1111-111111111111"
    response = client.post(
        "/execute",
        json=body("restart_service", {"service": "checkout-api"}),
        headers={"Authorization": f"Bearer {tokens(run_id=other_run)}"},
    )
    assert response.status_code == 403
    assert "run" in response.json()["detail"]
    assert client.captured == {}


def test_resolution_runs_under_the_token_tenant(client: TestClient) -> None:
    """The tenant is a claim, not an input: the approval is resolved under it."""
    payload = {**body("restart_service", {"service": "checkout-api"}), "tenant_id": "lab-b"}

    forged = client.post("/execute", json=payload)
    assert forged.status_code == 422, "the body cannot carry a tenant at all"

    accepted = client.post("/execute", json=body("restart_service", {"service": "checkout-api"}))
    assert accepted.status_code == 200
    assert client.resolved[0]["tenant_id"] == TENANT


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
