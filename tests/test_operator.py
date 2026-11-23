"""Operator boundary: only an approved T1 action runs, and only as rebuilt argv."""

from __future__ import annotations

import base64
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from fastapi.testclient import TestClient

from citadel.approvals import mint_approval_token
from citadel.operator import app as operator_module
from citadel.tools import runner

RUN_ID = "run-1"
TENANT = "lab-a"
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


@pytest.fixture
def key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def client(key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    public = base64.b64encode(
        key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    ).decode()
    monkeypatch.setenv("CITADEL_RUN_TOKEN_PUBLIC_KEY", public)
    monkeypatch.setenv("CITADEL_DB_DSN", "unused")
    monkeypatch.setattr(operator_module, "_already_used", lambda *_: False)

    captured: dict[str, Any] = {}

    def fake_run(argv: list[str]) -> Done:
        captured["argv"] = argv
        return Done()

    monkeypatch.setattr(runner, "run", fake_run)
    test_client = TestClient(operator_module.app)
    test_client.captured = captured
    return test_client


def body(
    key: Ed25519PrivateKey, tool: str, arguments: dict[str, Any], **overrides: Any
) -> dict[str, Any]:
    token = mint_approval_token(
        tenant_id=TENANT,
        run_id=RUN_ID,
        tool=tool,
        arguments=arguments,
        approver="user-carol",
        private_key=key,
    )
    payload: dict[str, Any] = {
        "tenant_id": TENANT,
        "run_id": RUN_ID,
        "tool": tool,
        "arguments": arguments,
        "approval_token": token,
    }
    payload.update(overrides)
    return payload


def test_approved_pr_opens_as_a_draft_from_the_named_branch(
    client: TestClient, key: Ed25519PrivateKey
) -> None:
    response = client.post("/execute", json=body(key, "open_remediation_pr", PR_ARGS))
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


def test_restart_argv_carries_the_derived_container_name(
    client: TestClient, key: Ed25519PrivateKey
) -> None:
    """The approver authorised a service; the container name is derived, and the
    derived argv is the one that was validated."""
    response = client.post(
        "/execute", json=body(key, "restart_service", {"service": "checkout-api"})
    )
    assert response.status_code == 200
    assert client.captured["argv"] == ["docker", "restart", "citadel-checkout-api-1"]


def test_token_for_other_arguments_is_refused(client: TestClient, key: Ed25519PrivateKey) -> None:
    """Red team: approval for one branch redirected to another."""
    payload = body(key, "open_remediation_pr", PR_ARGS)
    payload["arguments"] = {**PR_ARGS, "head": "fix/something-else"}
    assert client.post("/execute", json=payload).status_code == 403


def test_used_approval_is_refused(
    client: TestClient, key: Ed25519PrivateKey, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(operator_module, "_already_used", lambda *_: True)
    assert (
        client.post("/execute", json=body(key, "open_remediation_pr", PR_ARGS)).status_code == 409
    )


def test_read_only_tool_cannot_be_written_through_the_operator(
    client: TestClient, key: Ed25519PrivateKey
) -> None:
    """Red team: a T0 tool smuggled in as a 'write'."""
    assert client.post("/execute", json=body(key, "inspect_containers", {})).status_code == 403


def test_t2_tool_is_refused(client: TestClient, key: Ed25519PrivateKey) -> None:
    assert client.post("/execute", json=body(key, "force_push", {})).status_code == 403


def test_missing_approval_is_refused(client: TestClient, key: Ed25519PrivateKey) -> None:
    payload = body(key, "open_remediation_pr", PR_ARGS)
    payload["approval_token"] = ""
    assert client.post("/execute", json=payload).status_code == 403
