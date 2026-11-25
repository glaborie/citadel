"""Sandbox executor boundary."""

from __future__ import annotations

import urllib.error
from typing import Any

import pytest
from fastapi.testclient import TestClient

from citadel import dlp
from citadel.tools import runner

LOGS = {"agent": "docker", "tool": "read_logs", "arguments": {"service": "checkout-api"}}


class Done:
    def __init__(self, returncode: int = 0, stdout: str = "ok", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, analyzer: list[dict[str, Any]]) -> TestClient:
    captured: dict[str, Any] = {"stdout": "ok", "stderr": ""}

    def fake_run(argv: list[str]) -> Done:
        captured["argv"] = argv
        return Done(stdout=str(captured["stdout"]), stderr=str(captured["stderr"]))

    monkeypatch.setattr(runner, "run", fake_run)
    test_client = TestClient(runner.app)
    test_client.captured = captured
    return test_client


def test_execute_runs_the_built_argv(client: TestClient) -> None:
    response = client.post(
        "/execute", json={"agent": "docker", "tool": "inspect_containers", "arguments": {}}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["allowlist_id"] == "docker.ps"
    assert client.captured["argv"] == ["docker", "ps"]


def test_unknown_tool_is_refused(client: TestClient) -> None:
    response = client.post(
        "/execute", json={"agent": "docker", "tool": "exfiltrate", "arguments": {}}
    )
    assert response.status_code == 403


def test_agent_cannot_run_another_agents_tool(client: TestClient) -> None:
    """Red team: the docker agent asking the sandbox for a GitHub command."""
    response = client.post(
        "/execute", json={"agent": "docker", "tool": "get_pr_status", "arguments": {}}
    )
    assert response.status_code == 403


@pytest.mark.parametrize(
    ("agent", "tool", "arguments"),
    [
        ("docker", "restart_service", {"service": "checkout-api"}),
        (
            "github",
            "open_remediation_pr",
            {
                "repo": "a/b",
                "base": "main",
                "head": "x",
                "title": "t",
                "body": "b",
            },
        ),
    ],
)
def test_sandbox_refuses_t1_whatever_the_caller_asks(
    client: TestClient, agent: str, tool: str, arguments: dict[str, Any]
) -> None:
    """Writes belong to the operator; the sandbox never runs one."""
    response = client.post("/execute", json={"agent": agent, "tool": tool, "arguments": arguments})
    assert response.status_code == 403
    assert "use the operator service" in response.json()["detail"]


def test_output_passes_through_dlp_and_is_reported(client: TestClient) -> None:
    """`read_logs` output is served now, and the ledger can see DLP ran."""
    response = client.post("/execute", json=LOGS)

    assert response.status_code == 200
    assert client.captured["argv"] == ["docker", "logs", "citadel-checkout-api-1"]
    reports = response.json()["dlp"]
    assert [report["surface"] for report in reports] == ["input", "output", "output"]
    assert all(report["action"] == "pass" for report in reports)


def test_pii_in_output_is_redacted_before_it_is_served(
    client: TestClient, analyzer: dict[str, list[dict[str, Any]]]
) -> None:
    analyzer["a@example.ch"] = [
        {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 13, "score": 1.0}
    ]
    client.captured["stdout"] = "a@example.ch"

    body = client.post("/execute", json=LOGS).json()

    assert body["stdout"] == "<EMAIL_ADDRESS>"
    assert body["dlp"][1]["categories"] == ["EMAIL_ADDRESS"]


def test_a_credential_in_output_blocks_the_call(client: TestClient) -> None:
    client.captured["stdout"] = "boom ghp_" + "a" * 36

    response = client.post("/execute", json=LOGS)

    assert response.status_code == 403
    detail = response.json()["detail"]
    assert detail["reason"] == "dlp_blocked"
    assert detail["dlp"][0]["categories"] == ["GITHUB_TOKEN"]
    assert "ghp_" not in response.text


def test_a_credential_in_an_argument_never_reaches_the_command(
    client: TestClient,
) -> None:
    """Red team: smuggle a token through a tool argument instead of the output."""
    response = client.post(
        "/execute",
        json={**LOGS, "arguments": {"service": "ghp_" + "a" * 36}},
    )

    assert response.status_code == 403
    assert "argv" not in client.captured, "the command must not have run"
    assert "ghp_" not in response.text


def test_detector_outage_blocks_the_call(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail closed: an unavailable detector is a refusal, not a bypass."""

    def boom(*_: Any, **__: Any) -> Any:
        raise urllib.error.URLError("name resolution")

    monkeypatch.setattr(dlp, "urlopen", boom)

    response = client.post("/execute", json=LOGS)

    assert response.status_code == 503
    assert response.json()["detail"]["reason"] == "dlp_unavailable"
    assert "argv" not in client.captured


def test_malformed_arguments_are_refused(client: TestClient) -> None:
    response = client.post(
        "/execute",
        json={"agent": "docker", "tool": "read_logs", "arguments": {"service": "a; rm -rf /"}},
    )
    assert response.status_code == 403


def test_extra_fields_are_rejected(client: TestClient) -> None:
    response = client.post(
        "/execute",
        json={"agent": "docker", "tool": "inspect_containers", "arguments": {}, "argv": ["sh"]},
    )
    assert response.status_code == 422


def test_child_environment_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "should-not-leak")
    monkeypatch.setenv("GH_TOKEN", "ghp_secret")
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker-socket-proxy:2375")
    env = runner._child_env("docker")
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "GH_TOKEN" not in env, "only gh may see the token"
    assert env["DOCKER_HOST"] == "tcp://docker-socket-proxy:2375"


def test_gh_is_given_the_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GH_TOKEN", "ghp_secret")
    assert runner._child_env("gh")["GH_TOKEN"] == "ghp_secret"


def test_large_output_is_truncated() -> None:
    text, truncated = runner._clip("x" * (runner.MAX_OUTPUT_BYTES + 10))
    assert truncated is True
    assert len(text) == runner.MAX_OUTPUT_BYTES
