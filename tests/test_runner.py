"""Sandbox executor boundary."""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from citadel.tools import runner


class Done:
    def __init__(self, returncode: int = 0, stdout: str = "ok", stderr: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    captured: dict[str, Any] = {}

    def fake_run(argv: list[str]) -> Done:
        captured["argv"] = argv
        return Done()

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


@pytest.mark.parametrize("tool", ["read_logs", "get_pr_status"])
def test_risky_output_is_refused_until_dlp_exists(client: TestClient, tool: str) -> None:
    """definitive and possible risk are both blocked here for now."""
    args = {"service": "checkout-api"} if tool == "read_logs" else {"repo": "acme/infra"}
    response = client.post("/execute", json={"agent": "docker", "tool": tool, "arguments": args})
    assert response.status_code == 403


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
    monkeypatch.setenv("DOCKER_HOST", "tcp://docker-socket-proxy:2375")
    env = runner._child_env()
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert env["DOCKER_HOST"] == "tcp://docker-socket-proxy:2375"


def test_large_output_is_truncated() -> None:
    text, truncated = runner._clip("x" * (runner.MAX_OUTPUT_BYTES + 10))
    assert truncated is True
    assert len(text) == runner.MAX_OUTPUT_BYTES
