"""Sandbox executor boundary."""

from __future__ import annotations

import hashlib
import json
import urllib.error
from typing import Any

import pytest
from fastapi.testclient import TestClient

from citadel import dlp
from citadel.tools import runner
from citadel.tools.bounds import bound
from tests.conftest import AnalyzerResponse

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
        {"entity_type": "EMAIL_ADDRESS", "start": 0, "end": 12, "score": 1.0}
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


def test_gh_token_comes_from_a_mounted_file(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    path = tmp_path / "gh_token"
    path.write_text("ghp_from_file\n", encoding="ascii")
    monkeypatch.setenv("GH_TOKEN_FILE", str(path))
    monkeypatch.setenv("GH_TOKEN", "ghp_from_env")
    assert runner._child_env("gh")["GH_TOKEN"] == "ghp_from_file"
    assert "GH_TOKEN" not in runner._child_env("docker")


def test_large_output_is_bounded_to_the_cap() -> None:
    result = bound("x" * (runner.MAX_OUTPUT_BYTES + 10), limit=runner.MAX_OUTPUT_BYTES)
    assert result.truncated is True
    assert len(result.text.encode("utf-8")) <= runner.MAX_OUTPUT_BYTES


SECRET = "ghp_" + "A" * 36


def test_a_secret_past_the_cap_is_refused(client: TestClient) -> None:
    """The old order clipped to 64 KB and then scanned: this token vanished first.

    Scan-then-bound is the only order in which the answer to "was the output
    checked?" is yes for the whole output, not just its first 64 KB.
    """
    client.captured["stdout"] = ("x" * 90_000) + f" token={SECRET}\n"

    response = client.post("/execute", json=LOGS)

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"


def test_a_large_clean_output_is_bounded_not_truncated_silently(
    client: TestClient,
) -> None:
    body = "HEAD\n" + ("a" * 100_000) + "\nlast line of the traceback\n"
    client.captured["stdout"] = body

    response = client.post("/execute", json=LOGS)
    assert response.status_code == 200
    payload = response.json()

    assert payload["truncated"] is True
    assert len(payload["stdout"].encode("utf-8")) <= runner.MAX_OUTPUT_BYTES
    assert payload["stdout"].startswith("HEAD")
    # Head-only clipping used to drop this, which is where the diagnosis is.
    assert payload["stdout"].rstrip().endswith("last line of the traceback")
    assert payload["output_sha256"] == hashlib.sha256(body.encode()).hexdigest()
    assert payload["original_bytes"] == len(body.encode())
    assert payload["omitted_bytes"] == payload["original_bytes"] - len(
        payload["stdout"].encode("utf-8")
    )


def test_a_small_output_is_reported_as_complete(client: TestClient) -> None:
    client.captured["stdout"] = "one line\n"

    payload = client.post("/execute", json=LOGS).json()

    assert payload["truncated"] is False
    assert payload["omitted_bytes"] == 0
    assert payload["stdout"] == "one line\n"
    assert payload["output_sha256"] == hashlib.sha256(b"one line\n").hexdigest()


def test_both_dlp_surfaces_are_reported_with_the_bound(
    client: TestClient, analyzer: dict[str, list[dict[str, Any]]]
) -> None:
    """Input and output each get a report, passes included."""
    client.captured["stdout"] = "y" * 80_000
    analyzer["y" * 80_000] = []

    payload = client.post("/execute", json=LOGS).json()

    assert {report["surface"] for report in payload["dlp"]} == {"input", "output"}
    assert all(report["action"] == "pass" for report in payload["dlp"])
    assert payload["truncated"] is True


@pytest.mark.parametrize("limit", [1_024, 4_096])
def test_the_cap_is_configurable_through_the_bounds(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, limit: int
) -> None:
    """The number is a policy choice; the invariant is that it holds."""
    monkeypatch.setattr(runner, "MAX_OUTPUT_BYTES", limit)
    client.captured["stdout"] = "z" * (limit * 3)

    payload = client.post("/execute", json=LOGS).json()

    assert len(payload["stdout"].encode("utf-8")) <= limit
    assert json.loads(json.dumps(payload))["truncated"] is True


def test_a_secret_in_an_illegal_argument_is_refused_by_the_gate(
    client: TestClient,
) -> None:
    """The ordering is the fix: without it, this argument returns a 403 that quotes it."""
    secret = "ghp_" + "A1b2" * 8
    arguments = {"service": f"x;{secret}"}
    response = client.post(
        "/execute", json={"agent": "docker", "tool": "read_logs", "arguments": arguments}
    )

    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "dlp_blocked"
    assert secret not in response.text


def test_the_gate_runs_even_when_validation_would_refuse(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    """One analyzer call, on the raw arguments, before `build_argv` is reached."""
    arguments = {"service": "checkout-api; rm -rf /"}
    seen: list[str] = []

    def counting(request: Any, timeout: Any = None) -> AnalyzerResponse:
        seen.append(json.loads(request.data)["text"])
        return AnalyzerResponse([])

    monkeypatch.setattr(dlp, "urlopen", counting)
    response = client.post(
        "/execute", json={"agent": "docker", "tool": "read_logs", "arguments": arguments}
    )

    assert response.status_code == 403
    assert "service" in response.json()["detail"]
    assert "rm -rf" not in response.text
    assert seen == [json.dumps(arguments, ensure_ascii=False)]
