"""Command allowlist boundary: what may run, and what must never run."""

from __future__ import annotations

import pytest

from citadel.tool_outputs import MAX_STORED_BYTES
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
        ["docker", "logs", "citadel-checkout-api-1"],
        ["docker", "logs", "citadel-checkout-api-1", "--tail", "100"],
        ["docker", "logs", "--since", "10m", "citadel-checkout-api-1"],
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


def test_exactly_two_t1_commands_one_per_agent() -> None:
    t1 = sorted(entry.id for entry in load_allowlist() if entry.tier == "T1")
    assert t1 == ["docker.restart", "gh.pr.create"]


def test_pr_create_is_pinned_to_a_draft_from_a_named_branch() -> None:
    """The write's shape is fixed in the argv prefix, not chosen by the caller."""
    tokens = [
        "gh",
        "pr",
        "create",
        "--draft",
        "--repo",
        "acme/infra",
        "--base",
        "main",
        "--head",
        "fix/oom",
        "--title",
        "Restart checkout-api on OOM",
        "--body-file",
        "/tmp/citadel-pr-text/0123456789abcdef.txt",
    ]
    command = match(tokens, agent="github")
    assert command.id == "gh.pr.create"
    assert command.tier == "T1"
    assert command.argv == ("gh", "pr", "create", "--draft")


@pytest.mark.parametrize(
    "tokens",
    [
        # The fixed prefix is mandatory: no un-drafted PR.
        ["gh", "pr", "create", "--repo", "acme/infra", "--head", "x"],
        ["gh", "pr", "create", "--draft", "--base", "main", "extra"],
        ["gh", "pr", "create", "--draft", "--head", "x", "--admin"],
        ["gh", "pr", "create", "--draft", "--head", "x", "--fill"],
        ["gh", "pr", "create", "--draft", "--head", "x", "--body-file", "/tmp/x"],
    ],
)
def test_pr_create_does_not_accept_extra_flags(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="github")


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
        ["docker", "logs", "citadel-checkout-api-1", ">", "/etc/passwd"],
    ],
)
def test_shell_injection_is_denied(tokens: list[str]) -> None:
    with pytest.raises(CommandDenied):
        match(tokens, agent="docker")


@pytest.mark.parametrize(
    "tokens",
    [
        ["docker", "inspect", "../../etc/passwd"],
        ["docker", "logs", "/etc/shadow"],
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

def test_a_command_may_raise_its_own_output_cap() -> None:
    """Only the command whose output IS the answer: a diff, not a log."""
    commands = load_allowlist()
    raised = {c.id for c in commands if c.output_limit is not None}
    assert raised == {"gh.pr.diff"}
    diff = next(c for c in commands if c.id == "gh.pr.diff")
    assert diff.output_limit == 524_288
    # Below the store's limit, or the bytes would be capped again on the way in.
    assert 0 < int(diff.output_limit or 0) <= MAX_STORED_BYTES


def test_a_command_without_a_cap_uses_the_default() -> None:
    logs = next(c for c in load_allowlist() if c.id == "docker.logs")
    assert logs.output_limit is None


def test_a_body_file_must_look_like_the_operators_own_file() -> None:
    """The one absolute path the argv may carry, and only in the shape written."""
    prefix = ["gh", "pr", "create", "--draft", "--repo", "acme/infra", "--base", "main"]
    accepted = [*prefix, "--body-file", "/tmp/citadel-pr-text/0123456789abcdef.txt"]
    assert match(accepted, agent="github").id == "gh.pr.create"

    for value in (
        "/etc/passwd",
        "/tmp/citadel-pr-text/../../etc/passwd.txt",
        "/tmp/citadel-pr-text/abc.txt;id",
        "citadel-pr-text/abc.txt",
    ):
        with pytest.raises(CommandDenied):
            match([*prefix, "--body-file", value], agent="github")


def test_the_inline_body_flag_is_gone() -> None:
    """Prose on the command line was the limitation; the flag is not offered."""
    with pytest.raises(CommandDenied, match="not permitted"):
        match(
            ["gh", "pr", "create", "--draft", "--body", "text"],
            agent="github",
        )
