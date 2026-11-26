"""Turn a tool call into argv, then verify it against the command allowlist.

The model never supplies a command line. It supplies a tool name and named
arguments; Citadel builds the argv. Unknown tools, unmapped tools, unknown
argument names and malformed values are all denied.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from citadel.policy.catalog import ToolSpec, load_catalog
from citadel.tools.allowlist import AllowedCommand, CommandDenied, match

# Conservative: ids, names, paths inside a repo. No spaces, no separators.
_VALUE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:@/-]*$")


def container_name(service: str) -> str:
    # v0.1 couples to Compose naming; revisit when the project name changes.
    return f"citadel-{service}-1"


def _resolve(arguments: Mapping[str, Any]) -> dict[str, Any]:
    """Translate the service a caller names into the container that exists.

    The approval token binds the service name, so this runs after approval
    verification and on the way to argv. A value that would fail the normal
    argument checks is passed through untouched, so it is refused by the same
    code path and with the same message.
    """
    service = arguments.get("service")
    if isinstance(service, str) and _VALUE.match(service):
        return {**arguments, "service": container_name(service)}
    return dict(arguments)


def needs_body_file(tool: str, *, catalog: dict[str, ToolSpec] | None = None) -> bool:
    """Whether this tool's prose travels as a file instead of as an argument."""
    specs = catalog if catalog is not None else load_catalog()
    spec = specs.get(tool)
    return spec is not None and any(param.kind == "body_file" for param in spec.params)


def build_argv(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    body_path: Path | None = None,
    catalog: dict[str, ToolSpec] | None = None,
) -> tuple[list[str], AllowedCommand]:
    """Build the argv for a tool call.

    `body_path` is the operator's file for a `body_file` parameter. It is not an
    argument: a caller that tries to supply it is refused as an unexpected
    argument, and a call that needs one without it is refused here.
    """
    specs = catalog if catalog is not None else load_catalog()
    spec = specs.get(tool)
    if spec is None:
        raise CommandDenied(f"tool {tool!r} is not in the catalog")
    if spec.command is None:
        raise CommandDenied(f"tool {tool!r} has no allowlisted command yet")
    if spec.tier == "T2":
        raise CommandDenied(f"tool {tool!r} is T2 and never executes")

    known = {param.name for param in spec.params}
    unexpected = set(arguments) - known
    if unexpected:
        raise CommandDenied(f"unexpected arguments for {tool}: {sorted(unexpected)}")

    resolved = _resolve(arguments)
    # Pinned arguments first: the catalog decides what the command is allowed to
    # disclose, and the caller's parameters are appended after them.
    tokens: list[str] = list(spec.args)
    for param in spec.params:
        value = resolved.get(param.name)
        if value is None:
            if param.required:
                raise CommandDenied(f"{tool} requires argument {param.name!r}")
            continue
        if param.kind == "body_file":
            # The prose is already in the operator's file; argv carries its name.
            # The value is still checked, because a body that is too long must be
            # refused before anyone writes it to disk, and skipping the render path
            # would otherwise skip the checks with it.
            if not isinstance(value, str):
                raise CommandDenied(f"argument {param.name!r} must be a string")
            if len(value) > param.max_length:
                raise CommandDenied(
                    f"argument {param.name!r} exceeds {param.max_length} characters"
                )
            if body_path is None:
                raise CommandDenied(f"{tool} needs {param.name!r} written to a file first")
            tokens.extend([param.flag or "--body-file", str(body_path)])
            continue
        tokens.extend(_render(param.name, param, value))

    # The catalog must not invent flags; re-check the built argv against the list.
    from citadel.tools import load_allowlist  # local import keeps cycles out

    entry = next((c for c in load_allowlist() if c.id == spec.command), None)
    if entry is None:
        raise CommandDenied(f"command {spec.command!r} is not allowlisted")
    full = list(entry.argv) + tokens
    return full, match(full, agent=spec.agent)


def _render(name: str, param: Any, value: Any) -> Sequence[str]:
    if not isinstance(value, str):
        raise CommandDenied(f"argument {name!r} must be a string")
    if len(value) > param.max_length:
        raise CommandDenied(f"argument {name!r} exceeds {param.max_length} characters")
    if param.kind == "text":
        # Short prose that stays on the command line (a PR title). One line,
        # printable; the allowlist matcher still rejects shell metacharacters and
        # ".." on the built argv, so a title cannot contain an ellipsis. A body
        # is not text: it travels as a file (`body_file`), because a body is where
        # the ellipses, version ranges and fenced blocks live.
        if param.flag is None:
            raise CommandDenied(f"argument {name!r} is text without a flag name")
        if not value.strip() or any(ch < " " or ch == "\x7f" for ch in value):
            raise CommandDenied(f"argument {name!r} must be one printable line")
        return [param.flag, value]
    if not _VALUE.match(value):
        raise CommandDenied(f"argument {name!r} has disallowed characters")
    if param.kind == "flag":
        if param.flag is None:
            raise CommandDenied(f"argument {name!r} is a flag without a flag name")
        return [param.flag, value]
    return [value]
