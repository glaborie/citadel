"""Turn a tool call into argv, then verify it against the command allowlist.

The model never supplies a command line. It supplies a tool name and named
arguments; Citadel builds the argv. Unknown tools, unmapped tools, unknown
argument names and malformed values are all denied.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

from citadel.policy.catalog import ToolSpec, load_catalog
from citadel.tools.allowlist import AllowedCommand, CommandDenied, match

# Conservative: ids, names, paths inside a repo. No spaces, no separators.
_VALUE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.:@/-]*$")


def build_argv(
    tool: str,
    arguments: Mapping[str, Any],
    *,
    catalog: dict[str, ToolSpec] | None = None,
) -> tuple[list[str], AllowedCommand]:
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

    tokens: list[str] = []
    for param in spec.params:
        value = arguments.get(param.name)
        if value is None:
            if param.required:
                raise CommandDenied(f"{tool} requires argument {param.name!r}")
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
        # Prose (a PR title or body). One line, printable; the allowlist
        # matcher still rejects shell metacharacters on the built argv.
        # shortcut: the matcher also rejects ".." anywhere, so a body cannot
        # contain an ellipsis; switch to --fill from a checkout if that matters.
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
