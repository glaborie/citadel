"""Command allowlist: the authorisation layer in front of every CLI call.

Default deny. A command must match a versioned entry exactly: the binary, a
required argv prefix, a closed set of flags, and a bounded number of
positional arguments. Nothing is ever passed to a shell.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from importlib import resources
from typing import Any

# Any of these in a token means the caller is trying to build a second command.
_FORBIDDEN = re.compile(r"[;|&$`<>\n\r\x00]")
_FLAG_WITH_VALUE = re.compile(r"^(?P<flag>--?[A-Za-z0-9-]+)=(?P<value>.*)$")


class CommandDenied(Exception):
    """Raised when a command is not on the allowlist. Never downgraded to allow."""


@dataclass(frozen=True)
class AllowedCommand:
    id: str
    agent: str
    tier: str
    argv: tuple[str, ...]
    flags: frozenset[str]
    flags_with_value: frozenset[str]
    max_positional: int
    # "definitive" = output discloses secrets by design, "possible" = may.
    content_risk: str | None = None


def load_allowlist() -> tuple[AllowedCommand, ...]:
    raw: dict[str, Any] = json.loads(
        resources.files("citadel.tools").joinpath("commands.json").read_text(encoding="utf-8")
    )
    return tuple(
        AllowedCommand(
            id=entry["id"],
            agent=entry["agent"],
            tier=entry["tier"],
            argv=tuple(entry["argv"]),
            flags=frozenset(entry.get("flags", [])),
            flags_with_value=frozenset(entry.get("flags_with_value", [])),
            max_positional=int(entry.get("max_positional", 0)),
            content_risk=entry.get("content_risk"),
        )
        for entry in raw["commands"]
    )


def _check_tokens(tokens: Sequence[str]) -> None:
    if not tokens:
        raise CommandDenied("empty command")
    for token in tokens:
        if not isinstance(token, str):
            raise CommandDenied("non-string token")
        if _FORBIDDEN.search(token):
            raise CommandDenied(f"illegal character in token {token!r}")
        if token.startswith("/") or ".." in token:
            raise CommandDenied(f"path traversal or absolute path in {token!r}")


def _matches(entry: AllowedCommand, tokens: Sequence[str]) -> bool:
    n = len(entry.argv)
    if len(tokens) < n or tuple(tokens[:n]) != entry.argv:
        return False

    positional = 0
    index = n
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            # Never rewrite arguments for the caller; anything after it is
            # positional and still bounded.
            index += 1
            continue
        if token.startswith("-"):
            if token in entry.flags:
                index += 1
                continue
            pair = _FLAG_WITH_VALUE.match(token)
            if pair and pair.group("flag") in entry.flags_with_value:
                index += 1
                continue
            if token in entry.flags_with_value:
                # Separate-value form: the next token is the value.
                if index + 1 >= len(tokens):
                    raise CommandDenied(f"flag {token} needs a value")
                index += 2
                continue
            raise CommandDenied(f"flag {token!r} is not permitted for {entry.id}")
        positional += 1
        if positional > entry.max_positional:
            raise CommandDenied(f"too many positional arguments for {entry.id}")
        index += 1
    return True


def match(tokens: Sequence[str], *, agent: str) -> AllowedCommand:
    """Return the allowlist entry for these tokens, or raise CommandDenied."""
    _check_tokens(tokens)
    candidates = [entry for entry in load_allowlist() if entry.agent == agent]
    if not candidates:
        raise CommandDenied(f"no allowlisted commands for agent {agent!r}")

    denied: str | None = None
    for entry in candidates:
        try:
            if _matches(entry, tokens):
                return entry
        except CommandDenied as exc:
            denied = str(exc)
    if denied is not None:
        # A prefix matched but the arguments were rejected: report the reason
        # rather than a generic miss, so the audit log is useful.
        raise CommandDenied(denied)
    raise CommandDenied(f"command not allowlisted for {agent}: {' '.join(tokens[:3])}")


def requires_redaction(command: AllowedCommand) -> bool:
    """True when the command's output is not safe to show without DLP."""
    return command.content_risk is not None


def audit_view(command: AllowedCommand, tokens: Sequence[str]) -> dict[str, Any]:
    return {
        "allowlist_id": command.id,
        "agent": command.agent,
        "tier": command.tier,
        "content_risk": command.content_risk,
        "argv": list(tokens),
    }
