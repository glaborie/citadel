"""One CLI for humans and agents: `citadel <verb>`.

The contract every subcommand keeps is in ADR-026 — `--json` for one machine-readable
document, exit codes that separate failure from refusal from unavailability, no prompts,
no credentials on stdout, and a hint attached to every failure.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Sequence

EXIT_OK: Final = 0
EXIT_FAILED: Final = 1
EXIT_USAGE: Final = 2
EXIT_REFUSED: Final = 3
EXIT_UNAVAILABLE: Final = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="citadel",
        description="Operate a Citadel deployment: check it, run it, read what it recorded.",
    )
    parser.add_argument("--version", action="version", version="citadel (see pyproject.toml)")
    commands = parser.add_subparsers(dest="command", metavar="<command>")

    doctor = commands.add_parser("doctor", help="report whether each dependency answers")
    doctor.add_argument("--json", action="store_true", help="one document, nothing else")
    doctor.set_defaults(handler="doctor")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_USAGE

    if args.handler == "doctor":
        from citadel.cli.doctor import run

        return run(as_json=args.json)

    parser.error(f"unknown command {args.command!r}")  # exits 2, the usage code
    return EXIT_USAGE


def emit(payload: dict[str, object], *, as_json: bool, text: str) -> None:
    """The one place a subcommand decides between a person and a pipe."""
    if as_json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(text, end="" if text.endswith("\n") else "\n")
    sys.stdout.flush()


__all__ = ["EXIT_FAILED", "EXIT_OK", "EXIT_REFUSED", "EXIT_UNAVAILABLE", "EXIT_USAGE", "main"]
