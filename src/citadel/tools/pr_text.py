"""A PR body travels as a file the operator writes, not as argv.

`gh pr create --body <prose>` puts caller text on a command line, which is why the
allowlist matcher refuses `..` anywhere inside it - a path-traversal token is a
path-traversal token whatever the flag - and why a newline cannot survive at all.

Writing the text to a file removes both limits without loosening the matcher: the
argv no longer contains the prose, only the name of a file that this module named.
A caller cannot choose that name. It is `sha256(tool:run_id)`, so the same approved
argument set always resolves to the same path, and a different run to a different
one.

The text itself is not sanitised here, because it is not a path and never becomes
one. It is the body of a pull request: newlines, `..`, version ranges and fenced
blocks are what a body is made of.
"""

from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

# Overridable so a test - and a deployment that wants a volume - can say where.
DIRECTORY_ENV = "CITADEL_PR_TEXT_DIR"
SUFFIX = ".txt"


def directory() -> Path:
    """Where the operator keeps the bodies it hands to `gh`."""
    configured = os.environ.get(DIRECTORY_ENV)
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "citadel-pr-text"


def path_for(tool: str, run_id: str) -> Path:
    """The operator's own name for the file. Nothing a caller can choose."""
    seed = hashlib.sha256(f"{tool}:{run_id}".encode()).hexdigest()[:16]
    return directory() / f"{seed}{SUFFIX}"


def write(*, tool: str, run_id: str, body: str) -> Path:
    """Write the approved body and return the path handed to `gh`.

    Created 0600 in a 0700 directory: the body is what a human approved, so it may
    quote the incident that caused it. The write goes through a temporary name in
    the same directory so a reader never sees a half-written body.
    """
    target = path_for(tool, run_id)
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    handle, name = tempfile.mkstemp(dir=target.parent, suffix=".part")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(body)
        os.chmod(name, 0o600)
        os.replace(name, target)
    except BaseException:
        Path(name).unlink(missing_ok=True)
        raise
    return target


def discard(path: Path) -> None:
    """Remove the file once the command that read it has finished."""
    path.unlink(missing_ok=True)
