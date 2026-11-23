"""Sandbox executor: runs allowlisted CLI commands, never a shell.

This is the last line of defence. The worker already validated policy, the
catalog and the allowlist; this service re-validates and refuses anything that
could disclose secrets before DLP exists, because a caller it cannot trust is
still a caller.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__
from citadel.tools import CommandDenied, build_argv, requires_redaction

COMMAND_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = 64_000

# Nothing from the ambient environment reaches the child process. The GitHub
# token is only exposed to `gh`, so `docker ps` cannot read it.
SAFE_ENV_KEYS = ("PATH", "DOCKER_HOST", "HOME", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")
BINARY_ENV_KEYS = {"gh": ("GH_TOKEN",)}

app = FastAPI(title="Citadel Tool Runner", version=__version__)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    agent: str
    tool: str
    arguments: dict[str, Any] = {}


class ExecuteResponse(BaseModel):
    allowlist_id: str
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool


def _child_env(binary: str = "") -> dict[str, str]:
    keys = SAFE_ENV_KEYS + BINARY_ENV_KEYS.get(binary, ())
    env = {key: os.environ[key] for key in keys if key in os.environ}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.setdefault("HOME", "/tmp")
    return env


def run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    """Executed as an argv list with shell=False. No pipes, no redirection."""
    return subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=COMMAND_TIMEOUT_SECONDS,
        env=_child_env(argv[0] if argv else ""),
        shell=False,
        check=False,
    )


def _clip(text: str) -> tuple[str, bool]:
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= MAX_OUTPUT_BYTES:
        return text, False
    return encoded[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), True


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/execute")
def execute(request: ExecuteRequest) -> ExecuteResponse:
    try:
        argv, command = build_argv(request.tool, request.arguments)
    except CommandDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if command.agent != request.agent:
        raise HTTPException(status_code=403, detail="agent may not run this command")
    if command.tier != "T0":
        # Writes belong to the operator service, never to the sandbox.
        raise HTTPException(
            status_code=403, detail=f"{command.id} is {command.tier}; use the operator service"
        )
    if requires_redaction(command):
        # Step 7 adds DLP. Until then risky output never leaves the sandbox.
        raise HTTPException(
            status_code=403, detail=f"{command.id} output requires redaction before it is served"
        )

    try:
        completed = run(argv)
    except FileNotFoundError as exc:
        # e.g. gh is not installed in the sandbox yet; say so plainly.
        raise HTTPException(
            status_code=503, detail=f"{argv[0]} is not available in the sandbox"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    stdout, clipped_out = _clip(completed.stdout or "")
    stderr, clipped_err = _clip(completed.stderr or "")
    return ExecuteResponse(
        allowlist_id=command.id,
        exit_code=completed.returncode,
        stdout=stdout,
        stderr=stderr,
        truncated=clipped_out or clipped_err,
    )
