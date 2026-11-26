"""Sandbox executor: runs allowlisted CLI commands, never a shell.

This is the last line of defence. The worker already validated policy, the
catalog and the allowlist; this service re-validates and refuses anything that
could disclose secrets before DLP exists, because a caller it cannot trust is
still a caller.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__, dlp
from citadel.env import secret
from citadel.tools import CommandDenied, build_argv
from citadel.tools.bounds import DEFAULT_OUTPUT_LIMIT, bound

COMMAND_TIMEOUT_SECONDS = 30
MAX_OUTPUT_BYTES = int(os.environ.get("CITADEL_TOOL_OUTPUT_MAX_BYTES", DEFAULT_OUTPUT_LIMIT))
DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")

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
    # The digest of the stream before it was bounded, so a caller can prove what
    # it did not receive instead of trusting the flag.
    output_sha256: str = ""
    original_bytes: int = 0
    omitted_bytes: int = 0
    # One report per DLP surface, including passes: the audit ledger has to show
    # that the control ran, not only that it found something.
    dlp: list[dict[str, Any]]


def _child_env(binary: str = "") -> dict[str, str]:
    env = {key: os.environ[key] for key in SAFE_ENV_KEYS if key in os.environ}
    if binary in BINARY_ENV_KEYS:
        # The token reaches only the child that needs it, and comes from a
        # mounted file so the container environment never carries it.
        try:
            for name in BINARY_ENV_KEYS[binary]:
                env[name] = secret(name)
        except KeyError:
            # Unconfigured gh is a refusal from gh itself, never a silent pass.
            pass
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env.setdefault("HOME", tempfile.gettempdir())
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


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


def _guard(text: str, *, surface: str) -> tuple[str, dict[str, Any]]:
    """DLP for one surface. Refuses rather than serving unchecked text."""
    try:
        return dlp.gate(text, surface=surface, analyzer_url=DLP_URL)
    except dlp.DlpBlocked as exc:
        raise HTTPException(
            status_code=exc.status, detail={"reason": exc.reason, "dlp": [exc.report]}
        ) from exc


@app.post("/execute")
def execute(request: ExecuteRequest) -> ExecuteResponse:
    # The raw arguments are inspected before they are parsed. Validation rejects a
    # malformed argument with a 403, and a gate that only ran after validation would
    # leave that path - the one an agent hits by accident - as the only route into a
    # response body that never consulted the detector.
    reports: list[dict[str, Any]] = []
    arguments = json.dumps(request.arguments, ensure_ascii=False)
    _, report = _guard(arguments, surface="input")
    reports.append(report)

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

    try:
        completed = run(argv)
    except FileNotFoundError as exc:
        # e.g. gh is not installed in the sandbox yet; say so plainly.
        raise HTTPException(
            status_code=503, detail=f"{argv[0]} is not available in the sandbox"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    # Scan the whole stream, then bound it. Clipping first would hand the
    # detector a shorter, cleaner string and call that a pass, which is exactly
    # how an output control becomes decorative: the secret past the cap is never
    # examined, and the caller is told the output was checked.
    # gate() returns the text it is safe to serve: findings are redacted in
    # place, so the value it hands back is the product, not a formality.
    stdout_checked, report = _guard(completed.stdout or "", surface="output")
    reports.append(report)
    stderr_checked, report = _guard(completed.stderr or "", surface="output")
    reports.append(report)

    out = bound(stdout_checked, limit=MAX_OUTPUT_BYTES)
    err = bound(stderr_checked, limit=MAX_OUTPUT_BYTES)
    return ExecuteResponse(
        allowlist_id=command.id,
        exit_code=completed.returncode,
        stdout=out.text,
        stderr=err.text,
        truncated=out.truncated or err.truncated,
        output_sha256=out.sha256,
        original_bytes=out.original_bytes,
        omitted_bytes=out.omitted_bytes,
        dlp=reports,
    )
