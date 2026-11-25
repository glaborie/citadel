"""The operator service: the only component that performs a T1 write.

It is deliberately narrow. A caller supplies a tool name and named arguments
that a human already approved plus the signed token proving it; the operator
re-builds the argv from the catalog and runs it. It accepts no command line and
no free text, so a prompt-injected agent cannot compose an action of its own.
The worst it can do is replay an approval, which the jti table prevents.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__, dlp
from citadel.approvals import verify_approval_token
from citadel.db import tenant_connection
from citadel.identity import IdentityError
from citadel.identity.run_token import public_key_from_env
from citadel.tools import CommandDenied, build_argv
from citadel.tools import runner as executor

WRITABLE_TIERS = {"T1"}
DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")

app = FastAPI(title="Citadel Operator", version=__version__)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    run_id: str
    tool: str
    arguments: dict[str, Any] = {}
    approval_token: str


def _already_used(dsn: str, tenant_id: str, jti: str) -> bool:
    with tenant_connection(dsn, tenant_id) as conn:
        row = conn.execute(
            "INSERT INTO approval_tokens (jti, tenant_id) VALUES (%s, %s)"
            " ON CONFLICT (jti) DO NOTHING RETURNING jti",
            (jti, tenant_id),
        ).fetchone()
    return row is None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


def _guard(text: str, *, surface: str) -> tuple[str, dict[str, Any]]:
    """DLP for one surface. Refuses rather than running or returning unchecked text."""
    try:
        return dlp.gate(text, surface=surface, analyzer_url=DLP_URL)
    except dlp.DlpBlocked as exc:
        raise HTTPException(
            status_code=exc.status, detail={"reason": exc.reason, "dlp": [exc.report]}
        ) from exc


@app.post("/execute")
def execute(request: ExecuteRequest) -> dict[str, Any]:
    public_key = public_key_from_env(os.environ["CITADEL_RUN_TOKEN_PUBLIC_KEY"])
    try:
        claims = verify_approval_token(
            request.approval_token,
            public_key=public_key,
            tenant_id=request.tenant_id,
            run_id=request.run_id,
            tool=request.tool,
            arguments=request.arguments,
        )
    except IdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if _already_used(os.environ["CITADEL_DB_DSN"], request.tenant_id, claims.jti):
        raise HTTPException(status_code=409, detail="approval token already used")

    # The approver authorised the service name; build_argv derives the container
    # name and validates the derived argv — never a validated argv rewritten.
    try:
        argv, command = build_argv(request.tool, request.arguments)
    except CommandDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if command.tier not in WRITABLE_TIERS:
        raise HTTPException(status_code=403, detail=f"{command.id} is not a T1 command")

    # Checked before anything runs: a credential in an argument must never
    # reach a command, and rewriting an argument would run something other than
    # what the human approved.
    reports: list[dict[str, Any]] = []
    arguments = json.dumps(request.arguments, ensure_ascii=False)
    _, report = _guard(arguments, surface="input")
    reports.append(report)

    try:
        completed = executor.run(argv)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"{argv[0]} is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    stdout, report = _guard(completed.stdout[:4000], surface="output")
    reports.append(report)
    stderr, report = _guard(completed.stderr[:4000], surface="output")
    reports.append(report)
    return {
        "allowlist_id": command.id,
        "argv": argv,
        "approver": claims.approver,
        "exit_code": completed.returncode,
        "stdout": stdout,
        "stderr": stderr,
        "dlp": reports,
    }
