"""The operator service: the only component that performs a T1 write.

It is deliberately narrow. A caller supplies a tool name and named arguments
that a human already approved plus the signed token proving it; the operator
re-builds the argv from the catalog and runs it. It accepts no command line and
no free text, so a prompt-injected agent cannot compose an action of its own.
The worst it can do is replay an approval, which the jti table prevents.
"""

from __future__ import annotations

import os
import subprocess
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__
from citadel.approvals import verify_approval_token
from citadel.db import tenant_connection
from citadel.identity import IdentityError
from citadel.identity.run_token import public_key_from_env
from citadel.tools import CommandDenied, build_argv
from citadel.tools import runner as executor
from citadel.tools.allowlist import AllowedCommand

WRITABLE_TIERS = {"T1"}

app = FastAPI(title="Citadel Operator", version=__version__)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    run_id: str
    tool: str
    arguments: dict[str, Any] = {}
    approval_token: str


def container_name(service: str) -> str:
    # v0.1 couples to Compose naming; revisit when the project name changes.
    return f"citadel-{service}-1"


def _resolved_argv(tool: str, arguments: dict[str, Any]) -> tuple[list[str], AllowedCommand]:
    """Translate the approved arguments into the argv that actually runs.

    The approver authorised the service name, so the container name is derived
    here and the derived argv is what gets validated — never a validated argv
    that is then rewritten.
    """
    resolved = dict(arguments)
    if tool == "restart_service" and "service" in resolved:
        resolved["service"] = container_name(str(resolved["service"]))
    return build_argv(tool, resolved)


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

    try:
        argv, command = _resolved_argv(request.tool, request.arguments)
    except CommandDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if command.tier not in WRITABLE_TIERS:
        raise HTTPException(status_code=403, detail=f"{command.id} is not a T1 command")

    try:
        completed = executor.run(argv)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"{argv[0]} is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    return {
        "allowlist_id": command.id,
        "argv": argv,
        "approver": claims.approver,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[:4000],
        "stderr": completed.stderr[:4000],
    }
