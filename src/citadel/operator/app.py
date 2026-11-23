"""The operator service: the only component that performs a T1 write.

It is deliberately narrow. One action, one command, and every request must
carry a signed approval token binding the tenant, run, tool and arguments. It
never sees model output, so a prompt-injected agent cannot talk it into
anything; the worst it can do is replay an approval, which the jti table
prevents.
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
from citadel.tools import runner as sandbox

WRITABLE_TIERS = {"T1"}

app = FastAPI(title="Citadel Operator", version=__version__)


class RestartRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str
    run_id: str
    tool: str
    arguments: dict[str, Any] = {}
    approval_token: str


def container_name(service: str) -> str:
    # v0.1 couples to Compose naming; revisit when the project name changes.
    return f"citadel-{service}-1"


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


@app.post("/restart")
def restart(request: RestartRequest) -> dict[str, Any]:
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
        argv, command = build_argv(request.tool, request.arguments)
    except CommandDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    if command.tier not in WRITABLE_TIERS:
        raise HTTPException(status_code=403, detail=f"{command.id} is not a T1 command")

    service = str(request.arguments.get("service", ""))
    argv = [*argv[:-1], container_name(service)]

    try:
        completed = sandbox.run(argv)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail="docker is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    return {
        "allowlist_id": command.id,
        "approver": claims.approver,
        "exit_code": completed.returncode,
        "stdout": completed.stdout[:4000],
        "stderr": completed.stderr[:4000],
    }
