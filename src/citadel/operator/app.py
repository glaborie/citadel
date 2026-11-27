"""The operator service: the only component that performs a T1 write.

It is deliberately narrow. A caller presents a signed run token, the audit
reference of a human approval and the tool with the approved named arguments;
the operator takes the tenant from the token's claims, resolves the reference
under that tenant, re-builds the argv from the catalog and runs it. It accepts
no command line, no free text and no tenant from the body, so a
prompt-injected agent cannot compose an action of its own. The worst it can do
is replay an approval, which the consumed reference prevents.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict

from citadel import __version__, dlp
from citadel.approvals import resolve_approval
from citadel.audit import AuditLedger
from citadel.db import tenant_connection
from citadel.env import secret
from citadel.identity import IdentityError
from citadel.identity.bearer import require_run_token
from citadel.identity.run_token import RunContext, bind_identity
from citadel.tools import CommandDenied, build_argv, needs_body_file, pr_text
from citadel.tools import runner as executor

WRITABLE_TIERS = {"T1"}
DLP_URL = os.environ.get("CITADEL_DLP_URL", "http://presidio:3000")

app = FastAPI(title="Citadel Operator", version=__version__)


class ExecuteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    run_id: str
    tool: str
    arguments: dict[str, Any] = {}
    approval_ref: str


def _dsn() -> str:
    return secret("CITADEL_DB_DSN")


def _already_used(dsn: str, tenant_id: str, ref: str) -> bool:
    with tenant_connection(dsn, tenant_id) as conn:
        row = conn.execute(
            "INSERT INTO approval_tokens (jti, tenant_id) VALUES (%s, %s)"
            " ON CONFLICT (jti) DO NOTHING RETURNING jti",
            (ref, tenant_id),
        ).fetchone()
    return row is None


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


def _guard(
    text: str,
    *,
    surface: str,
    tenant_id: str,
    run_id: str,
    tool: str,
    approver: str,
) -> tuple[str, dict[str, Any]]:
    """DLP for one surface. Refuses rather than running or returning unchecked text."""
    try:
        return dlp.gate(text, surface=surface, analyzer_url=DLP_URL)
    except dlp.DlpBlocked as exc:
        # A refused check is still an event an auditor must be able to see.
        AuditLedger(_dsn()).append(
            tenant_id=tenant_id,
            event_type="dlp.event",
            actor_type="user",
            actor_id=approver,
            payload={"run_id": run_id, "tool": tool, **exc.report},
        )
        raise HTTPException(
            status_code=exc.status, detail={"reason": exc.reason, "dlp": [exc.report]}
        ) from exc


@contextmanager
def _body_file(tool: str, run_id: str, arguments: dict[str, Any]) -> Iterator[Path | None]:
    """The approved body, on disk for exactly as long as the command that reads it.

    The text is written by this process, under a name this process derives, and
    removed once `gh` has finished - so a body can carry a newline or a version
    range without any of it touching the argv a caller could influence.
    """
    if not needs_body_file(tool):
        yield None
        return
    body = arguments.get("body")
    if not isinstance(body, str):
        raise CommandDenied("body must be a string")
    path = pr_text.write(tool=tool, run_id=run_id, body=body)
    try:
        yield path
    finally:
        pr_text.discard(path)


@app.post("/execute")
def execute(
    request: ExecuteRequest,
    ctx: Annotated[RunContext, Depends(require_run_token)],
) -> dict[str, Any]:
    # Identity first: the token decides the tenant and the run, and the body
    # only has to agree with it. Before #237 this route took a credential-free
    # body, so any peer on the internal network could drive the T1 writer.
    try:
        bind_identity(ctx, run_id=request.run_id)
    except IdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    try:
        claims = resolve_approval(
            dsn=_dsn(),
            tenant_id=ctx.tenant_id,
            ref=request.approval_ref,
            run_id=request.run_id,
            tool=request.tool,
            arguments=request.arguments,
        )
    except IdentityError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    if _already_used(_dsn(), ctx.tenant_id, claims.ref):
        raise HTTPException(status_code=409, detail="approval already used")

    # Checked before anything runs: a credential in an argument must never
    # reach a command, and rewriting an argument would run something other than
    # what the human approved. The gate also runs before `build_argv`, because
    # argument validation rejects a malformed value with a 403 whose detail the
    # caller reads - so a secret inside an illegal argument would otherwise be
    # echoed back without the detector ever seeing it.
    reports: list[dict[str, Any]] = []
    arguments = json.dumps(request.arguments, ensure_ascii=False)
    context = {
        "tenant_id": claims.tenant_id,
        "run_id": claims.run_id,
        "tool": claims.tool,
        "approver": claims.approver,
    }
    _, report = _guard(arguments, surface="input", **context)
    reports.append(report)

    # The approver authorised the service name; build_argv derives the container
    # name and validates the derived argv — never a validated argv rewritten. A
    # body travels as a file, written here and removed when the command returns.
    try:
        with _body_file(request.tool, claims.run_id, request.arguments) as body_path:
            argv, command = build_argv(request.tool, request.arguments, body_path=body_path)
            if command.tier not in WRITABLE_TIERS:
                raise HTTPException(status_code=403, detail=f"{command.id} is not a T1 command")
            completed = executor.run(argv)
    except CommandDenied as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=503, detail=f"{argv[0]} is not available") from exc
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(status_code=504, detail="command timed out") from exc

    stdout, report = _guard(completed.stdout[:4000], surface="output", **context)
    reports.append(report)
    stderr, report = _guard(completed.stderr[:4000], surface="output", **context)
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
