"""Single-use approval references.

The API records an approval in the append-only audit ledger and signals only
that record's id; the operator resolves the id back to the decision. Temporal
history therefore carries no bearer credential, and a reference is consumed
exactly once by the operator's `approval_tokens` table.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from citadel.db import tenant_connection
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError


@dataclass(frozen=True)
class ApprovalClaims:
    tenant_id: str
    run_id: str
    tool: str
    arguments_hash: str
    approver: str
    ref: str


def validate_approval(
    record: Mapping[str, Any],
    *,
    created_at: float,
    tenant_id: str,
    ref: str,
    run_id: str,
    tool: str,
    arguments: Mapping[str, Any],
    now: float | None = None,
) -> ApprovalClaims:
    """Turn one audited decision into claims, or refuse. Never a partial answer."""
    if record.get("decision") != "approved":
        raise IdentityError("approval was not granted")
    if not record.get("approver"):
        raise IdentityError("approval names no approver")
    if record.get("run_id") != run_id:
        raise IdentityError("approval was issued for another run")
    if record.get("tool") != tool:
        raise IdentityError("approval was issued for another tool")
    if record.get("args_hash") != arguments_hash(arguments):
        raise IdentityError("approval does not match these arguments")
    ttl = record.get("ttl")
    if not isinstance(ttl, int) or ttl <= 0:
        raise IdentityError("approval has no usable lifetime")
    if (time.time() if now is None else now) > created_at + ttl:
        raise IdentityError("approval expired")

    return ApprovalClaims(
        tenant_id=tenant_id,
        run_id=str(record["run_id"]),
        tool=str(record["tool"]),
        arguments_hash=str(record["args_hash"]),
        approver=str(record["approver"]),
        ref=ref,
    )


def resolve_approval(
    *,
    dsn: str,
    tenant_id: str,
    ref: str,
    run_id: str,
    tool: str,
    arguments: Mapping[str, Any],
    now: float | None = None,
) -> ApprovalClaims:
    """Load the approval the audit ledger holds under ``ref`` and validate it."""
    try:
        uuid.UUID(ref)
    except (ValueError, TypeError, AttributeError) as exc:
        raise IdentityError("approval reference is not valid") from exc
    with tenant_connection(dsn, tenant_id) as conn:
        row = conn.execute(
            "SELECT payload, EXTRACT(EPOCH FROM created_at) FROM audit_events"
            " WHERE id = %s::uuid AND tenant_id = %s AND event_type = 'approval.decision'",
            (ref, tenant_id),
        ).fetchone()
    if row is None:
        raise IdentityError("no approval for that reference")
    payload = row[0] if isinstance(row[0], dict) else json.loads(row[0])
    return validate_approval(
        payload,
        created_at=float(row[1]),
        tenant_id=tenant_id,
        ref=ref,
        run_id=run_id,
        tool=tool,
        arguments=arguments,
        now=now,
    )
