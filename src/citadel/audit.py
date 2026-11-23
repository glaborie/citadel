"""Append-only, hash-chained audit ledger.

The chain is per tenant: each event's hash covers the previous event's hash,
its own sequence number and a canonical JSON payload. Editing or removing any
row invalidates every hash after it, which is what makes the ledger tamper
evident rather than merely append-only by convention.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass
from typing import Any

from citadel.db import tenant_connection

GENESIS = "0" * 64


@dataclass(frozen=True)
class AuditRef:
    audit_id: str
    tenant_id: str
    seq: int
    hash: str


def canonical(payload: dict[str, Any]) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)


def event_hash(
    *,
    prev_hash: str,
    tenant_id: str,
    seq: int,
    event_type: str,
    actor_type: str,
    actor_id: str,
    body: str,
) -> str:
    # Every audited column is in the material. Omitting actor_id would make
    # actor spoofing invisible to verification.
    material = f"{prev_hash}|{tenant_id}|{seq}|{event_type}|{actor_type}|{actor_id}|{body}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


class AuditLedger:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def append(
        self,
        *,
        tenant_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        payload: dict[str, Any],
    ) -> AuditRef:
        if not tenant_id:
            raise ValueError("audit events must be tenant scoped")
        body = canonical(payload)
        with tenant_connection(self._dsn, tenant_id) as conn:
            # Serialise appends per tenant without a separate coordination table.
            conn.execute("SELECT pg_advisory_xact_lock(hashtext(%s))", (tenant_id,))
            head = conn.execute(
                "SELECT seq, hash FROM audit_events WHERE tenant_id = %s ORDER BY seq DESC LIMIT 1",
                (tenant_id,),
            ).fetchone()
            seq = int(head[0]) + 1 if head is not None else 1
            prev_hash = str(head[1]) if head is not None else GENESIS
            digest = event_hash(
                prev_hash=prev_hash,
                tenant_id=tenant_id,
                seq=seq,
                event_type=event_type,
                actor_type=actor_type,
                actor_id=actor_id,
                body=body,
            )
            row = conn.execute(
                "INSERT INTO audit_events"
                " (tenant_id, seq, event_type, actor_type, actor_id, payload, prev_hash, hash)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (tenant_id, seq, event_type, actor_type, actor_id, body, prev_hash, digest),
            ).fetchone()
        if row is None:  # pragma: no cover - RETURNING always yields a row
            raise RuntimeError("audit insert returned no id")
        return AuditRef(audit_id=str(row[0]), tenant_id=tenant_id, seq=seq, hash=digest)

    def verify(self, tenant_id: str) -> tuple[bool, int]:
        """Return (chain_ok, number_of_events_checked)."""
        with tenant_connection(self._dsn, tenant_id) as conn:
            rows = conn.execute(
                "SELECT seq, event_type, actor_type, actor_id, payload, prev_hash, hash"
                " FROM audit_events"
                " WHERE tenant_id = %s ORDER BY seq",
                (tenant_id,),
            ).fetchall()

        expected_prev = GENESIS
        for index, row in enumerate(rows, start=1):
            seq, event_type, actor_type, actor_id, payload, prev_hash, stored = row
            if int(seq) != index:
                return False, len(rows)
            body = canonical(payload if isinstance(payload, dict) else json.loads(payload))
            recomputed = event_hash(
                prev_hash=str(prev_hash),
                tenant_id=tenant_id,
                seq=int(seq),
                event_type=str(event_type),
                actor_type=str(actor_type),
                actor_id=str(actor_id),
                body=body,
            )
            if str(prev_hash) != expected_prev or str(stored) != recomputed:
                return False, len(rows)
            expected_prev = str(stored)
        return True, len(rows)


def new_audit_id() -> str:
    return str(uuid.uuid4())
