"""Run lookups. Always tenant-scoped: RLS decides what exists."""

from __future__ import annotations

import uuid

from citadel.db import tenant_connection


class PostgresRunStore:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn

    def exists(self, *, tenant_id: str, run_id: str) -> bool:
        try:
            uuid.UUID(run_id)
        except (ValueError, AttributeError, TypeError):
            # A malformed id is simply not a run in this tenant.
            return False
        with tenant_connection(self._dsn, tenant_id) as conn:
            row = conn.execute("SELECT 1 FROM runs WHERE id = %s", (run_id,)).fetchone()
        return row is not None
