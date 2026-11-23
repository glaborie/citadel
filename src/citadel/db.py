"""Tenant-scoped database access. The tenant always comes from a verified token."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager

import psycopg


@contextmanager
def tenant_connection(dsn: str, tenant_id: str) -> Iterator[psycopg.Connection]:
    if not tenant_id:
        raise ValueError("refusing to open a connection without a tenant")
    with psycopg.connect(dsn) as conn, conn.transaction():
        # set_config(..., is_local => true) scopes the setting to this transaction.
        conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant_id,))
        yield conn
