-- Append-only, hash-chained security audit ledger.
--
-- Each row's hash covers the previous hash, so deleting or editing any row
-- breaks verification for everything after it. The application role may only
-- INSERT and SELECT: no UPDATE, no DELETE.

CREATE TABLE IF NOT EXISTS audit_events (
    id         uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  text        NOT NULL,
    seq        bigint      NOT NULL,
    event_type text        NOT NULL,
    actor_type text        NOT NULL,
    actor_id   text        NOT NULL,
    payload    jsonb       NOT NULL,
    prev_hash  text        NOT NULL,
    hash       text        NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT audit_events_tenant_seq_key UNIQUE (tenant_id, seq)
);

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS audit_tenant ON audit_events;
CREATE POLICY audit_tenant ON audit_events
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON audit_events TO citadel_app;
-- Defence in depth: even if a grant is added later, the intent is explicit.
REVOKE UPDATE, DELETE ON audit_events FROM citadel_app;

CREATE INDEX IF NOT EXISTS audit_events_tenant_seq_idx ON audit_events (tenant_id, seq);
