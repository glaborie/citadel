-- Durable idempotency for tool execution.
--
-- The unique key is derived from (run_id, tool, canonical arguments), so a
-- Temporal retry after a crash hits the same row instead of repeating the
-- side effect. Effectively-once, not exactly-once: see ADR-014.

CREATE TABLE IF NOT EXISTS tool_calls (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    idempotency_key text        NOT NULL UNIQUE,
    tenant_id       text        NOT NULL,
    run_id          uuid        NOT NULL,
    tool            text        NOT NULL,
    status          text        NOT NULL,
    result          jsonb,
    created_at      timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_calls FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tool_calls_tenant ON tool_calls;
CREATE POLICY tool_calls_tenant ON tool_calls
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON tool_calls TO citadel_app;
