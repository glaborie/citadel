-- Tool output that did not fit in the record.
--
-- Event history carries 8 KB of head and tail per stream plus the sha256 of the
-- whole thing. The digest proves what existed; this table is how a reviewer reads
-- it back without running a side-effecting tool again.
--
-- Bodies are the redacted text the tool service returned: the store is not a way
-- around the output gate. Keyed by (tenant_id, digest) so the same bytes found by
-- two tenants are two rows, and RLS keeps the separation that a shared
-- content-addressed key would otherwise erase.

CREATE TABLE IF NOT EXISTS tool_outputs (
    tenant_id   text        NOT NULL,
    digest      text        NOT NULL,
    run_id      uuid        NOT NULL,
    tool        text        NOT NULL,
    stream      text        NOT NULL,
    body        bytea       NOT NULL,
    bytes       integer     NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, digest)
);

CREATE INDEX IF NOT EXISTS tool_outputs_run ON tool_outputs (tenant_id, run_id);

ALTER TABLE tool_outputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_outputs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tool_outputs_tenant ON tool_outputs;
CREATE POLICY tool_outputs_tenant ON tool_outputs
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON tool_outputs TO citadel_app;
