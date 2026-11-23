-- Tenant isolation for application data.
--
-- The policy reads app.tenant_id, which the API sets from the *verified token*
-- inside each transaction. When it is unset current_setting returns NULL, the
-- comparison is NULL, and no row is visible: fail closed.

CREATE TABLE IF NOT EXISTS runs (
    id         uuid        PRIMARY KEY,
    tenant_id  text        NOT NULL,
    user_id    text        NOT NULL,
    agent_id   text        NOT NULL,
    risk_tier  text        NOT NULL,
    status     text        NOT NULL DEFAULT 'created',
    created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE runs ENABLE ROW LEVEL SECURITY;
-- FORCE so the table owner is subject to the policy too.
ALTER TABLE runs FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS tenant_isolation ON runs;
CREATE POLICY tenant_isolation ON runs
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT USAGE ON SCHEMA public TO citadel_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON runs TO citadel_app;
