-- Single-use approval tokens. A jti is consumed exactly once.
CREATE TABLE IF NOT EXISTS approval_tokens (
    jti        text        PRIMARY KEY,
    tenant_id  text        NOT NULL,
    used_at    timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE approval_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_tokens FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS approval_tokens_tenant ON approval_tokens;
CREATE POLICY approval_tokens_tenant ON approval_tokens
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT ON approval_tokens TO citadel_app;
