-- What a T1 call is waiting on.
--
-- The specialist writes this row before it waits for a human, so the console
-- has something durable to list and read. Arguments are stored only after the
-- DLP gate passes: a row a human is asked to approve must not carry a secret.

CREATE TABLE IF NOT EXISTS approval_requests (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    text        NOT NULL,
    run_id       uuid        NOT NULL,
    tool         text        NOT NULL,
    agent_id     text        NOT NULL,
    arguments    jsonb       NOT NULL,
    tier         text        NOT NULL,
    rule_id      text        NOT NULL,
    requested_by text        NOT NULL,
    status       text        NOT NULL DEFAULT 'pending',
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz,
    decided_by   text,
    reason       text,
    -- One child workflow per (run, tool), so a retry must not add a second row.
    CONSTRAINT approval_requests_once UNIQUE (run_id, tool)
);

ALTER TABLE approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE approval_requests FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS approval_requests_tenant ON approval_requests;
CREATE POLICY approval_requests_tenant ON approval_requests
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

GRANT SELECT, INSERT, UPDATE ON approval_requests TO citadel_app;
