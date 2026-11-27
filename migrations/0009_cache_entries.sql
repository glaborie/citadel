-- Citadel-owned model answer cache (ADR-018).
--
-- An entry is only reachable through its full partition key: tenant,
-- entitlement hash, agent, prompt-pack version, model alias, tool-context
-- version and the policy-model version. A row is never served past its TTL.
-- Only a DLP-passed text answer is stored; tool calls, approvals and T1/T2
-- effects have no column here.

CREATE TABLE IF NOT EXISTS cache_entries (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id         text        NOT NULL,
    partition_key     text        NOT NULL,
    prompt_digest     text        NOT NULL,
    prompt_embedding  jsonb,
    embedding_model   text        NOT NULL DEFAULT '',
    answer            text        NOT NULL,
    answer_model      text        NOT NULL DEFAULT '',
    created_at        timestamptz NOT NULL DEFAULT now(),
    expires_at        timestamptz NOT NULL,
    CONSTRAINT cache_entries_ttl CHECK (expires_at > created_at),
    CONSTRAINT cache_entries_key UNIQUE (partition_key, prompt_digest)
);

ALTER TABLE cache_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE cache_entries FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS cache_entries_tenant ON cache_entries;
CREATE POLICY cache_entries_tenant ON cache_entries
    USING (tenant_id = current_setting('app.tenant_id', true))
    WITH CHECK (tenant_id = current_setting('app.tenant_id', true));

CREATE INDEX IF NOT EXISTS cache_entries_partition ON cache_entries (partition_key);
CREATE INDEX IF NOT EXISTS cache_entries_expiry ON cache_entries (expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON cache_entries TO citadel_app;
