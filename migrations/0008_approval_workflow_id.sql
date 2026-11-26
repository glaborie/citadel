-- The exact child workflow a pending T1 call parked in.
--
-- The id includes the task-run step, so it cannot be rebuilt from run_id and
-- tool: the specialist records its own runtime id and the API signals that.

ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS workflow_id text NOT NULL DEFAULT '';
