-- One run.end per run. A retried finish_run activity must not fork the
-- trajectory, and a forked trajectory would make grading ambiguous.

CREATE UNIQUE INDEX IF NOT EXISTS audit_events_run_end_once
    ON audit_events (tenant_id, (payload->>'run_id'))
    WHERE event_type = 'run.end';
