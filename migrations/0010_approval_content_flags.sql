-- The taint the run carried when it asked for the write.
--
-- The orchestrator accumulates the content flags of every earlier observation
-- and puts them on the ToolCall it delegates (ADR-028). The pending row keeps
-- them, so the console can show the approver what the run has read and the
-- API can refuse an agent approver for a call flagged prompt_injection. The
-- default covers rows written before the column existed.

ALTER TABLE approval_requests
    ADD COLUMN IF NOT EXISTS content_flags jsonb NOT NULL DEFAULT '[]'::jsonb;
