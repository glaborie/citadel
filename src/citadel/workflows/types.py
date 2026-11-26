"""Serialisable payloads shared by workflows and activities.

Temporal moves these across process boundaries, so they must stay plain
dataclasses with JSON-friendly fields.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

TASK_QUEUES = {
    "orchestrator": "orchestrator",
    "docker": "docker",
    "github": "github",
    "researcher": "researcher",
}

# Seconds. Deployment-wide: the console, the API and the workflow must agree.
APPROVAL_TTL = int(os.environ.get("CITADEL_APPROVAL_TTL_SECONDS", "300"))
MAX_ATTEMPTS = 3


@dataclass
class ToolCall:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    approval_ref: str | None = None
    # The API-minted run token the sandbox verifies. Identity comes from it, so
    # the body's agent string is a claim the runner checks, never trusts.
    run_token: str = ""


@dataclass
class PolicyOutcome:
    outcome: str  # allow | requires_approval | deny
    rule_id: str
    reason: str
    tier: str


@dataclass
class ApprovalDecision:
    approved: bool
    approver: str
    reason: str
    # The audit event id of the decision, not a credential: the operator
    # resolves it server-side and consumes it once.
    approval_ref: str | None = None


@dataclass
class ToolResult:
    status: str  # executed | denied | failed | replayed
    tool: str
    rule_id: str
    detail: str
    idempotency_key: str = ""
    replayed: bool = False
    output: dict[str, Any] = field(default_factory=dict)
    # The digest of the output as the tool service returned it, before this
    # process capped it for the record.
    output_sha256: str = ""
    output_bytes: int = 0
    output_truncated: bool = False
    # Digest of the stream the record could not carry in full; the body is in
    # tool_outputs when output_stored is true.
    output_ref: str = ""
    output_stored: bool = False
    # Content labels the payload itself carries (untrusted_external,
    # prompt_injection). `run.end.safety_flags` copies them, so the label is in
    # the trajectory and not only in the text the model read.
    content_flags: list[str] = field(default_factory=list)


@dataclass
class RunInput:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    # A task run carries its instruction here instead of naming a tool; the
    # orchestrator then loops until the model answers or the budget runs out.
    task: str = ""
    model_alias: str = ""
    prompt_pack_version: str = ""
    max_steps: int = 3
    # Minted by the API at POST /runs. Every sandbox call re-presents it, so a
    # workload on the internal network cannot act as an agent it has no token for.
    run_token: str = ""


@dataclass
class RunEnd:
    run_id: str
    tenant_id: str
    outcome: str
    citation_ids: list[str] = field(default_factory=list)
    safety_flags: list[str] = field(default_factory=list)
    # The model's gated answer, bounded. A submitted run has no other surface a
    # person can read, and `run.end` is already the event they look at.
    answer: str = ""
