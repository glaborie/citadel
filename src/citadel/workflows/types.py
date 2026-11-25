"""Serialisable payloads shared by workflows and activities.

Temporal moves these across process boundaries, so they must stay plain
dataclasses with JSON-friendly fields.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

TASK_QUEUES = {"orchestrator": "orchestrator", "docker": "docker", "github": "github"}

APPROVAL_TTL = 15 * 60  # seconds; docs/security/tool-tiers.md
MAX_ATTEMPTS = 3


@dataclass
class ToolCall:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)
    approval_token: str | None = None


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
    token: str | None = None


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


@dataclass
class RunInput:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    tool: str
    arguments: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunEnd:
    run_id: str
    tenant_id: str
    outcome: str
    citation_ids: list[str] = field(default_factory=list)
    safety_flags: list[str] = field(default_factory=list)
