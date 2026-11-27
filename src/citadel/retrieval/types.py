"""Retrieval payloads shared by the activity and the workflow that calls it.

Plain dataclasses with no Qdrant, HTTP or audit imports: the Temporal workflow
sandbox imports this module to build the request and read the outcome, so it must
not drag the activity's clients in with it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Architecture §6: rerank top 50 to top 8. Kept here so the workflow sandbox can
# import the request defaults without importing the Qdrant query module.
CANDIDATES: int = 50
TOP_K: int = 8


@dataclass(frozen=True)
class RetrievalRequest:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    query: str
    top_k: int = TOP_K
    candidates: int = CANDIDATES
    # The ACL tags the run holds, as full tags (`tenant:lab-a`, `doc:...`). The
    # activity refuses a set without this tenant's tag; empty means the tenant's
    # own set, which is what a run without document scoping holds.
    entitlements: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class RetrievalOutcome:
    status: str  # answered | refused
    rule_id: str
    detail: str
    filter_set_hash: str = ""
    citations: list[dict[str, Any]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)
