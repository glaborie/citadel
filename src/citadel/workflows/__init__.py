"""Workflow and activity registration, plus the per-role worker bootstrap."""

from __future__ import annotations

import os
from typing import Any

from citadel.policy import RelationChecker, RunStore
from citadel.workflows.activities import ToolActivities
from citadel.workflows.orchestrator import RunWorkflow
from citadel.workflows.specialist import SpecialistWorkflow


def workflows_for(role: str) -> list[Any]:
    if role == "orchestrator":
        return [RunWorkflow]
    if role in ("docker", "github"):
        return [SpecialistWorkflow]
    raise ValueError(f"unknown worker role {role!r}")


def activities_for(
    role: str, *, checker: RelationChecker, run_store: RunStore, dsn: str, runner_url: str
) -> list[Any]:
    if role == "orchestrator":
        return []
    impl = ToolActivities(checker=checker, run_store=run_store, dsn=dsn, runner_url=runner_url)
    return [impl.authorize_tool, impl.execute_tool]


def temporal_address() -> str:
    return os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")


def namespace() -> str:
    return os.environ.get("TEMPORAL_NAMESPACE", "default")
