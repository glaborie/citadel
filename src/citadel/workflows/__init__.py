"""Workflow and activity registration, plus the per-role worker bootstrap."""

from __future__ import annotations

import os
from typing import Any

from citadel.audit import AuditLedger
from citadel.policy import RelationChecker, RunStore
from citadel.workflows.activities import ModelActivities, RunActivities, ToolActivities
from citadel.workflows.orchestrator import RunWorkflow
from citadel.workflows.specialist import SpecialistWorkflow


def workflows_for(role: str) -> list[Any]:
    if role == "orchestrator":
        return [RunWorkflow]
    if role in ("docker", "github"):
        return [SpecialistWorkflow]
    raise ValueError(f"unknown worker role {role!r}")


def activities_for(
    role: str,
    *,
    dsn: str,
    checker: RelationChecker | None = None,
    run_store: RunStore | None = None,
    runner_url: str = "",
    operator_url: str = "",
) -> list[Any]:
    audit = AuditLedger(dsn)
    if role == "orchestrator":
        run_activities = RunActivities(dsn=dsn, audit=audit)
        model_activities = ModelActivities(
            dsn=dsn,
            audit=audit,
            gateway_url=os.environ.get("OMNIROUTE_URL", ""),
            api_key=os.environ.get("OMNIROUTE_API_KEY", ""),
            analyzer_url=os.environ.get("CITADEL_DLP_URL", "http://presidio:3000"),
            default_alias=os.environ.get("MODEL_ALIAS_FAST", "auto/best-fast"),
        )
        return [
            run_activities.finish_run,
            model_activities.system_prompt,
            model_activities.tools,
            model_activities.complete,
            model_activities.gate,
        ]
    if checker is None or run_store is None:
        raise ValueError(f"{role} activities need a policy checker and run store")
    impl = ToolActivities(
        checker=checker,
        run_store=run_store,
        dsn=dsn,
        runner_url=runner_url,
        operator_url=operator_url,
        audit=audit,
    )
    return [impl.authorize_tool, impl.execute_tool]


def temporal_address() -> str:
    return os.environ.get("TEMPORAL_ADDRESS", "temporal:7233")


def namespace() -> str:
    return os.environ.get("TEMPORAL_NAMESPACE", "default")
