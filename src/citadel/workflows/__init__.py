"""Workflow and activity registration, plus the per-role worker bootstrap."""

from __future__ import annotations

import os
from typing import Any

from citadel.audit import AuditLedger
from citadel.policy import RelationChecker, RunStore
from citadel.workflows.activities import RunActivities, ToolActivities
from citadel.workflows.model_step import ModelActivities
from citadel.workflows.orchestrator import RunWorkflow
from citadel.workflows.specialist import SpecialistWorkflow


def workflows_for(role: str) -> list[Any]:
    if role == "orchestrator":
        return [RunWorkflow]
    if role in ("docker", "github", "researcher"):
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
        # The orchestrator owns sequencing: it may ask the model for a step and it
        # writes run.end. It never holds a side-effecting tool.
        # Imported here, not at module scope: the Temporal workflow sandbox
        # imports this package too, and qdrant_client cannot load twice.
        from qdrant_client import QdrantClient

        from citadel.cache import AnswerCache, PostgresCacheStore
        from citadel.env import optional_secret
        from citadel.retrieval.activities import RetrievalActivities
        from citadel.retrieval.embed import OmniRouteEmbedder
        from citadel.retrieval.rerank import TeiReranker

        embedder = OmniRouteEmbedder(
            base_url=os.environ.get("OMNIROUTE_URL", "http://omniroute:20128/v1"),
            api_key=optional_secret("OMNIROUTE_API_KEY"),
            model=os.environ.get("CITADEL_EMBEDDING_MODEL", ""),
        )
        run_activities = RunActivities(dsn=dsn, audit=audit)
        model_activities = ModelActivities(
            dsn=dsn,
            audit=audit,
            cache=AnswerCache(
                backend=PostgresCacheStore(dsn),
                embedder=embedder,
                embedding_model=os.environ.get("CITADEL_EMBEDDING_MODEL", ""),
                ttl_seconds=int(os.environ.get("CITADEL_CACHE_TTL_SECONDS", "3600")),
                similarity=float(os.environ.get("CITADEL_CACHE_SIMILARITY", "0.95")),
            ),
        )
        retrieval = RetrievalActivities(
            audit=audit,
            client=QdrantClient(url=os.environ.get("CITADEL_QDRANT_URL", "http://qdrant:6333")),
            embedder=embedder,
            reranker=TeiReranker(os.environ.get("CITADEL_RERANKER_URL", "")),
            analyzer_url=os.environ.get("CITADEL_DLP_URL", "http://presidio:3000"),
        )
        return [
            run_activities.finish_run,
            model_activities.next_step,
            retrieval.retrieve,
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
