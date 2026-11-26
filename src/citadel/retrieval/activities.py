"""The retrieval producer: one activity writes both `retrieval.*` events.

The query event is written before the search and carries the filter-set digest,
never the query text. The result event carries citation metadata and scores,
never a chunk body. Both are ordinary audit rows, so the recorder exports them
like every other span.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from temporalio import activity

from citadel import dlp
from citadel.audit import AuditLedger
from citadel.retrieval.embed import Embedder
from citadel.retrieval.errors import QueryRefused, RetrievalUnavailable
from citadel.retrieval.ingest import collection_name
from citadel.retrieval.query import (
    CANDIDATES,
    TOP_K,
    Entitlements,
    Results,
    SearchRequest,
    query_digest,
    search,
)
from citadel.retrieval.rerank import Reranker
from citadel.telemetry import record_span


@dataclass(frozen=True)
class RetrievalRequest:
    run_id: str
    tenant_id: str
    user_id: str
    agent_id: str
    query: str
    top_k: int = TOP_K
    candidates: int = CANDIDATES


@dataclass(frozen=True)
class RetrievalOutcome:
    status: str  # answered | refused
    rule_id: str
    detail: str
    filter_set_hash: str = ""
    citations: list[dict[str, Any]] = field(default_factory=list)
    chunks: list[dict[str, Any]] = field(default_factory=list)


class RetrievalActivities:
    def __init__(
        self,
        *,
        audit: AuditLedger,
        client: Any,  # noqa: ANN401 - the QdrantClient seam, replaced in tests
        embedder: Embedder,
        reranker: Reranker,
        analyzer_url: str,
    ) -> None:
        self._audit = audit
        self._client = client
        self._embedder = embedder
        self._reranker = reranker
        self._analyzer_url = analyzer_url

    def _audit_dlp(self, request: RetrievalRequest, report: dict[str, Any]) -> None:
        categories = report.get("categories")
        ref = self._audit.append(
            tenant_id=request.tenant_id,
            event_type="dlp.event",
            actor_type="agent",
            actor_id=request.agent_id,
            payload={
                "run_id": request.run_id,
                "surface": "output",
                "categories": categories if isinstance(categories, list) else [],
                "action": report.get("action", "pass"),
                "detector_version": report.get("detector_version", ""),
                "tool": "retrieval",
            },
        )
        record_span(
            "dlp.event",
            run_id=request.run_id,
            audit_id=ref.audit_id,
            surface="output",
            action=str(report.get("action", "pass")),
        )

    def _redact(self, request: RetrievalRequest, text: str) -> str:
        try:
            clean, report = dlp.gate(text, surface="output", analyzer_url=self._analyzer_url)
        except dlp.DlpBlocked as exc:
            self._audit_dlp(request, exc.report)
            raise
        if report.get("action") != "pass":
            self._audit_dlp(request, report)
        return clean

    def _query_event(self, request: RetrievalRequest, entitlements: Entitlements) -> None:
        ref = self._audit.append(
            tenant_id=request.tenant_id,
            event_type="retrieval.query",
            actor_type="agent",
            actor_id=request.agent_id,
            payload={
                "run_id": request.run_id,
                "tenant_id": request.tenant_id,
                "filter_set_hash": entitlements.filter_set_hash,
                "top_k": request.top_k,
                "candidate_k": request.candidates,
                "collection": collection_name(request.tenant_id),
                "query_digest": query_digest(request.query),
            },
        )
        record_span(
            "retrieval.query",
            run_id=request.run_id,
            audit_id=ref.audit_id,
            filter_set_hash=entitlements.filter_set_hash,
            top_k=str(request.top_k),
        )

    def _result_event(self, request: RetrievalRequest, results: Results, status: str) -> None:
        self._audit.append(
            tenant_id=request.tenant_id,
            event_type="retrieval.result",
            actor_type="agent",
            actor_id=request.agent_id,
            payload={
                "run_id": request.run_id,
                "status": status,
                "chunk_ids": [item["chunk_id"] for item in results.citations],
                "source_uris": [item["source_uri"] for item in results.citations],
                "revisions": [item["revision"] for item in results.citations],
                "scores": [item["score"] for item in results.citations],
            },
        )

    @staticmethod
    def _identity_refusal(request: RetrievalRequest) -> RetrievalOutcome | None:
        if all(
            value.strip()
            for value in (request.run_id, request.tenant_id, request.user_id, request.agent_id)
        ):
            return None
        return RetrievalOutcome(
            status="refused",
            rule_id="retrieval.missing_identity",
            detail="a retrieval request needs a run, tenant, user and agent",
        )

    def _search(self, request: RetrievalRequest, entitlements: Entitlements) -> Results:
        return search(
            self._client,
            SearchRequest(
                tenant_id=request.tenant_id,
                query=request.query,
                top_k=request.top_k,
                candidates=request.candidates,
                entitlements=entitlements,
            ),
            self._embedder,
            self._reranker,
            redact=lambda text: self._redact(request, text),
        )

    @activity.defn
    def retrieve(self, request: RetrievalRequest) -> RetrievalOutcome:
        refused = self._identity_refusal(request)
        if refused is not None:
            return refused
        try:
            entitlements = Entitlements.for_tenant(request.tenant_id)
        except QueryRefused as exc:
            return RetrievalOutcome(
                status="refused", rule_id="retrieval.invalid_tenant", detail=str(exc)
            )

        self._query_event(request, entitlements)
        try:
            found = self._search(request, entitlements)
        except (QueryRefused, RetrievalUnavailable, dlp.DlpBlocked) as exc:
            self._result_event(request, _empty(request), status="refused")
            return RetrievalOutcome(
                status="refused",
                rule_id="retrieval.refused",
                detail=str(exc)[:300],
                filter_set_hash=entitlements.filter_set_hash,
            )

        self._result_event(request, found, status="answered")
        return _answered(found)


def _empty(request: RetrievalRequest) -> Results:
    """A refusal still exports a result event; it carries no hit."""
    return Results(
        query_digest=query_digest(request.query),
        collection=collection_name(request.tenant_id),
        filter_set_hash="",
        top_k=request.top_k,
        chunks=(),
    )


def _answered(found: Results) -> RetrievalOutcome:
    return RetrievalOutcome(
        status="answered",
        rule_id="retrieval.answered",
        detail=f"{len(found.chunks)} chunks passed the ACL filter and reranker",
        filter_set_hash=found.filter_set_hash,
        citations=found.citations,
        chunks=[
            {
                "chunk_id": chunk.citation.chunk_id,
                "source_uri": chunk.citation.source_uri,
                "revision": chunk.citation.revision,
                "score": chunk.citation.score,
                "text": chunk.text,
            }
            for chunk in found.chunks
        ],
    )
