"""The retrieval producer: one activity writes both `retrieval.*` events.

The query event is written before the search and carries the filter-set digest,
never the query text. The result event carries citation metadata and scores,
never a chunk body. Both are ordinary audit rows, so the recorder exports them
like every other span.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from temporalio import activity

from citadel import dlp
from citadel.audit import AuditLedger
from citadel.retrieval.embed import Embedder
from citadel.retrieval.errors import QueryRefused, RetrievalUnavailable
from citadel.retrieval.ingest import collection_name
from citadel.retrieval.query import (
    Entitlements,
    Results,
    SearchRequest,
    query_digest,
    search,
)
from citadel.retrieval.rerank import Reranker
from citadel.retrieval.types import RetrievalOutcome, RetrievalRequest
from citadel.telemetry import record_span


def _entitlements(request: RetrievalRequest) -> Entitlements:
    """The caller's tag set when it named one, else the tenant's own set."""
    if request.entitlements:
        return Entitlements(tags=tuple(sorted(set(request.entitlements))))
    return Entitlements.for_tenant(request.tenant_id)


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
        ref = self._audit.append(
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
        record_span(
            "retrieval.result",
            run_id=request.run_id,
            audit_id=ref.audit_id,
            status=status,
            cited=str(len(results.citations)),
            sources=self._sources(results.citations),
        )

    @staticmethod
    def _sources(citations: Sequence[Mapping[str, Any]]) -> str:
        """What was cited, as a reader can use it: document, revision, score.

        The row's `citation_ids` are Qdrant point ids - storage, not evidence. A reviewer
        reading a trace could not tell that three opaque ids were three chunks of one
        runbook, nor which runbook. This is the same fact the ledger already keeps in
        `source_uris`, put where the trace can show it.
        """
        return json.dumps(
            [
                {
                    "id": str(item.get("chunk_id", "")),
                    "source_uri": str(item.get("source_uri", "")),
                    "revision": str(item.get("revision", ""))[:12],
                    "score": item.get("score"),
                }
                for item in citations
            ],
            sort_keys=True,
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
            entitlements = _entitlements(request)
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
