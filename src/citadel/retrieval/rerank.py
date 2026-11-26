"""Cross-encoder reranking through the in-stack Text Embeddings Inference service.

The reranker sees only redacted text; the caller applies DLP before this seam.
A missing or malformed answer refuses the query, because quietly returning the
fused order would make the scores in a citation mean something different from
what the schema promises.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any, Protocol
from urllib.error import URLError
from urllib.request import Request

from citadel import net
from citadel.retrieval.errors import RetrievalUnavailable

TIMEOUT: int = 30


class Reranker(Protocol):
    def rerank(
        self, query: str, texts: Sequence[str], *, top_n: int
    ) -> list[tuple[int, float]]: ...


class TeiReranker:
    """TEI's `/rerank`, with client-side validation of what came back."""

    def __init__(self, url: str, *, timeout: int = TIMEOUT, opener: Any = None) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._opener = opener

    def rerank(self, query: str, texts: Sequence[str], *, top_n: int) -> list[tuple[int, float]]:
        if not self.url:
            raise RetrievalUnavailable("CITADEL_RERANKER_URL is not set")
        if not texts:
            return []
        request = Request(
            f"{self.url}/rerank",
            data=json.dumps(
                {"query": query, "texts": list(texts), "truncate": True, "top_n": top_n}
            ).encode(),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with net.open_url(request, timeout=self.timeout, opener=self._opener) as response:
                body = json.loads(response.read())
        except (URLError, OSError, ValueError) as exc:
            raise RetrievalUnavailable(f"reranker failed: {exc}") from exc
        return _scores(body, count=len(texts), top_n=top_n)


def _scores(body: Any, *, count: int, top_n: int) -> list[tuple[int, float]]:  # noqa: ANN401
    if not isinstance(body, list):
        raise RetrievalUnavailable("reranker returned a malformed response")
    ranked: list[tuple[int, float]] = []
    seen: set[int] = set()
    for item in body:
        if not isinstance(item, dict):
            raise RetrievalUnavailable("reranker returned a malformed item")
        index, score = item.get("index"), item.get("score")
        if (
            not isinstance(index, int)
            or isinstance(index, bool)
            or not isinstance(score, (int, float))
        ):
            raise RetrievalUnavailable("reranker returned an item without index and score")
        if not 0 <= index < count or index in seen:
            raise RetrievalUnavailable("reranker returned an index outside the candidates")
        seen.add(index)
        ranked.append((index, float(score)))
    if not ranked:
        raise RetrievalUnavailable("reranker returned no scores")
    return ranked[:top_n]
