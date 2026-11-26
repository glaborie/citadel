"""Dense embeddings through OmniRoute's OpenAI-compatible endpoint.

No model name is invented here: the alias is configuration, because which
provider sees the text is the open decision in #136. An empty alias is an
unavailable endpoint, not a reason to store a chunk no query can find.
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


class Embedder(Protocol):
    def embed(self, texts: Sequence[str]) -> list[list[float]]: ...


class OmniRouteEmbedder:
    """`/v1/embeddings` on the same gateway the model path already uses."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout: int = TIMEOUT,
        opener: Any = None,
    ) -> None:
        # OMNIROUTE_URL is documented as the OpenAI base; accept both forms.
        trimmed = base_url.rstrip("/")
        if trimmed.endswith("/v1"):
            trimmed = trimmed[: -len("/v1")]
        self.base_url = trimmed
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self._opener = opener

    def embed(self, texts: Sequence[str]) -> list[list[float]]:
        if not texts:
            return []
        if not self.model:
            raise RetrievalUnavailable("CITADEL_EMBEDDING_MODEL is not set")
        request = Request(
            f"{self.base_url}/v1/embeddings",
            data=json.dumps({"model": self.model, "input": list(texts)}).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with net.open_url(request, timeout=self.timeout, opener=self._opener) as response:
                body = json.loads(response.read())
        except (URLError, OSError, ValueError) as exc:
            raise RetrievalUnavailable(f"embedding endpoint failed: {exc}") from exc
        return _vectors(body, expected=len(texts))


def _item(item: Any) -> tuple[int, list[float]]:  # noqa: ANN401 - JSON
    if not isinstance(item, dict) or not isinstance(item.get("index"), int):
        raise RetrievalUnavailable("embedding endpoint returned a malformed item")
    vector = item.get("embedding")
    if not isinstance(vector, list) or not vector:
        raise RetrievalUnavailable("embedding endpoint returned an empty vector")
    return item["index"], [float(value) for value in vector]


def _vectors(body: Any, *, expected: int) -> list[list[float]]:  # noqa: ANN401 - JSON
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, list) or len(data) != expected:
        raise RetrievalUnavailable("embedding endpoint returned the wrong number of vectors")
    ordered = sorted(_item(item) for item in data)
    if [index for index, _ in ordered] != list(range(expected)):
        raise RetrievalUnavailable("embedding endpoint returned duplicate or missing indices")
    return [vector for _, vector in ordered]
