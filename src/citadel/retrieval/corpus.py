"""Keeping a tenant's index equal to its corpus.

Upsert alone makes ingest idempotent in content and additive in membership: a document deleted
from `knowledge/` keeps its chunks and keeps being served as evidence. These three functions are
the missing half - what is indexed, what should be, and the difference.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

from qdrant_client import models

FS_PREFIX: Final = "fs:"


def stale_sources(indexed: Iterable[str], corpus: Iterable[str]) -> list[str]:
    """Sources in the index that this corpus no longer contains.

    A corpus is a set; an index built by upsert alone is a union. `knowledge/live-run-183.md`
    was ingested, deleted, and then served for two nights as evidence for a host that has no
    `checkout-api` - idempotent upsert keeps content honest and membership wrong.

    Only filesystem sources are considered. A repository-backed source is the responsibility of
    the repository run that owns it, and deleting it because a directory walk did not see it
    would turn a partial run into data loss.
    """
    present = set(corpus)
    return sorted({uri for uri in indexed if uri.startswith(FS_PREFIX) and uri not in present})


def indexed_sources(client: Any, collection: str) -> list[str]:  # noqa: ANN401 - QdrantClient
    """Every `source_uri` in the collection, read without vectors."""
    seen: set[str] = set()
    offset: Any = None
    while True:
        points, offset = client.scroll(
            collection_name=collection,
            limit=256,
            offset=offset,
            with_payload=True,
            with_vectors=False,
        )
        for point in points:
            uri = (point.payload or {}).get("source_uri")
            if isinstance(uri, str) and uri:
                seen.add(uri)
        if offset is None:
            return sorted(seen)


def prune_sources(client: Any, collection: str, sources: Iterable[str]) -> int:  # noqa: ANN401
    """Delete every chunk of the given sources. Returns the number of sources removed."""
    removed = 0
    for uri in sources:
        selector = models.Filter(
            must=[models.FieldCondition(key="source_uri", match=models.MatchValue(value=uri))]
        )
        client.delete(collection_name=collection, points_selector=selector, wait=True)
        print(f"  pruned {uri}")
        removed += 1
    return removed
