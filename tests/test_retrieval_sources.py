"""What a citation looks like to a reader, not to a store.

A run's `citation_ids` are Qdrant point ids. Three of them, in one real trace, were three
chunks of a single runbook - and nothing in the trace said so. The span carries the document
now; these tests hold that shape and hold that it carries no chunk text.
"""

from __future__ import annotations

import json

from citadel.retrieval.activities import RetrievalActivities

CITED = [
    {
        "chunk_id": "8506d70c-59d5-5c43-baf3-3d7d895f7ff3",
        "source_uri": "fs:live-run-183.md",
        "revision": "082935f76dbfdce0384d45211dbfabe9b902296aa195a530cfb6261304e485f0",
        "score": 0.72,
    },
    {
        "chunk_id": "4e6203e1-212e-5767-97c0-ca5a4c8cbc76",
        "source_uri": "fs:live-run-183.md",
        "revision": "082935f76dbfdce0384d45211dbfabe9b902296aa195a530cfb6261304e485f0",
        "score": 0.31,
    },
]


def test_the_payload_names_the_document_behind_every_id() -> None:
    payload = json.loads(RetrievalActivities._sources(CITED))

    assert [item["source_uri"] for item in payload] == ["fs:live-run-183.md"] * 2
    assert payload[0]["id"] == "8506d70c-59d5-5c43-baf3-3d7d895f7ff3"
    assert payload[1]["score"] == 0.31
    assert payload[0]["revision"] == "082935f76dbf", "a digest is enough to match a re-ingest"


def test_the_payload_carries_no_chunk_text() -> None:
    """Text is the answer's business and `CITADEL_TRACE_CONTENT`'s decision, not this one's."""
    cited = [dict(CITED[0], text="checkout-api runs on the payments host.")]

    payload = RetrievalActivities._sources(cited)

    assert "payments host" not in payload
    assert set(json.loads(payload)[0]) == {"id", "revision", "score", "source_uri"}


def test_an_empty_retrieval_is_an_empty_list_not_a_null() -> None:
    assert json.loads(RetrievalActivities._sources([])) == []
