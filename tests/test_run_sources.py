"""The answer's footnotes reach the trace, and stop at the ledger.

`citation_ids` in a trace are Qdrant point ids. A reader could not tell that three of them were
three chunks of one runbook - or which runbook. The root span now carries the document next to
each id; the ledger keeps its own shape, which `evals/schema.py` pins.
"""

from __future__ import annotations

from citadel.workflows.activities import _run_outputs
from citadel.workflows.orchestrator import _cited_documents
from citadel.workflows.types import RunEnd

CITED = [
    {
        "chunk_id": "8506d70c-59d5-5c43-baf3-3d7d895f7ff3",
        "source_uri": "fs:live-run-183.md",
        "revision": "082935f76dbfdce0384d45211dbfabe9b902296aa195a530cfb6261304e485f0",
        "score": 0.72,
    }
]


def test_the_root_output_names_the_document_next_to_the_id() -> None:
    end = RunEnd(
        run_id="run-1",
        tenant_id="lab-a",
        outcome="completed",
        answer="citadel-api-1 is running",
        citation_ids=["8506d70c-59d5-5c43-baf3-3d7d895f7ff3"],
        sources=_cited_documents(CITED),
    )

    outputs = _run_outputs(end)

    assert outputs["answer"] == "citadel-api-1 is running"
    assert outputs["citation_ids"] == ["8506d70c-59d5-5c43-baf3-3d7d895f7ff3"]
    assert outputs["sources"][0]["source_uri"] == "fs:live-run-183.md"
    assert outputs["sources"][0]["revision"] == "082935f76dbf"
    assert outputs["sources"][0]["score"] == 0.72


def test_a_run_without_retrieval_says_so_with_an_empty_list() -> None:
    end = RunEnd(run_id="run-1", tenant_id="lab-a", outcome="denied", answer="")

    outputs = _run_outputs(end)

    assert outputs["sources"] == []
    assert outputs["citation_ids"] == []


def test_the_orchestrator_normalises_whatever_the_activity_returned() -> None:
    assert _cited_documents("not a list") == []
    assert _cited_documents([{**CITED[0], "text": "secret prose"}])[0] == {
        "id": "8506d70c-59d5-5c43-baf3-3d7d895f7ff3",
        "source_uri": "fs:live-run-183.md",
        "revision": "082935f76dbf",
        "score": 0.72,
    }
