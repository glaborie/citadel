"""Ingestion: one collection per tenant, content-hash revisions, refuse the rest."""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from qdrant_client import QdrantClient, models

from citadel.retrieval import ingest

DOC_A = "checkout-api restarts when postgres is unreachable.\n\nCheck the network first."
DOC_B = "temporal-ui is a debugging console. Do not restart it during an incident."


def _documents(**by_name: str) -> list[ingest.Document]:
    return [
        ingest.Document(source_uri=f"fs:{name}", content=text) for name, text in by_name.items()
    ]


def _points(client: QdrantClient, tenant: str) -> list[models.Record]:
    return client.scroll(ingest.collection_name(tenant), limit=100, with_payload=True)[0]


def _payload(point: models.Record) -> dict[str, Any]:
    assert point.payload is not None
    return point.payload


def _revisions(client: QdrantClient, tenant: str) -> set[str]:
    return {str(_payload(point)["revision"]) for point in _points(client, tenant)}


def test_one_collection_per_tenant_and_nothing_crosses() -> None:
    """A chunk of lab-a lives in a collection lab-b never names."""
    client = QdrantClient(location=":memory:")

    ingest.ingest(client, tenant="lab-a", documents=_documents(runbook=DOC_A))
    ingest.ingest(client, tenant="lab-b", documents=_documents(handbook=DOC_B))

    assert client.collection_exists("citadel_lab-a")
    assert client.collection_exists("citadel_lab-b")
    a = {_payload(point)["tenant_id"] for point in _points(client, "lab-a")}
    b = {_payload(point)["tenant_id"] for point in _points(client, "lab-b")}
    assert a == {"lab-a"}
    assert b == {"lab-b"}
    assert {_payload(point)["source_uri"] for point in _points(client, "lab-b")} == {"fs:handbook"}


def test_reingesting_an_unchanged_file_stores_nothing_new() -> None:
    client = QdrantClient(location=":memory:")
    documents = _documents(runbook=DOC_A)
    ingest.ingest(client, tenant="lab-a", documents=documents)
    before = _points(client, "lab-a")

    ingest.ingest(client, tenant="lab-a", documents=_documents(runbook=DOC_A))

    after = _points(client, "lab-a")
    assert len(after) == len(before)
    assert {point.id for point in after} == {point.id for point in before}
    assert len(_revisions(client, "lab-a")) == 1


def test_a_changed_file_adds_one_revision_and_keeps_the_old() -> None:
    client = QdrantClient(location=":memory:")
    ingest.ingest(client, tenant="lab-a", documents=_documents(runbook=DOC_A))
    old = _revisions(client, "lab-a")

    ingest.ingest(client, tenant="lab-a", documents=_documents(runbook=DOC_B))

    revisions = _revisions(client, "lab-a")
    assert len(revisions - old) == 1, "one changed file is one new revision"
    assert old <= revisions, "the revision the record already cites must stay readable"


def test_a_link_that_resolves_outside_the_root_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "knowledge"
    root.mkdir()
    (root / "inside.md").write_text("fine")
    outside = tmp_path / "secret.md"
    outside.write_text("not knowledge")
    (root / "escape.md").symlink_to(outside)

    with pytest.raises(ingest.IngestRefused, match="outside the ingest root"):
        list(ingest.filesystem(root))


def test_a_root_outside_the_configured_one_is_refused(tmp_path: Path) -> None:
    configured = tmp_path / "knowledge"
    configured.mkdir()

    with pytest.raises(ingest.IngestRefused, match="outside the configured ingest root"):
        ingest.allowed_root(str(configured), str(tmp_path / "elsewhere"))

    with pytest.raises(ingest.IngestRefused, match="CITADEL_INGEST_ROOT"):
        ingest.allowed_root("", str(configured))


def test_a_repo_not_in_the_configured_set_is_refused() -> None:
    assert ingest.allowed_repos("owner/runbooks,owner/notes", ["owner/runbooks"]) == (
        "owner/runbooks",
    )
    with pytest.raises(ingest.IngestRefused, match="not in CITADEL_INGEST_REPOS"):
        ingest.allowed_repos("owner/runbooks", ["someone-else/secrets"])


def test_a_tenant_that_cannot_name_a_collection_is_refused() -> None:
    with pytest.raises(ingest.IngestRefused):
        ingest.collection_name("../lab-a")
    with pytest.raises(ingest.IngestRefused):
        ingest.collection_name("lab a")


class _Reply:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def _github(payloads: dict[str, dict[str, Any]], seen: list[Any]) -> Callable[..., _Reply]:
    def opener(request: Any, timeout: Any = None) -> _Reply:
        seen.append(request)
        for suffix, payload in payloads.items():
            if request.full_url.endswith(suffix):
                return _Reply(payload)
        raise AssertionError(f"unexpected request {request.full_url}")

    return opener


def test_github_reads_use_the_existing_token_and_the_repo_is_the_source() -> None:
    body = "# Runbook\n\nRestart the api after postgres is reachable."
    seen: list[Any] = []
    payloads: dict[str, dict[str, Any]] = {
        "/git/trees/main?recursive=1": {
            "tree": [{"type": "blob", "path": "runbooks/api.md", "sha": "abc", "size": len(body)}],
            "truncated": False,
        },
        "/git/blobs/abc": {
            "encoding": "base64",
            "content": base64.b64encode(body.encode()).decode(),
        },
    }

    documents = list(
        ingest.github("owner/runbooks", "main", token="ghp_test", opener=_github(payloads, seen))
    )

    assert documents == [
        ingest.Document(source_uri="gh:owner/runbooks@main:runbooks/api.md", content=body)
    ]
    assert seen[0].get_header("Authorization") == "Bearer ghp_test"


def test_github_refuses_without_a_token_and_on_a_truncated_tree() -> None:
    with pytest.raises(ingest.IngestRefused, match="GH_TOKEN"):
        list(ingest.github("owner/runbooks", "main", token=""))

    seen: list[Any] = []
    opener = _github({"/git/trees/main?recursive=1": {"tree": [], "truncated": True}}, seen)
    with pytest.raises(ingest.IngestRefused, match="truncated"):
        list(ingest.github("owner/runbooks", "main", token="t", opener=opener))


def test_the_cli_refuses_a_missing_source(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("CITADEL_INGEST_ROOT", raising=False)

    with pytest.raises(SystemExit) as refused:
        ingest.main(["--tenant", "lab-a"])
    assert refused.value.code == 2
    assert "no source given" in capsys.readouterr().err


def test_the_cli_refuses_a_root_outside_the_configured_one(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CITADEL_INGEST_ROOT", str(tmp_path / "knowledge"))
    (tmp_path / "knowledge").mkdir()

    with pytest.raises(SystemExit) as refused:
        ingest.main(["--tenant", "lab-a", "--root", str(tmp_path / "elsewhere")])
    assert refused.value.code == 2
    assert "outside the configured ingest root" in capsys.readouterr().err


def test_the_cli_refuses_a_repo_outside_the_configured_set(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("CITADEL_INGEST_REPOS", "owner/runbooks")

    with pytest.raises(SystemExit) as refused:
        ingest.main(["--tenant", "lab-a", "--repo", "owner/secrets"])
    assert refused.value.code == 2
    assert "not in CITADEL_INGEST_REPOS" in capsys.readouterr().err


def test_chunks_are_bounded_and_deterministic() -> None:
    text = " ".join(["word"] * 1500)

    pieces = ingest.chunks(text)

    assert all(len(piece) <= ingest.MAX_CHUNK_CHARS for piece in pieces)
    assert " ".join(pieces) == text
    assert ingest.chunks(text) == pieces


def test_the_sparse_vector_counts_terms_and_is_stable() -> None:
    vector = ingest.sparse("restart restart postgres")

    assert len(vector.indices) == 2
    assert sorted(vector.values) == [1.0, 2.0]
    assert vector.indices == ingest.sparse("restart restart postgres").indices
    assert len(set(vector.indices)) == len(vector.indices)
