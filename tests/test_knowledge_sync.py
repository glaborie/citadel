"""The corpus and the index have to be the same set.

`ingest` upserts, which makes it idempotent in content and additive in membership: a document
deleted from `knowledge/` keeps its chunks and keeps being served. That is how a checkout-api
runbook became evidence about a host with no checkout-api.
"""

from __future__ import annotations

import importlib.util
import pathlib
from types import ModuleType

import pytest

from citadel.retrieval.ingest import stale_sources

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "knowledge-sync.py"


def _sync() -> ModuleType:
    spec = importlib.util.spec_from_file_location("knowledge_sync", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PS = """citadel-api-1|Up 18 minutes (healthy)
citadel-worker-docker-1|Up 18 minutes (healthy)
bastion-db|Up 27 hours (healthy)
freellmapi-freellmapi-1|Up 27 hours (healthy)
citadel-mlflow-ui|Up 4 hours
"""


def test_a_running_document_names_one_container_and_its_state() -> None:
    rows = _sync().containers(PS)

    assert rows[0] == ("citadel-api-1", "Up 18 minutes (healthy)")
    assert len(rows) == 5


def test_three_projects_share_the_daemon_so_the_document_groups_them() -> None:
    sync = _sync()
    document = sync.render(sync.containers(PS), "2026-11-27T15:00:00+00:00", "docker ps")

    assert "5 containers across 3 projects" in document
    # three project sections, plus provenance
    assert document.count("\n## ") == 4
    assert "## bastion" in document and "## citadel" in document
    assert "`citadel-api-1` - Up 18 minutes (healthy)" in document


def test_the_document_says_when_it_was_generated_and_how_to_refresh_it() -> None:
    sync = _sync()
    document = sync.render(sync.containers(PS), "2026-11-27T15:00:00+00:00", "docker ps")

    assert "generated: 2026-11-27T15:00:00+00:00" in document
    assert "make knowledge-sync" in document


def test_each_project_section_can_stand_alone() -> None:
    """Chunks are paragraphs: a section has to survive being retrieved without its neighbour."""
    sync = _sync()
    document = sync.render(sync.containers(PS), "now", "docker ps")

    project_sections = [
        part for part in document.split("\n## ")[1:] if not part.startswith("Provenance")
    ]
    assert len(project_sections) == 3
    for section in project_sections:
        assert "containers." in section, "a section must state its own count"
        assert "- `" in section, "a section must list its own names"


@pytest.mark.parametrize(
    ("indexed", "corpus", "expected"),
    [
        (["fs:a.md", "fs:b.md"], ["fs:a.md"], ["fs:b.md"]),
        (["fs:a.md"], ["fs:a.md"], []),
        ([], ["fs:a.md"], []),
        (["fs:a.md"], [], ["fs:a.md"]),
    ],
)
def test_the_prune_is_a_set_difference(
    indexed: list[str], corpus: list[str], expected: list[str]
) -> None:
    assert stale_sources(indexed, corpus) == expected


def test_a_repository_source_is_never_pruned_by_a_directory_walk() -> None:
    """Only `fs:` is this run's business; a repo source belongs to the run that owns it."""
    assert stale_sources(["gh:owner/repo@HEAD:README.md", "fs:gone.md"], ["fs:kept.md"]) == [
        "fs:gone.md"
    ]


def test_the_script_is_executable() -> None:
    assert SCRIPT.stat().st_mode & 0o111
