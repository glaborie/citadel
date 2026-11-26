"""The web services are reachable by the researcher and by nobody else.

`web` is the internet-facing network; `research` is the internal one the worker
shares with the two services. Neither service publishes a port, and neither
joins `edge`, which the host-reachable services share. The guard is fed a
published service to prove it can fail.
"""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE = Path(__file__).resolve().parents[1] / "compose.yaml"
DOCKERFILE = Path(__file__).resolve().parents[1] / "Dockerfile"


def service_block(compose: str, name: str) -> str:
    lines = compose.splitlines()
    for index, line in enumerate(lines):
        if line == f"  {name}:":
            block: list[str] = []
            for following in lines[index + 1 :]:
                if following[:2] == "  " and following[:4] != "    " and following.strip():
                    break
                block.append(following)
            return "\n".join(block)
    raise AssertionError(f"service {name!r} not found in compose.yaml")


def networks(block: str) -> list[str]:
    found = re.search(r"^    networks:\n((?:      (?:#.*|- \S+)(?:\n|$))+)", block, re.MULTILINE)
    assert found is not None, "the service must declare its networks explicitly"
    return re.findall(r"- (\S+)", found.group(1))


def test_the_web_services_publish_nothing_and_join_no_edge() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    for name in ("searxng", "fetcher"):
        block = service_block(compose, name)
        assert "ports:" not in block, f"{name} must not be published on the host"
        joined = networks(block)
        assert "research" in joined, f"{name} must be reachable by the researcher"
        assert "web" in joined, f"{name} needs the internet-facing network"
        assert "edge" not in joined, f"{name} must not join the shared edge network"


def test_the_researcher_worker_reaches_research_but_not_the_web() -> None:
    block = service_block(COMPOSE.read_text(encoding="utf-8"), "worker-researcher")
    assert "ports:" not in block
    joined = networks(block)
    assert joined == ["internal", "research"], joined


def test_searxng_is_pinned_by_digest_and_the_fetcher_by_build_target() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    assert re.search(
        r"searxng/searxng:\S+@sha256:[0-9a-f]{64}", service_block(compose, "searxng")
    ), "SearXNG must be pinned by tag and digest"
    assert "target: fetcher" in service_block(compose, "fetcher")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "--extra fetcher" in dockerfile, "trafilatura belongs only in the fetcher image"
    assert "citadel.research.service:app" in dockerfile


def test_the_guard_notices_a_published_service() -> None:
    published = """\
services:
  searxng:
    image: example
    ports:
      - "8080:8080"
    networks:
      - research
      - edge
"""
    block = service_block(published, "searxng")
    assert "ports:" in block
    assert "edge" in networks(block)
