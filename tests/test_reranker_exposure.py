"""Issue #148: the reranker is internal-only and its model is pinned.

The model now ships inside the image, so the service needs no egress and no
model volume. If someone repoints it at the mutable Hub name, this guard and
the Dockerfile's pinned revision are the two places that should fail.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_PATH = ROOT / "compose.yaml"
DOCKERFILE_PATH = ROOT / "docker" / "reranker.Dockerfile"


def _service_block(compose: str, name: str) -> str:
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


def test_reranker_is_not_published_and_stays_internal_only() -> None:
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "reranker")
    assert "ports:" not in block, "the reranker serves the workers from inside Compose only"
    networks = re.search(r"^    networks:\n((?:      - \S+\n)+)", block, re.MULTILINE)
    assert networks is not None, "reranker must declare its networks explicitly"
    assert re.findall(r"- (\S+)", networks.group(1)) == ["internal"], (
        "the reranker must stay internal-only: the model is baked in, so it "
        "needs no egress and no model volume."
    )
    assert "volumes:" not in block, "a model volume means a runtime fetch can come back"


def test_reranker_model_is_baked_at_a_pinned_revision() -> None:
    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert re.search(r"^ARG MODEL_REVISION=[0-9a-f]{40}$", dockerfile, re.MULTILINE), (
        "pin the model revision to a commit id, never a branch"
    )
    assert "/resolve/${MODEL_REVISION}/" in dockerfile, "fetch by the pinned revision"


def test_reranker_runs_unprivileged_with_dropped_capabilities() -> None:
    """Issue #227: root with the default capability set on the network that
    holds postgres, qdrant, openfga and mlflow was the worst starting
    position if TEI's request parsing had a memory-safety bug."""
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "reranker")
    assert 'user: "10001:10001"' in block, "the reranker must not run as root"
    assert re.search(r"^    cap_drop:\n      - ALL$", block, re.MULTILINE), (
        "no capability may survive: the service reads a local model and serves HTTP"
    )
    assert "- no-new-privileges:true" in block, "no path to new privileges"
    assert "read_only: true" in block, "the image is complete at build; runtime writes nothing"
    assert re.search(r"^    tmpfs:\n      - /tmp$", block, re.MULTILINE), (
        "read_only needs a writable /tmp (TEI's cache and any temp files)"
    )
    assert re.search(r"^    pids_limit: \d+$", block, re.MULTILINE), "a pid ceiling is required"
    assert re.search(r"^    mem_limit: \d+m$", block, re.MULTILINE), "a memory ceiling is required"

    dockerfile = DOCKERFILE_PATH.read_text(encoding="utf-8")
    assert re.search(r"^USER 10001:10001$", dockerfile, re.MULTILINE), (
        "the Dockerfile itself must drop root (trivy DS-0002), not only compose"
    )


def test_reranker_memory_limit_covers_the_measured_warmup() -> None:
    """Issue #269: warmup peaked at 1365 MiB (cgroup `memory.peak`), so the
    1024m ceiling that preceded it killed the server before it served, and
    nothing depended on its health, so the loss was silent. The floor keeps a
    future edit from walking the value back under the measurement."""
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "reranker")
    limit = re.search(r"^    mem_limit: (\d+)m$", block, re.MULTILINE)
    assert limit is not None, "the reranker must declare a memory ceiling in MiB"
    assert int(limit.group(1)) >= 1536, (
        "warmup needs 1365 MiB; 1024m OOM-kills it before it serves (issue #269)"
    )


def test_reranker_serves_on_an_unprivileged_port_everywhere() -> None:
    """TEI's default port 80 needs CAP_NET_BIND_SERVICE, which a
    capability-dropped user cannot hold. Port, healthcheck, compose caller and
    .env.example must all agree, or the retrieval path silently breaks."""
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "reranker")
    port = re.search(r'"--port", "(\d+)"', block)
    assert port is not None, "the command must name the port explicitly"
    assert int(port.group(1)) > 1024, "the port must not need a capability to bind"
    assert f"/dev/tcp/127.0.0.1/{port.group(1)}" in block, (
        "the healthcheck must probe the port TEI actually serves"
    )

    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    assert f"CITADEL_RERANKER_URL: http://reranker:{port.group(1)}" in compose, (
        "the orchestrator worker's URL must match the served port"
    )
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert f"CITADEL_RERANKER_URL=http://reranker:{port.group(1)}" in env_example, (
        ".env.example must match the served port"
    )


def test_reranker_accepts_a_full_candidate_batch() -> None:
    """TEI caps a /rerank batch at 32 by default, which 413s the 50 candidates
    CANDIDATES (src/citadel/retrieval/types.py) sends in one call — measured
    live on the pre-hardening defaults, so the flag is load-bearing."""
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "reranker")
    batch = re.search(r'"--max-client-batch-size", "(\d+)"', block)
    assert batch is not None, "name the batch ceiling explicitly, never TEI's default"
    assert int(batch.group(1)) >= 50, "must cover the retrieval path's candidate count"
