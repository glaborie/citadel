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
