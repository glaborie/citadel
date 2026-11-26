"""ADR-017/D3: the MLflow UI stays off the host until a Keycloak proxy fronts it.

The API and workers write traces over the internal OTLP route, which needs no
browser session. The UI is internal-only, so the only thing to enforce today is
that nobody publishes it: a published port with no authentication is a hole.
"""

from __future__ import annotations

import re
from pathlib import Path

COMPOSE_PATH = Path(__file__).resolve().parents[1] / "compose.yaml"


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


def test_mlflow_is_not_published_and_stays_off_edge() -> None:
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "mlflow")
    assert "ports:" not in block, (
        "MLflow is published on the host. ADR-017 requires the Keycloak OAuth2 "
        "proxy in front of the UI first (unauthenticated -> Keycloak redirect, "
        "authenticated -> the UI); teach this guard the proxy's shape before "
        "opening the port."
    )
    networks = re.search(r"^    networks:\n((?:      - \S+\n)+)", block, re.MULTILINE)
    assert networks is not None, "mlflow must declare its networks explicitly"
    assert re.findall(r"- (\S+)", networks.group(1)) == ["internal"], (
        "MLflow must stay internal-only; the OTLP write path and the eval UI are "
        "reached from inside the compose network."
    )


PUBLISHED_MLFLOW = """\
services:
  mlflow:
    image: example
    ports:
      - "15000:5000"
  presidio:
    image: example
"""


def test_the_guard_notices_a_published_mlflow() -> None:
    block = _service_block(PUBLISHED_MLFLOW, "mlflow")
    assert "ports:" in block, "the extractor must see mlflow's own keys"
    assert "presidio" not in block, "the extractor must stop at the next service"
