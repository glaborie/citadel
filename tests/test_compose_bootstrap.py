"""#95: a fresh volume gets its experiment before anything writes a span."""

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


def _span_exporters(compose: str) -> list[str]:
    """Every service that names an experiment, so every service that writes a span."""
    return [
        match.group(1)
        for match in re.finditer(r"^  ([a-z0-9-]+):$", compose, re.MULTILINE)
        if match.group(1) != "mlflow-bootstrap"
        and "MLFLOW_EXPERIMENT_ID:" in _service_block(compose, match.group(1))
    ]


def test_the_bootstrap_runs_once_and_stops() -> None:
    """A one-shot that restarts would recreate the experiment on every crash loop."""
    block = _service_block(COMPOSE_PATH.read_text(encoding="utf-8"), "mlflow-bootstrap")

    assert 'restart: "no"' in block
    assert "citadel.mlflow_bootstrap" in block
    assert re.search(r"depends_on:\n      mlflow:\n        condition: service_healthy", block), (
        "the bootstrap must wait for MLflow's health check, or a fresh start races the server"
    )


def test_every_span_exporter_waits_for_the_bootstrap() -> None:
    """`make up` is the acceptance: nobody may write a span before the experiment exists."""
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    exporters = _span_exporters(compose)

    assert exporters, "no service declares MLFLOW_EXPERIMENT_ID; this test is asleep"
    for name in exporters:
        block = _service_block(compose, name)
        assert re.search(
            r"mlflow-bootstrap:\n        condition: service_completed_successfully", block
        ), f"{name} exports spans but does not wait for mlflow-bootstrap to exit 0"


def test_the_bootstrap_writes_to_the_same_experiment_the_workers_read() -> None:
    """The check is only worth anything if the id it validates is the id they use."""
    compose = COMPOSE_PATH.read_text(encoding="utf-8")
    bootstrap = _service_block(compose, "mlflow-bootstrap")
    bootstrap_id = re.search(r"MLFLOW_EXPERIMENT_ID: \$\{MLFLOW_EXPERIMENT_ID:-(\d+)\}", bootstrap)
    assert bootstrap_id is not None, "the bootstrap must be told which id to expect"

    for name in _span_exporters(compose):
        block = _service_block(compose, name)
        worker_id = re.search(r"MLFLOW_EXPERIMENT_ID: \$\{MLFLOW_EXPERIMENT_ID:-(\d+)\}", block)
        assert worker_id is not None, name
        assert worker_id.group(1) == bootstrap_id.group(1), (
            f"{name} writes to experiment {worker_id.group(1)}, the bootstrap validates "
            f"{bootstrap_id.group(1)}"
        )
