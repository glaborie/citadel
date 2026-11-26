"""The MLflow experiment bootstrap is idempotent and creates only on 404."""

from __future__ import annotations

import io
import json
import urllib.error
import urllib.request
from email.message import Message
from typing import Any

import pytest

from citadel import mlflow_bootstrap, net


class Reply:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def test_existing_experiment_is_returned(monkeypatch: pytest.MonkeyPatch) -> None:
    def urlopen(request: Any, timeout: Any = None) -> Reply:
        assert "get-by-name" in request.full_url
        return Reply({"experiment": {"experiment_id": "3"}})

    monkeypatch.setattr(net, "urlopen", urlopen)
    assert mlflow_bootstrap.ensure_experiment() == "3"


def test_missing_experiment_is_created(monkeypatch: pytest.MonkeyPatch) -> None:
    created: list[str] = []

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        if "get-by-name" in request.full_url:
            raise urllib.error.HTTPError(
                request.full_url, 404, "Not Found", Message(), io.BytesIO(b"{}")
            )
        created.append(request.full_url)
        return Reply({"experiment_id": "7"})

    monkeypatch.setattr(net, "urlopen", urlopen)
    assert mlflow_bootstrap.ensure_experiment() == "7"
    assert created == [f"{mlflow_bootstrap.BASE}/api/2.0/mlflow/experiments/create"]

def _found(monkeypatch: pytest.MonkeyPatch, experiment_id: str) -> None:
    def urlopen(request: Any, timeout: Any = None) -> Reply:
        assert "get-by-name" in request.full_url
        return Reply({"experiment": {"experiment_id": experiment_id}})

    monkeypatch.setattr(net, "urlopen", urlopen)


def test_a_drifted_experiment_id_fails_before_any_worker_starts(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """MLflow answers a span for a missing experiment with 404 and the exporter drops it."""
    _found(monkeypatch, "7")
    monkeypatch.setattr(mlflow_bootstrap, "EXPECTED", "1")

    assert mlflow_bootstrap.main() == 1
    message = capsys.readouterr().err
    assert "id 7" in message and "MLFLOW_EXPERIMENT_ID=1" in message
    assert "MLFLOW_EXPERIMENT_ID=7" in message, "the failure has to name the fix"


def test_a_matching_id_passes_and_prints_it(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    _found(monkeypatch, "1")
    monkeypatch.setattr(mlflow_bootstrap, "EXPECTED", "1")

    assert mlflow_bootstrap.main() == 0
    assert capsys.readouterr().out.strip() == "1"


def test_an_unset_id_is_not_checked(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The module is usable without the compose wiring, so the check is opt-in."""
    _found(monkeypatch, "7")
    monkeypatch.setattr(mlflow_bootstrap, "EXPECTED", "")

    assert mlflow_bootstrap.main() == 0
    assert capsys.readouterr().out.strip() == "7"


def test_an_unreachable_mlflow_is_a_failure_not_a_silent_no_op(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A bootstrap that exits 0 without an experiment would let the workers start blind."""
    import urllib.error

    def urlopen(request: Any, timeout: Any = None) -> Reply:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(net, "urlopen", urlopen)

    assert mlflow_bootstrap.main() == 1
    assert "could not ensure MLflow experiment" in capsys.readouterr().err
