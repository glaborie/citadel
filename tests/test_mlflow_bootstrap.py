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
