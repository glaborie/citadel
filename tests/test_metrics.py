"""Prometheus exposition: the names, the bounded labels and the cost distinction."""

from __future__ import annotations

import urllib.error
import urllib.request
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from citadel import metrics
from citadel.api.app import create_app

TOKEN = "test-metrics-token"


@pytest.fixture
def metrics_token(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.delenv("CITADEL_METRICS_TOKEN_FILE", raising=False)
    monkeypatch.setenv("CITADEL_METRICS_TOKEN", TOKEN)
    return TOKEN


def _value(name: str, labels: dict[str, str] | None = None) -> float:
    return metrics.REGISTRY.get_sample_value(name, labels) or 0.0


def test_run_outcomes_stay_inside_the_label_set() -> None:
    before = _value("citadel_runs_total", {"outcome": "other"})

    metrics.run_finished("run-7b1f3d2e-should-not-become-a-label")

    assert _value("citadel_runs_total", {"outcome": "other"}) == before + 1
    assert (
        _value("citadel_runs_total", {"outcome": "run-7b1f3d2e-should-not-become-a-label"}) == 0.0
    )


def test_a_reported_zero_is_not_an_unreported_cost() -> None:
    reported = _value("citadel_model_cost_reported_total")
    unreported = _value("citadel_model_cost_unreported_total")

    metrics.model_usage(prompt_tokens=10, completion_tokens=5, cost_usd=0.0, cost_source="reported")
    assert _value("citadel_model_cost_reported_total") == reported + 1
    assert _value("citadel_model_cost_unreported_total") == unreported

    metrics.model_usage(
        prompt_tokens=3, completion_tokens=1, cost_usd=None, cost_source="unreported"
    )
    assert _value("citadel_model_cost_reported_total") == reported + 1
    assert _value("citadel_model_cost_unreported_total") == unreported + 1


def test_tokens_are_counted_by_kind() -> None:
    prompt = _value("citadel_model_tokens_total", {"kind": "prompt"})
    completion = _value("citadel_model_tokens_total", {"kind": "completion"})

    metrics.model_usage(
        prompt_tokens=12, completion_tokens=4, cost_usd=0.01, cost_source="reported"
    )

    assert _value("citadel_model_tokens_total", {"kind": "prompt"}) == prompt + 12
    assert _value("citadel_model_tokens_total", {"kind": "completion"}) == completion + 4


def test_dlp_and_policy_values_outside_the_set_become_other() -> None:
    metrics.dlp_block(surface="prompt text", reason="credential")
    metrics.policy_denial("rule-from-a-request")

    assert _value("citadel_dlp_blocks_total", {"surface": "other", "reason": "other"}) >= 1
    assert _value("citadel_policy_denials_total", {"rule": "other"}) >= 1


def test_cache_and_approval_results_are_bounded() -> None:
    metrics.cache_lookup("exact")
    metrics.approval_decision("approved", 42.0)

    assert _value("citadel_cache_lookups_total", {"result": "exact"}) >= 1
    assert _value("citadel_approval_wait_seconds_count", {"decision": "approved"}) >= 1


def test_the_api_exposes_a_prometheus_scrape_endpoint(metrics_token: str) -> None:
    client = TestClient(create_app())

    denied = client.get("/metrics")
    assert denied.status_code == 401
    assert "citadel_runs_total" not in denied.text
    assert metrics_token not in denied.text

    response = client.get("/metrics", headers={"Authorization": f"Bearer {metrics_token}"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "citadel_runs_total" in response.text
    assert "# TYPE citadel_model_cost_unreported_total counter" in response.text
    assert metrics_token not in response.text


def test_a_wrong_metrics_token_is_refused(metrics_token: str) -> None:
    response = TestClient(create_app()).get(
        "/metrics", headers={"Authorization": "Bearer not-the-token"}
    )

    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"
    assert "citadel_runs_total" not in response.text
    assert metrics_token not in response.text


def test_an_unset_metrics_token_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("CITADEL_METRICS_TOKEN_FILE", raising=False)
    monkeypatch.delenv("CITADEL_METRICS_TOKEN", raising=False)

    response = TestClient(create_app()).get(
        "/metrics", headers={"Authorization": "Bearer anything"}
    )

    assert response.status_code == 503
    assert "citadel_runs_total" not in response.text


def test_the_token_can_come_from_the_mounted_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "metrics_token"
    path.write_text(TOKEN + "\n", encoding="ascii")
    monkeypatch.delenv("CITADEL_METRICS_TOKEN", raising=False)
    monkeypatch.setenv("CITADEL_METRICS_TOKEN_FILE", str(path))

    metrics.check_scrape_auth(f"Bearer {TOKEN}")

    monkeypatch.setenv("CITADEL_METRICS_TOKEN_FILE", str(tmp_path / "absent"))
    with pytest.raises(metrics.ScrapeRefused) as refused:
        metrics.check_scrape_auth(f"Bearer {TOKEN}")
    assert refused.value.status == 503


def test_the_worker_scrape_server_requires_the_same_token(
    metrics_token: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    port = metrics.serve(0)
    url = f"http://127.0.0.1:{port}/metrics"

    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {metrics_token}"})
    with urllib.request.urlopen(request, timeout=5) as response:
        body = response.read().decode()

    assert response.status == 200
    assert "citadel_runs_total" in body
    assert metrics_token not in body

    with pytest.raises(urllib.error.HTTPError) as denied:
        urllib.request.urlopen(url, timeout=5)
    assert denied.value.code == 401
    assert metrics_token not in denied.value.read().decode()

    wrong = urllib.request.Request(url, headers={"Authorization": "Bearer wrong-token"})
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(wrong, timeout=5)
    assert refused.value.code == 401

    monkeypatch.delenv("CITADEL_METRICS_TOKEN")
    with pytest.raises(urllib.error.HTTPError) as unconfigured:
        urllib.request.urlopen(url, timeout=5)
    assert unconfigured.value.code == 503
