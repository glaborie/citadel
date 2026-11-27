"""Prometheus exposition: the names, the bounded labels and the cost distinction."""

from __future__ import annotations

import urllib.request

from fastapi.testclient import TestClient

from citadel import metrics
from citadel.api.app import create_app


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


def test_the_api_exposes_a_prometheus_scrape_endpoint() -> None:
    response = TestClient(create_app()).get("/metrics")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "citadel_runs_total" in response.text
    assert "# TYPE citadel_model_cost_unreported_total counter" in response.text


def test_the_worker_scrape_server_serves_the_same_registry() -> None:
    port = metrics.serve(0)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics", timeout=5) as response:
        body = response.read().decode()

    assert response.status == 200
    assert "citadel_runs_total" in body
