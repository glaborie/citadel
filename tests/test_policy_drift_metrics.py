"""Issue #285: the drift verdict reaches Prometheus, and an alert can fire on it.

The scheduled check runs on the host, which Prometheus cannot scrape, so the
wrapper pushes gauges to `pushgateway`. These tests cover the payload, the push
against a real HTTP endpoint, the fail-open-on-push-failure rule, and the
Compose/rule/doc wiring that makes the series visible in Grafana.
"""

from __future__ import annotations

import importlib.util
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy-drift-alert.py"
COMPOSE = ROOT / "compose.yaml"
SCRAPE = ROOT / "docker" / "prometheus" / "prometheus.yml"
RULES = ROOT / "docker" / "prometheus" / "rules" / "citadel.yml"
METRICS_DOC = ROOT / "docs" / "architecture" / "metrics.md"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("policy_drift_alert_metrics", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load()


def test_a_clean_run_pushes_zero_drift() -> None:
    body = cli.payload(0, 1_700_000_000.0)

    assert "citadel_policy_drift 0\n" in body
    assert "citadel_policy_drift_check_failed 0\n" in body
    assert "citadel_policy_drift_last_run_timestamp_seconds 1700000000\n" in body


def test_drift_pushes_one_and_is_not_a_check_failure() -> None:
    """The two series are separate so "could not compare" cannot satisfy the drift alert."""
    body = cli.payload(1, 1_700_000_000.0)

    assert "citadel_policy_drift 1\n" in body
    assert "citadel_policy_drift_check_failed 0\n" in body


def test_could_not_compare_pushes_the_check_failure_not_drift() -> None:
    body = cli.payload(2, 1_700_000_000.0)

    assert "citadel_policy_drift 0\n" in body
    assert "citadel_policy_drift_check_failed 1\n" in body


class _Capture(BaseHTTPRequestHandler):
    requests: list[tuple[str, str, str]] = []

    def do_POST(self) -> None:  # noqa: N802 - the http.server interface
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode()
        type(self).requests.append((self.command, self.path, body))
        self.send_response(200)
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        del format, args


def test_the_push_posts_the_gauges_to_the_job_path() -> None:
    _Capture.requests = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Capture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        cli.push(1, f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()

    assert len(_Capture.requests) == 1
    method, path, body = _Capture.requests[0]
    assert method == "POST"
    assert path == "/metrics/job/citadel_policy_drift"
    assert "citadel_policy_drift 1" in body


def test_a_refused_push_is_an_error_not_a_silent_success() -> None:
    """`push` raises, so `main` can say so; `main` is what decides the verdict."""

    class _Refusing(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            self.send_response(500)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            del format, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Refusing)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        try:
            cli.push(0, f"http://127.0.0.1:{server.server_port}")
        except OSError as exc:
            assert "500" in str(exc)
        else:  # pragma: no cover - the assertion below is the point
            raise AssertionError("a 500 from the pushgateway must raise")
    finally:
        server.shutdown()


def test_a_dead_pushgateway_does_not_change_the_verdict() -> None:
    """Telemetry is not a control (ADR-015); a metrics outage must not mask drift."""
    seen: list[tuple[str, str]] = []

    def dead(_code: int) -> None:
        raise ConnectionRefusedError(111, "Connection refused")

    code = cli.main(
        check=lambda: 1,
        notify=lambda p, m: seen.append((p, m)),
        push_metrics=dead,
    )

    assert code == 1, "the check's verdict is the exit code, not the push result"
    assert [priority for priority, _ in seen] == ["err", "crit"], (
        "metrics failure is reported at err, and the drift alert still goes out"
    )
    assert "not pushed" in seen[0][1]


def test_the_drift_verdict_is_pushed_for_every_outcome() -> None:
    pushed: list[int] = []

    def quiet(_priority: str, _message: str) -> None:
        return None

    for code in (0, 1, 2):
        cli.main(
            check=lambda c=code: c,
            notify=quiet,
            push_metrics=pushed.append,
        )

    assert pushed == [0, 1, 2], "a run that did not report looks exactly like a clean store"


def test_prometheus_scrapes_the_pushgateway() -> None:
    scrape = SCRAPE.read_text(encoding="utf-8")

    assert "job_name: pushgateway" in scrape
    assert "pushgateway:9091" in scrape


def test_the_three_policy_alerts_exist() -> None:
    rules = RULES.read_text(encoding="utf-8")

    for alert in ("CitadelPolicyDrift", "CitadelPolicyDriftCheckFailed", "CitadelPolicyDriftStale"):
        assert f"alert: {alert}" in rules, alert
    assert "max(citadel_policy_drift) > 0" in rules
    assert "absent(citadel_policy_drift_last_run_timestamp_seconds)" in rules, (
        "a job that never reported must alert, not stay silent"
    )


def test_the_pushgateway_service_is_pinned_and_loopback_only() -> None:
    compose = COMPOSE.read_text(encoding="utf-8")
    block: str = compose.split("  pushgateway:\n", 1)[1].split("\n  grafana:", 1)[0]

    assert "image: prom/pushgateway:v1.9.0@sha256:" in block
    assert '"127.0.0.1:19091:9091"' in block
    assert "no-new-privileges:true" in block
    assert "healthcheck:" in block


def test_the_metrics_doc_lists_the_gauges_and_the_alerts() -> None:
    doc = METRICS_DOC.read_text(encoding="utf-8")

    for name in (
        "citadel_policy_drift",
        "citadel_policy_drift_check_failed",
        "citadel_policy_drift_last_run_timestamp_seconds",
        "CitadelPolicyDrift",
        "CitadelPolicyDriftCheckFailed",
        "CitadelPolicyDriftStale",
        "pushgateway",
    ):
        assert name in doc, f"docs/architecture/metrics.md does not mention {name}"
