"""Traces: one per run, every span joined to the audit ledger."""

from __future__ import annotations

import io
import json
import logging
import urllib.error
import uuid
from email.message import Message
from typing import Any
from urllib.parse import urlsplit

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from citadel import net, telemetry

RUN = "11111111-1111-1111-1111-111111111111"


def _path(request: Any) -> str:
    """A URL is parsed, never substring-matched: `"host" in url` is CWE-20.

    CodeQL flags the pattern (py/incomplete-url-substring-sanitization) because the
    allowed value can appear anywhere in the string - here it is a test double
    asserting which endpoint was called, so the check is on the path, which is what the
    assertion means anyway.
    """
    return str(urlsplit(str(request.full_url)).path)


def _mentions(message: str, value: str) -> bool:
    """Whether the message names `value` as a whole token, not as a substring."""
    return any(token == value for token in message.replace("(", " ").replace(")", " ").split())


def test_unconfigured_telemetry_is_a_no_op(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(telemetry, "_tracer", None)
    telemetry.record_span("run.start", run_id=RUN, audit_id="audit-1")


def test_spans_share_the_run_trace_and_carry_the_audit_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    exporter = InMemorySpanExporter()
    provider = TracerProvider(id_generator=telemetry._RunIdGenerator())
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(telemetry, "_tracer", provider.get_tracer("test"))

    telemetry.record_span("run.start", run_id=RUN, audit_id="audit-1", agent_id="docker")
    telemetry.record_span("tool.call", run_id=RUN, audit_id="audit-2", tool="read_logs")

    spans = exporter.get_finished_spans()
    assert [span.name for span in spans] == ["run.start", "tool.call"]
    assert spans[0].context is not None and spans[1].context is not None
    assert spans[0].context.trace_id == spans[1].context.trace_id
    assert spans[0].context.trace_id == uuid.UUID(RUN).int
    assert spans[0].attributes is not None and spans[1].attributes is not None
    assert spans[0].attributes["citadel.audit_id"] == "audit-1"
    assert spans[1].attributes["citadel.audit_id"] == "audit-2"
    assert spans[1].attributes["citadel.run_id"] == RUN


def test_non_uuid_run_ids_still_produce_a_valid_trace_id() -> None:
    first = telemetry._trace_id("run-devops-001")
    second = telemetry._trace_id("run-devops-001")
    assert first == second
    assert first != 0
    assert first < 1 << 128


class _Reply:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


@pytest.fixture(autouse=True)
def _reset_telemetry(monkeypatch: pytest.MonkeyPatch) -> Any:
    """`configure` writes module globals; a leaked provider would make the next test lie."""
    monkeypatch.setattr(telemetry, "_tracer", None)
    monkeypatch.setattr(telemetry, "_provider", None)
    monkeypatch.setenv("MLFLOW_TRACKING_URI", "http://mlflow.test")
    monkeypatch.delenv("MLFLOW_EXPERIMENT_ID", raising=False)
    monkeypatch.setenv("MLFLOW_EXPERIMENT_NAME", "citadel-trajectories")
    yield
    telemetry.shutdown()


def _not_found(request: Any) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(request.full_url, 404, "Not Found", Message(), io.BytesIO(b"{}"))


def test_the_configured_id_is_used_when_the_server_confirms_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    headers: list[dict[str, str]] = []

    class FakeExporter:
        def __init__(self, **kwargs: Any) -> None:
            headers.append(kwargs["headers"])

        def export(self, spans: Any) -> Any:
            return None

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    def urlopen(request: Any, timeout: Any = None) -> _Reply:
        assert _path(request) == "/api/2.0/mlflow/experiments/get"
        assert urlsplit(request.full_url).query == "experiment_id=1"
        return _Reply({"experiment": {"experiment_id": "1"}})

    monkeypatch.setenv("MLFLOW_EXPERIMENT_ID", "1")
    monkeypatch.setattr(net, "urlopen", urlopen)
    monkeypatch.setattr(telemetry, "OTLPSpanExporter", FakeExporter)

    telemetry.configure("api")

    assert headers == [{"x-mlflow-experiment-id": "1"}]


def test_an_id_the_server_does_not_have_falls_back_to_the_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A wrong id is a 404 on every span, so the name has to win when the id is stale."""
    headers: list[dict[str, str]] = []

    class FakeExporter:
        def __init__(self, **kwargs: Any) -> None:
            headers.append(kwargs["headers"])

        def export(self, spans: Any) -> Any:
            return None

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    def urlopen(request: Any, timeout: Any = None) -> _Reply:
        if _path(request) == "/api/2.0/mlflow/experiments/get":
            raise _not_found(request)
        assert _path(request) == "/api/2.0/mlflow/experiments/get-by-name"
        return _Reply({"experiment": {"experiment_id": "7"}})

    monkeypatch.setenv("MLFLOW_EXPERIMENT_ID", "1")
    monkeypatch.setattr(net, "urlopen", urlopen)
    monkeypatch.setattr(telemetry, "OTLPSpanExporter", FakeExporter)

    telemetry.configure("api")

    assert headers == [{"x-mlflow-experiment-id": "7"}]


def test_a_tracking_uri_with_no_experiment_disables_export_with_one_warning(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    calls: list[str] = []

    def urlopen(request: Any, timeout: Any = None) -> _Reply:
        calls.append(request.full_url)
        raise _not_found(request)

    monkeypatch.setattr(net, "urlopen", urlopen)

    with caplog.at_level(logging.WARNING):
        telemetry.configure("api")

    assert telemetry._tracer is None
    # get by name, then create: no id was configured, so the id lookup never ran.
    assert len(calls) == 2
    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert _mentions(message, "http://mlflow.test"), message
    assert "will not be recorded" in message


def test_an_unreachable_mlflow_warns_instead_of_a_silent_no_op(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def urlopen(request: Any, timeout: Any = None) -> _Reply:
        raise urllib.error.URLError("connection refused")

    monkeypatch.setenv("MLFLOW_EXPERIMENT_ID", "1")
    monkeypatch.setattr(net, "urlopen", urlopen)

    with caplog.at_level(logging.WARNING):
        telemetry.configure("api")

    assert telemetry._tracer is None
    assert any("connection refused" in record.getMessage() for record in caplog.records)


def test_a_rejected_batch_is_reported_once_not_per_batch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An outage must not become a log flood, and must not become silence either."""

    class Broken:
        def export(self, spans: Any) -> Any:
            raise RuntimeError("HTTP 404 RESOURCE_DOES_NOT_EXIST")

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30000) -> bool:
            return True

    exporter = telemetry._WarnOnceExporter(Broken())  # type: ignore[arg-type]

    with caplog.at_level(logging.WARNING):
        exporter.export([])
        exporter.export([])
        exporter.export([])

    warnings = [record for record in caplog.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "RESOURCE_DOES_NOT_EXIST" in warnings[0].getMessage()
    assert exporter.dropped == 3
