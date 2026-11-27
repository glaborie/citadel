"""The trace's shape: one root per run, and the payload MLflow reads from it.

Measured on 3.18.0: a trace whose spans are all parentless has `request=None` and
`response=None`, so the Traces table's Inputs/Outputs columns are empty. A root span carrying
`mlflow.spanInputs`/`mlflow.spanOutputs` fills both, and a second write with the same span id
**replaces** the first - which is why the closing write carries the inputs again. These tests
hold that shape without a server.
"""

from __future__ import annotations

import datetime

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from citadel import telemetry

RUN = "4f61bb68-7044-4f24-ae22-0c6389690880"
INPUTS: dict[str, object] = {"task_chars": 3, "tenant_id": "lab-a"}


@pytest.fixture
def exporter(monkeypatch: pytest.MonkeyPatch) -> InMemorySpanExporter:
    """A tracer that ends spans in memory, with the repository's own id generator."""
    memory = InMemorySpanExporter()
    provider = TracerProvider(id_generator=telemetry._RunIdGenerator())
    provider.add_span_processor(SimpleSpanProcessor(memory))
    monkeypatch.setattr(telemetry, "_tracer", provider.get_tracer("citadel"))
    return memory


def _attributes(span: object) -> dict[str, object]:
    values = getattr(span, "attributes", None)
    return dict(values or {})


def test_every_span_hangs_off_the_run_root(exporter: InMemorySpanExporter) -> None:
    telemetry.record_root_span("run.start", run_id=RUN, audit_id="a1", inputs=INPUTS)
    telemetry.record_span("model.call", run_id=RUN, audit_id="a2", model="auto")

    root, child = exporter.get_finished_spans()
    assert root.parent is None, "the root is the trace's entry point, not a child of itself"
    assert child.parent is not None
    assert child.parent.span_id == root.context.span_id
    assert child.context.trace_id == root.context.trace_id


def test_the_closing_write_replaces_the_root_with_both_directions(
    exporter: InMemorySpanExporter, monkeypatch: pytest.MonkeyPatch
) -> None:
    # `full` on purpose: this test is about the payload's content, not the mode's default.
    monkeypatch.setenv(telemetry.MODE_ENV, "full")
    telemetry.record_root_span("run.start", run_id=RUN, audit_id="a1", inputs=INPUTS)
    telemetry.record_root_span(
        "run.start",
        run_id=RUN,
        audit_id="a2",
        inputs=INPUTS,
        outputs={"outcome": "answered", "answer": "42"},
    )

    opened, closed = exporter.get_finished_spans()
    assert opened.context.span_id == closed.context.span_id, "one root, written twice"
    assert telemetry.SPAN_INPUTS in _attributes(opened)
    assert telemetry.SPAN_OUTPUTS not in _attributes(opened)

    closing = _attributes(closed)
    assert '"answer": "42"' in str(closing[telemetry.SPAN_OUTPUTS])
    assert telemetry.SPAN_INPUTS in closing, "the second write replaces, so it re-sends the inputs"
    assert closing["mlflow.spanType"] == "AGENT"


def test_a_root_id_is_stable_and_fits_the_wire(exporter: InMemorySpanExporter) -> None:
    """Both writers derive it from the run id, in different processes, with no shared state."""
    telemetry.record_root_span("run.start", run_id=RUN, audit_id="a1", inputs={})
    telemetry.record_span("retrieval.query", run_id=RUN, audit_id="a2")

    first, second = exporter.get_finished_spans()
    root_id = telemetry._root_span_id(RUN)
    assert root_id == telemetry._root_span_id(RUN)
    assert 0 < root_id < 2**64
    assert first.context.span_id == root_id
    assert second.parent is not None and second.parent.span_id == root_id


def test_a_span_without_a_chosen_parent_still_lands_in_the_run(
    exporter: InMemorySpanExporter,
) -> None:
    telemetry.record_span("policy.decision", run_id=RUN, audit_id="a1", decision="allow")

    (span,) = exporter.get_finished_spans()
    assert span.context.trace_id == telemetry._trace_id(RUN)
    assert span.parent is not None


def test_nothing_is_emitted_without_a_tracer(monkeypatch: pytest.MonkeyPatch) -> None:
    """An unconfigured process is a no-op, not an exception in the request path."""
    monkeypatch.setattr(telemetry, "_tracer", None)
    telemetry.record_root_span("run.start", run_id=RUN, audit_id="a1", inputs=INPUTS)
    telemetry.record_span("run.end", run_id=RUN, audit_id="a2")


def test_the_payload_is_json_mlflow_can_render() -> None:
    assert telemetry._as_json({"b": 1, "a": [1, 2]}) == '{"a": [1, 2], "b": 1}'
    assert telemetry._as_json("already json") == "already json"
    stamped = telemetry._as_json({"at": datetime.date(2026, 1, 2)})
    assert "2026-01-02" in stamped


def test_the_default_mode_drops_the_text_and_keeps_the_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A stack that says nothing gets summaries: ADR-005, not a debug convenience."""
    monkeypatch.delenv(telemetry.MODE_ENV, raising=False)
    encoded = str(telemetry._payload({"task": "hello", "tenant_id": "lab-a"}))
    assert "hello" not in encoded
    assert '"task_chars": 5' in encoded
    assert '"task_sha256"' in encoded
    assert "lab-a" in encoded


def test_full_mode_carries_the_text_a_reader_wants(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(telemetry.MODE_ENV, "full")
    assert '"task": "hello"' in str(telemetry._payload({"task": "hello"}))


def test_none_mode_sends_no_payload_at_all(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(telemetry.MODE_ENV, "none")
    assert telemetry._payload({"task": "hello"}) is None


def test_an_unrecognised_mode_falls_back_to_summary(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(telemetry.MODE_ENV, "verbose")
    assert telemetry.content_mode() == "summary"
