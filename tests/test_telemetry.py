"""Traces: one per run, every span joined to the audit ledger."""

from __future__ import annotations

import uuid

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

from citadel import telemetry

RUN = "11111111-1111-1111-1111-111111111111"


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
