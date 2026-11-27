"""OTLP/HTTP spans to MLflow, one trace per run.

The audit ledger is the control record; these spans are the telemetry view of
the same events. Every span carries the audit event id, so a trace can be joined
back to the ledger without trusting either store alone.

The trace id is derived from the run id and forced through a custom id
generator, so spans emitted by different processes (API, worker, operator) land
in the same MLflow trace without propagating context through Temporal headers.

Each span is still one audit event, but they hang off a single per-run root span
named `run`, whose id is derived from the run id the same way. Without it MLflow
has no root to take the trace's request and response from: it showed ten
parentless spans, and the Inputs/Outputs columns were empty - the trace recorded
what the agent did and nothing about what it produced.

The root is written twice with the same span id, and the second write **replaces**
the first rather than merging into it (measured: writing only outputs took the
request back to null). So `run.end` re-sends the inputs, which it reads back from
the run.start audit event, and only then is the root complete.

    MLFLOW_TRACKING_URI=http://mlflow:5000
    MLFLOW_EXPERIMENT_ID=1
"""

from __future__ import annotations

import atexit
import contextvars
import hashlib
import json
import logging
import os
import uuid
from typing import Any

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.id_generator import IdGenerator, RandomIdGenerator
from opentelemetry.trace import (
    NonRecordingSpan,
    SpanContext,
    TraceFlags,
    Tracer,
    set_span_in_context,
)

logger = logging.getLogger(__name__)

_tracer: Tracer | None = None
_provider: TracerProvider | None = None
_current_trace: contextvars.ContextVar[int] = contextvars.ContextVar("citadel_trace", default=0)
_current_span: contextvars.ContextVar[int] = contextvars.ContextVar("citadel_span", default=0)


class _RunIdGenerator(IdGenerator):
    """Force every span in a run onto the run's trace id."""

    def generate_trace_id(self) -> int:
        forced = _current_trace.get()
        return forced or RandomIdGenerator().generate_trace_id()

    def generate_span_id(self) -> int:
        forced = _current_span.get()
        return forced or RandomIdGenerator().generate_span_id()


def resolve_experiment(tracking: str) -> str | None:
    """The id the exporter must name, or None after one warning that says why.

    `MLFLOW_EXPERIMENT_ID` wins when the server confirms it exists; otherwise the id is
    taken for `MLFLOW_EXPERIMENT_NAME`, which the bootstrap creates if it is absent. A
    tracking URI with no experiment behind it used to look exactly like a healthy one:
    MLflow answers 404, the SDK retries, drops the batch, and nothing in the process
    mentioned it. The warning is the whole point of this function.
    """
    from citadel import mlflow_bootstrap

    configured = os.environ.get("MLFLOW_EXPERIMENT_ID", "").strip()
    try:
        if configured and mlflow_bootstrap.experiment_exists(configured, base=tracking):
            return configured
        return mlflow_bootstrap.ensure_experiment(base=tracking)
    except (OSError, KeyError, ValueError) as exc:
        logger.warning(
            "telemetry disabled: no MLflow experiment at %s (%s). Spans from this process "
            "will not be recorded; the audit ledger is unaffected.",
            tracking,
            exc,
        )
        return None


class _FailureLog:
    """One warning per process, then a count: an outage is a line, not a flood.

    The policy lives here rather than in the exporter so that it is one object with one
    job - the exporter asks it to record a failure and does not care what it cost.
    """

    def __init__(self) -> None:
        self.count = 0
        self._warned = False

    def record(self, reason: object) -> None:
        self.count += 1
        if self._warned:
            return
        self._warned = True
        logger.warning(
            "telemetry export failed: %s. Spans are being dropped (further failures are "
            "counted, not logged); the audit ledger is unaffected.",
            reason,
        )


class _WarnOnceExporter(SpanExporter):
    """An exporter that reports a dead trace path once per process.

    The SDK retries a failed batch and then discards it. Its own logging goes through a
    logger nothing here configures, so a rejected batch was invisible.
    """

    def __init__(self, inner: SpanExporter) -> None:
        self._inner = inner
        self.failures = _FailureLog()

    @property
    def dropped(self) -> int:
        """How many batches were lost. A number an operator can print, not just a log line."""
        return self.failures.count

    def export(self, spans: Any) -> SpanExportResult:  # noqa: ANN401 - the SDK's own type
        try:
            exported = self._inner.export(spans)
        except Exception as exc:  # noqa: BLE001 - a failing exporter must not fail a run
            self.failures.record(exc)
            return SpanExportResult.FAILURE
        if exported is SpanExportResult.FAILURE:
            self.failures.record("the exporter returned FAILURE")
        return exported

    def shutdown(self) -> None:
        self._inner.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._inner.force_flush(timeout_millis)


def configure(service_name: str) -> None:
    """Start exporting when MLflow answers. Otherwise spans are a no-op, and it says so."""
    global _tracer, _provider
    if _tracer is not None:
        return
    tracking = os.environ.get("MLFLOW_TRACKING_URI", "").rstrip("/")
    if not tracking:
        # Never configured: a deliberate no-op, and no warning to drown the logs in.
        return
    experiment = resolve_experiment(tracking)
    if experiment is None:
        return

    _start(tracking, experiment, service_name)


def _start(tracking: str, experiment: str, service_name: str) -> None:
    """Build the provider. Only called once a resolvable experiment exists."""
    global _tracer, _provider
    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name}),
        id_generator=_RunIdGenerator(),
    )
    exporter = _WarnOnceExporter(
        OTLPSpanExporter(
            endpoint=f"{tracking}/v1/traces",
            headers={"x-mlflow-experiment-id": experiment},
            timeout=5,
        )
    )
    # Batched: a slow or down MLflow must not add latency to a tool call.
    provider.add_span_processor(BatchSpanProcessor(exporter))
    _provider = provider
    _tracer = provider.get_tracer("citadel")
    atexit.register(shutdown)


def shutdown() -> None:
    global _tracer, _provider
    if _provider is not None:
        _provider.shutdown()
    _provider = None
    _tracer = None


ROOT_SPAN_NAME = "run"


def _as_json(value: Any) -> str:
    """MLflow reads span inputs and outputs as JSON text, and renders it as the trace's payload."""
    if isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, default=str)


def _set_span(name: str, run_id: str, values: dict[str, Any], *, root: bool) -> None:
    """Start and end one span, parented to the run root unless it is the root itself."""
    tracer = _tracer
    if tracer is None:
        return
    token_trace = _current_trace.set(_trace_id(run_id))
    token_span = _current_span.set(_root_span_id(run_id)) if root else None
    try:
        attributes = {key: value for key, value in values.items() if value is not None}
        # The root has no parent to point at; the id generator still puts it on the run's
        # trace. Everything else hangs off the root, whichever process writes it.
        with tracer.start_as_current_span(
            name,
            context=None if root else _root_context(run_id),
            attributes=attributes,
        ):
            pass
    except Exception:  # noqa: BLE001 - a broken exporter must not block the control
        logger.warning("failed to emit span %s", name, exc_info=True)
    finally:
        if token_span is not None:
            _current_span.reset(token_span)
        _current_trace.reset(token_trace)


def record_span(name: str, *, run_id: str, audit_id: str, **attributes: Any) -> None:
    """Emit one span linked to an audit event. Telemetry never fails a run."""
    _set_span(
        name,
        run_id,
        {"citadel.run_id": run_id, "citadel.audit_id": audit_id, **attributes},
        root=False,
    )


def record_root_span(
    name: str = ROOT_SPAN_NAME,
    *,
    run_id: str,
    audit_id: str,
    inputs: Any = None,
    outputs: Any = None,
    **attributes: Any,
) -> None:
    """Write the run's root span, the one MLflow takes the trace's request and response from.

    Called twice per run with the same span id: once at `run.start` with the inputs, once at
    `run.end` with the outputs. A partial write is still better than none - a run that dies
    mid-flight shows what it was asked.
    """
    values: dict[str, Any] = {
        "citadel.run_id": run_id,
        "citadel.audit_id": audit_id,
        **attributes,
    }
    encoded_inputs = _payload(inputs)
    encoded_outputs = _payload(outputs)
    if encoded_inputs is not None:
        values[SPAN_INPUTS] = encoded_inputs
    if encoded_outputs is not None:
        values[SPAN_OUTPUTS] = encoded_outputs
        values["mlflow.spanType"] = "AGENT"
    _set_span(name, run_id, values, root=True)


SPAN_INPUTS = "mlflow.spanInputs"
SPAN_OUTPUTS = "mlflow.spanOutputs"

MODE_ENV = "CITADEL_TRACE_CONTENT"
TEXT_KEYS = ("task", "answer")


def content_mode() -> str:
    """How much free text a trace may carry: `full`, `summary` (default) or `none`.

    `summary` keeps the shape of a payload - lengths, digests, ids - and drops the text, which
    is what ADR-005 asks for (traces carry redacted payloads). `full` is an explicit opt-in for
    a development stack, where reading the actual answer in the MLflow UI is the whole point.
    A value nobody recognises falls back to `summary`: a typo must not widen what leaves.
    """
    value = os.environ.get(MODE_ENV, "summary").strip().lower()
    return value if value in {"full", "summary", "none"} else "summary"


def _payload(payload: Any) -> str | None:  # noqa: ANN401 - a dict or an already-encoded string
    """Encode what the mode allows, and nothing else."""
    if payload is None:
        return None
    mode = content_mode()
    if mode == "none":
        return None
    if mode == "full" or not isinstance(payload, dict):
        return _as_json(payload)
    kept = {key: value for key, value in payload.items() if key not in TEXT_KEYS}
    for key in TEXT_KEYS:
        if key in payload:
            text = str(payload[key])
            kept[f"{key}_chars"] = len(text)
            kept[f"{key}_sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return _as_json(kept)


def _root_context(run_id: str) -> Any:  # noqa: ANN401 - opentelemetry's Context type
    """A parent context pointing at the run's root span, which may not be exported yet."""
    parent = SpanContext(
        trace_id=_trace_id(run_id),
        span_id=_root_span_id(run_id),
        is_remote=True,
        trace_flags=TraceFlags(TraceFlags.SAMPLED),
    )
    return set_span_in_context(NonRecordingSpan(parent))


def _root_span_id(run_id: str) -> int:
    """A 64-bit id derived from the run id, so both writers agree without sharing state."""
    digest = hashlib.sha256(f"root:{run_id}".encode()).digest()
    return int.from_bytes(digest[:8], "big") or 1


def _trace_id(run_id: str) -> int:
    try:
        value = uuid.UUID(run_id).int
    except (ValueError, AttributeError):
        # Deterministic for fixture ids too, so a trace still joins.
        digest = hashlib.sha256(run_id.encode("utf-8")).digest()
        value = int.from_bytes(digest[:16], "big")
    # An all-zero trace id is invalid.
    return value or 1
