"""OTLP/HTTP spans to MLflow, one trace per run.

The audit ledger is the control record; these spans are the telemetry view of
the same events. Every span carries the audit event id, so a trace can be joined
back to the ledger without trusting either store alone.

The trace id is derived from the run id and forced through a custom id
generator, so spans emitted by different processes (API, worker, operator) land
in the same MLflow trace without propagating context through Temporal headers.
The spans are siblings, not a call tree: each one is an audit event.

    MLFLOW_TRACKING_URI=http://mlflow:5000
    MLFLOW_EXPERIMENT_ID=1
"""

from __future__ import annotations

import atexit
import contextvars
import hashlib
import logging
import os
import uuid
from typing import Any

from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.sdk.trace.id_generator import IdGenerator, RandomIdGenerator
from opentelemetry.trace import Tracer

logger = logging.getLogger(__name__)

_tracer: Tracer | None = None
_provider: TracerProvider | None = None
_current_trace: contextvars.ContextVar[int] = contextvars.ContextVar("citadel_trace", default=0)


class _RunIdGenerator(IdGenerator):
    """Force every span in a run onto the run's trace id."""

    def generate_trace_id(self) -> int:
        forced = _current_trace.get()
        return forced or RandomIdGenerator().generate_trace_id()

    def generate_span_id(self) -> int:
        return RandomIdGenerator().generate_span_id()


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


def record_span(name: str, *, run_id: str, audit_id: str, **attributes: Any) -> None:
    """Emit one span linked to an audit event. Telemetry never fails a run."""
    tracer = _tracer
    if tracer is None:
        return
    token = _current_trace.set(_trace_id(run_id))
    try:
        values: dict[str, Any] = {
            "citadel.run_id": run_id,
            "citadel.audit_id": audit_id,
            **attributes,
        }
        with tracer.start_as_current_span(
            name,
            attributes={key: value for key, value in values.items() if value is not None},
        ):
            pass
    except Exception:  # noqa: BLE001 - a broken exporter must not block the control
        logger.warning("failed to emit span %s", name, exc_info=True)
    finally:
        _current_trace.reset(token)


def _trace_id(run_id: str) -> int:
    try:
        value = uuid.UUID(run_id).int
    except (ValueError, AttributeError):
        # Deterministic for fixture ids too, so a trace still joins.
        digest = hashlib.sha256(run_id.encode("utf-8")).digest()
        value = int.from_bytes(digest[:16], "big")
    # An all-zero trace id is invalid.
    return value or 1
