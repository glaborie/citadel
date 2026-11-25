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
from opentelemetry.sdk.trace.export import BatchSpanProcessor
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


def configure(service_name: str) -> None:
    """Start exporting when MLflow is configured. Otherwise spans are a no-op."""
    global _tracer, _provider
    if _tracer is not None:
        return
    tracking = os.environ.get("MLFLOW_TRACKING_URI", "").rstrip("/")
    experiment = os.environ.get("MLFLOW_EXPERIMENT_ID", "")
    if not tracking or not experiment:
        return

    provider = TracerProvider(
        resource=Resource.create({"service.name": service_name}),
        id_generator=_RunIdGenerator(),
    )
    exporter = OTLPSpanExporter(
        endpoint=f"{tracking}/v1/traces",
        headers={"x-mlflow-experiment-id": experiment},
        timeout=5,
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
