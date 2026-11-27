"""Role-scoped Temporal worker.

Each specialist polls its own task queue, so the docker worker never sees a
GitHub task. The heartbeat file is kept for the container healthcheck; it means
"worker loop is running", not "a workflow succeeded".
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final

from temporalio.client import Client
from temporalio.worker import Worker

from citadel import metrics, telemetry
from citadel.env import secret
from citadel.policy import RelationChecker, RunStore
from citadel.policy.openfga import build_checker
from citadel.runs import PostgresRunStore
from citadel.workflows import activities_for, namespace, temporal_address, workflows_for
from citadel.workflows.types import TASK_QUEUES

HEARTBEAT = Path(tempfile.gettempdir()) / "citadel-heartbeat"
HEARTBEAT_INTERVAL = 5
MAX_WORKERS = 8
DEFAULT_METRICS_PORT: Final = 9100


def _serve_metrics(role: str) -> None:
    """Expose this worker's registry. A bind failure is a log line, never a crash."""
    try:
        port = int(os.environ.get("CITADEL_METRICS_PORT", str(DEFAULT_METRICS_PORT)))
    except ValueError:
        port = DEFAULT_METRICS_PORT
    try:
        metrics.serve(port)
        print(f"worker {role} metrics on :{port}/metrics", flush=True)
    except (OSError, ValueError) as exc:
        print(f"worker {role} metrics unavailable on :{port}: {exc}", file=sys.stderr, flush=True)


def _beat(stop: threading.Event) -> None:
    while not stop.wait(HEARTBEAT_INTERVAL):
        HEARTBEAT.write_text(str(time.time()))


async def serve(role: str) -> None:
    if role not in TASK_QUEUES:
        raise SystemExit(f"unknown worker role {role!r}")

    client = await Client.connect(temporal_address(), namespace=namespace())

    dsn = secret("CITADEL_DB_DSN")
    checker: RelationChecker | None = None
    run_store: RunStore | None = None
    if role != "orchestrator":
        checker = build_checker(
            os.environ.get("OPENFGA_API_URL", "http://openfga:8080"),
            os.environ.get("OPENFGA_STORE_NAME", "citadel"),
        )
        run_store = PostgresRunStore(dsn)

    activities = activities_for(
        role,
        dsn=dsn,
        checker=checker,
        run_store=run_store,
        runner_url=os.environ.get("CITADEL_TOOL_RUNNER_URL", "http://tool-runner:8020"),
        operator_url=os.environ.get("CITADEL_OPERATOR_URL", "http://operator:8030"),
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)

    # Sync activities (policy and psycopg are sync) run off the event loop, so
    # the executor must outlive the worker.
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        worker = Worker(
            client,
            task_queue=TASK_QUEUES[role],
            workflows=workflows_for(role),
            activities=activities,
            activity_executor=executor,
        )
        print(f"worker {role} polling {TASK_QUEUES[role]!r}", flush=True)
        async with worker:
            await stop.wait()

    print(f"worker {role} stopped", flush=True)


def main() -> int:
    role = os.environ.get("CITADEL_WORKER_ROLE", "")
    if not role:
        raise SystemExit("CITADEL_WORKER_ROLE is not set")
    telemetry.configure(f"citadel-worker-{role}")

    stopping = threading.Event()
    threading.Thread(target=_beat, args=(stopping,), daemon=True).start()
    HEARTBEAT.write_text(str(time.time()))

    # A worker has no HTTP server of its own; the registry is exposed on its own port.
    _serve_metrics(role)

    try:
        asyncio.run(serve(role))
    finally:
        stopping.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
