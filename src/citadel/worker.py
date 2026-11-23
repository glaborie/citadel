"""Skeleton worker: stays alive and proves liveness until step 5 adds Temporal.

shortcut: no Temporal polling or workflow logic, replaced in step 5.
"""

from __future__ import annotations

import os
import signal
import sys
import time
from pathlib import Path

HEARTBEAT = Path("/tmp/citadel-heartbeat")
INTERVAL_SECONDS = 5
STALE_AFTER_SECONDS = 30


def main() -> int:
    role = os.environ.get("CITADEL_WORKER_ROLE", "unassigned")
    running = True

    def stop(signum: int, frame: object) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    print(f"worker {role} started", flush=True)
    while running:
        HEARTBEAT.write_text(str(time.time()))
        time.sleep(INTERVAL_SECONDS)
    print(f"worker {role} stopped", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
