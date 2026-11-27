"""A per-credential ingress budget for run creation.

`POST /runs` is the one endpoint whose cost leaves the deployment: every call
reserves provider spend. `max_steps` and `max_tokens` bound a single run, so
without a limiter a client holding one valid token can create runs as fast as
it can loop, and only OmniRoute's quota notices (LLM10, #256).

The budget is a token bucket per `(tenant, user)`, not per tenant: the loop
being defended against is one credential, and a tenant-wide bucket would let a
single noisy user starve their colleagues. The trade is that a tenant's ceiling
scales with its user count, which is the right side to err on while one tenant
is the norm (assumption A3 in `docs/security/citadel-threat-model.md`).

The state is in-process. That is correct for the single `api` container
`compose.yaml` defines and wrong the moment a second replica exists: each one
would allow the full rate. A shared store is the change to make then.
"""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

DEFAULT_RUNS_PER_MINUTE: Final = 30
SECONDS_PER_MINUTE: Final = 60.0


def runs_per_minute() -> int:
    """The configured allowance, or the default when it is unset or unusable.

    A limiter that cannot read its own number falls back to the default rate
    rather than to zero: a typo must not take run creation down, which is the
    opposite of a docs flag that has to fail closed.
    """
    raw = os.environ.get("CITADEL_RUNS_PER_MINUTE", "").strip()
    if not raw:
        return DEFAULT_RUNS_PER_MINUTE
    try:
        allowance = int(raw)
    except ValueError:
        return DEFAULT_RUNS_PER_MINUTE
    return allowance if allowance > 0 else DEFAULT_RUNS_PER_MINUTE


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RunBudget:
    """A token bucket per principal. One token is one run."""

    def __init__(self, per_minute: int, *, clock: Callable[[], float] = time.monotonic) -> None:
        if per_minute < 1:
            raise ValueError("a run budget needs at least one run per minute")
        self._rate = per_minute / SECONDS_PER_MINUTE
        self._capacity = float(per_minute)
        self._clock = clock
        self._buckets: dict[tuple[str, str], _Bucket] = {}
        self._lock = threading.Lock()

    def take(self, tenant_id: str, user_id: str) -> float | None:
        """Charge one run.

        Returns None when the run may proceed, otherwise the seconds until a
        token is available. The caller decides how to refuse; this only counts.
        """
        key = (tenant_id, user_id)
        with self._lock:
            now = self._clock()
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = _Bucket(tokens=self._capacity, updated=now)
                self._buckets[key] = bucket
            else:
                # A full bucket is the burst allowance: unused tokens do not
                # accumulate past it, so an idle client cannot bank a spike.
                elapsed = max(now - bucket.updated, 0.0)
                bucket.tokens = min(self._capacity, bucket.tokens + elapsed * self._rate)
                bucket.updated = now
            if bucket.tokens >= 1.0:
                bucket.tokens -= 1.0
                return None
            return (1.0 - bucket.tokens) / self._rate
