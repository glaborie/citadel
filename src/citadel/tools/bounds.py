"""Bounded tool output: the head, the tail, and proof of what was cut.

A tool may answer with anything up to its transport cap. Two things must not
happen to that text: a secret must not be missed because it sat past a clip
point, and a run's history must not grow with the size of a log file.

The order is therefore scan-then-bound, never bound-then-scan. Clipping first
would hand the detector a shorter, cleaner string and call it a pass - the one
mistake that makes an output control look enforced while the tail goes
unexamined. Once the full text has been judged, the bound keeps its head and
its tail (the end of a traceback is where the diagnosis is) and a digest of the
whole thing, so the part nobody can see is still provable.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

# Transport cap: what the sandbox will hand back at all.
DEFAULT_OUTPUT_LIMIT = 64_000
# History cap: what one call may add to a run's event history.
DEFAULT_EVENT_LIMIT = 8_192
# A quarter of the budget goes to the tail; the head keeps the rest.
_TAIL_SHARE = 4


@dataclass(frozen=True)
class Bounded:
    """Text that fits a budget, with the digest of the text it came from."""

    text: str
    sha256: str
    original_bytes: int
    kept_bytes: int

    @property
    def truncated(self) -> bool:
        return self.original_bytes > self.kept_bytes

    @property
    def omitted_bytes(self) -> int:
        return max(0, self.original_bytes - self.kept_bytes)


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _marker(total: int, omitted: int, full_digest: str) -> str:
    return f"\n[... {omitted} of {total} bytes omitted, sha256={full_digest} ...]\n"


def bound(text: str, *, limit: int = DEFAULT_OUTPUT_LIMIT) -> Bounded:
    """Keep at most `limit` bytes, preserving the head and the tail.

    The returned text never exceeds the limit: the marker is charged against the
    head's budget, and a last pass trims the head if replacement characters
    pushed the encoding back over it.
    """
    raw = text.encode("utf-8", errors="replace")
    full_digest = hashlib.sha256(raw).hexdigest()
    if len(raw) <= limit:
        return Bounded(text=text, sha256=full_digest, original_bytes=len(raw), kept_bytes=len(raw))

    tail_budget = max(0, limit // _TAIL_SHARE)
    marker = _marker(len(raw), len(raw) - limit, full_digest)
    head_budget = limit - tail_budget - len(marker.encode("utf-8"))
    if head_budget <= 0:
        # No room for a marker and both ends. Clip the head; the digest is still
        # on the object, which is where a caller reads it anyway.
        clipped = raw[:limit].decode("utf-8", errors="replace")
        while len(clipped.encode("utf-8")) > limit and clipped:
            clipped = clipped[:-1]
        return Bounded(
            text=clipped,
            sha256=full_digest,
            original_bytes=len(raw),
            kept_bytes=len(clipped.encode("utf-8")),
        )

    while True:
        head = raw[:head_budget].decode("utf-8", errors="replace")
        # A zero tail budget lands the slice at the end of the buffer: empty.
        tail = raw[max(0, len(raw) - tail_budget) :].decode("utf-8", errors="replace")
        candidate = head + marker + tail
        encoded = candidate.encode("utf-8")
        if len(encoded) <= limit or head_budget == 0:
            break
        head_budget = max(0, head_budget - 32)

    return Bounded(
        text=candidate,
        sha256=full_digest,
        original_bytes=len(raw),
        kept_bytes=len(encoded),
    )
