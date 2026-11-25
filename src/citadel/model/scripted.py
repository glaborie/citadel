"""A model double for the cases that must not spend money or need a provider.

A scripted reply is data. The cases that use it assert on the loop's behaviour —
what gets authorised, what gets executed, when the budget stops the run — which
is the part a real model cannot make deterministic.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from citadel.model.types import Reply


class ScriptedClient:
    """Returns the replies it was given, in order, and refuses to improvise."""

    def __init__(self, replies: Sequence[Reply]) -> None:
        self._replies = list(replies)
        self.calls = 0

    def complete(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]] = (),
        alias: str | None = None,
        run_id: str = "",
    ) -> Reply:
        self.calls += 1
        if not self._replies:
            raise AssertionError("scripted model ran out of replies")
        return self._replies.pop(0)
