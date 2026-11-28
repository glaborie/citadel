"""Issue #280: `make up` must not go green while a healthchecked service is down.

`docker compose up -d` returns 0 as soon as the containers exist. A service whose
healthcheck never passes — the reranker OOM in #269 is the recorded example —
left a half-up stack behind a green `make up`, and the failure only appeared on
the first run.
"""

from __future__ import annotations

import re
from pathlib import Path

MAKEFILE = Path(__file__).parents[1] / "Makefile"


def _recipe(target: str) -> str:
    body = MAKEFILE.read_text(encoding="utf-8")
    match = re.search(rf"^{re.escape(target)}:.*?(?=^\S|\Z)", body, re.MULTILINE | re.DOTALL)
    assert match is not None, f"no {target} target in the Makefile"
    return match.group(0)


def test_up_waits_for_health() -> None:
    recipe = _recipe("up")

    assert "docker compose up -d --wait" in recipe
    assert "--wait-timeout" in recipe, "an unbounded wait can hang CI forever"


def test_rebuild_waits_for_health() -> None:
    recipe = _recipe("rebuild")

    assert "docker compose up -d --wait" in recipe
    assert "--wait-timeout" in recipe


def test_no_target_starts_the_stack_without_waiting() -> None:
    """Any other `up -d` added later would reopen the same silent half-up."""
    offenders = [
        line.strip()
        for line in MAKEFILE.read_text(encoding="utf-8").splitlines()
        if "compose up -d" in line and "--wait" not in line
    ]

    assert not offenders, f"a target still starts the stack without --wait: {offenders}"


def test_up_and_rebuild_end_with_the_drift_gate() -> None:
    """#296: the live case is the only proof of the verdict path, so run it here."""
    for target in ("up", "rebuild"):
        recipe = _recipe(target)

        assert "bash scripts/post-deploy-check.sh" in recipe, (
            f"`make {target}` leaves the stack up without proving the drift verdict path"
        )
        assert recipe.rstrip().endswith("bash scripts/post-deploy-check.sh"), (
            f"`make {target}` has to run the gate last, once the stack is up"
        )


def test_the_gate_runs_the_live_case() -> None:
    script = (Path(__file__).parents[1] / "scripts" / "post-deploy-check.sh").read_text(
        encoding="utf-8"
    )

    assert "CITADEL_LIVE_TESTS=1" in script, "the case skips itself without the opt-in"
    assert "tests/test_policy_drift_live.py" in script
    assert "exit 1" in script, "a failed gate has to fail the make target"
