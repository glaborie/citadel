"""Workflow hardening: the token floor and the hashed install CodeQL flagged (#40, #41)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
REQUIREMENTS = ROOT / ".github" / "requirements-smellcheck.txt"
COMMIT_SHA = re.compile(r"@[0-9a-f]{40}$")
HASH = re.compile(r"--hash=sha256:([0-9a-f]{64})")


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_every_workflow_declares_a_read_only_floor() -> None:
    """#40: a workflow with no top-level permissions inherits the repository default."""
    missing = [
        path.name for path in WORKFLOWS if not re.search(r"^permissions:", _text(path), re.M)
    ]
    assert not missing, f"no top-level permissions block: {missing}"


def test_every_action_is_pinned_to_a_commit() -> None:
    """A mutable tag is a supply-chain dependency on whatever the tag points at today."""
    unpinned: list[str] = []
    for path in WORKFLOWS:
        for line in _text(path).splitlines():
            if "uses:" not in line or line.lstrip().startswith("#"):
                continue
            reference = line.split("uses:", 1)[1].strip().split()[0]
            if reference.startswith("./"):  # a local action is this repository
                continue
            if not COMMIT_SHA.search(reference):
                unpinned.append(f"{path.name}: {reference}")
    assert not unpinned, f"actions not pinned to a 40-character SHA: {unpinned}"


def test_the_smell_job_cannot_write_anything() -> None:
    """The job reads source and fails on findings; nothing in it writes to GitHub."""
    text = _text(ROOT / ".github" / "workflows" / "smellcheck.yml")

    assert text.count("permissions:") == 1, "a job-level block could widen the floor"
    block = text.split("permissions:", 1)[1].split("\njobs:", 1)[0]
    assert "contents: read" in block
    assert ": write" not in block


def _logical_requirements(text: str) -> list[str]:
    """One entry per requirement: backslash continuations joined, comments dropped.

    Hash-pinned requirements are written across lines - the pin on the first, the
    digests indented under it - so a line-by-line parser sees a requirement with no
    hash and calls it a failure.
    """
    return [
        line.strip()
        for line in text.replace("\\\n", " ").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def test_the_smell_gate_installs_from_hashes() -> None:
    """#41: `pip install smellcheck` ran whatever PyPI served next, by name."""
    text = _text(ROOT / ".github" / "workflows" / "smellcheck.yml")

    installs = [line for line in text.splitlines() if re.search(r"\bpip[0-9]* install\b", line)]
    assert installs, "the workflow no longer installs anything; this test is asleep"
    for line in installs:
        assert "--require-hashes" in line, f"unhashed install: {line.strip()}"
        assert "requirements-smellcheck.txt" in line

    pins = _logical_requirements(_text(REQUIREMENTS))
    assert pins, "the requirements file pins nothing"
    for line in pins:
        assert "==" in line, f"not pinned to a version: {line}"
        assert HASH.search(line), f"no sha256 hash: {line}"


def test_the_local_gate_runs_the_pinned_version() -> None:
    """`make check` judging with a newer release than CI is a green that means less.

    `make -n` evaluates the `$(shell ...)` that reads the requirements file without
    running anything, so a broken extraction fails here rather than at the install step.
    """
    pinned = re.search(r"^smellcheck==([0-9][0-9.]*)", _text(REQUIREMENTS), re.MULTILINE)
    assert pinned is not None, "requirements-smellcheck.txt pins no version"

    printed = subprocess.run(
        ["make", "-n", "check"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout
    smell_lines = [line for line in printed.splitlines() if "uvx smellcheck" in line]
    assert smell_lines, "make check no longer runs the smell gate"
    assert f"smellcheck=={pinned.group(1)} " in smell_lines[0], smell_lines[0]
