"""The two digests a cache partition is keyed on.

`policy_version` is the model OpenFGA actually loads: changing an allow/deny
relation changes the digest, so no entry from the old model can be served.
`tool_context_version` is the tool catalog the prompt pack is assembled from:
changing an allowlisted tool, its tier or its arguments changes the digest.

Computing them from files instead of a hand-bumped string means a policy change
cannot be forgotten at deploy time. The path candidates cover the repository and
the image (`/app/policy`); if neither is readable the caller treats the cache as
unavailable rather than inventing a version.
"""

from __future__ import annotations

import hashlib
import os
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Final

POLICY_MODEL: Final = "/app/policy/model.json"


class VersionUnavailable(RuntimeError):
    """The versioned artefact cannot be read, so a partition key is unsafe."""


@lru_cache(maxsize=1)
def policy_version() -> str:
    path = _policy_model_path()
    try:
        material = path.read_bytes()
    except OSError as exc:
        raise VersionUnavailable(f"policy model unreadable: {path}") from exc
    return "sha256:" + hashlib.sha256(material).hexdigest()


@lru_cache(maxsize=1)
def tool_context_version() -> str:
    try:
        material = resources.files("citadel.policy").joinpath("tools.json").read_bytes()
    except OSError as exc:
        raise VersionUnavailable("tool catalog unreadable") from exc
    return "sha256:" + hashlib.sha256(material).hexdigest()


def _policy_model_path() -> Path:
    candidates = [
        os.environ.get("CITADEL_POLICY_MODEL", ""),
        POLICY_MODEL,
        str(Path(__file__).resolve().parents[3] / "policy" / "model.json"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file():
            return path
    raise VersionUnavailable("no policy model file found")
