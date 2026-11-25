"""Secrets from a mounted file, not from the container environment.

The Docker API exposes every container's environment to anything that can reach
the socket proxy, so a secret in `Config.Env` is readable by the sandbox. A
Compose secret is mounted as a file and named by `<NAME>_FILE`; the bare
variable stays as the local-development fallback.
"""

from __future__ import annotations

import os
from pathlib import Path


def secret(name: str) -> str:
    """Return the value named by `<NAME>_FILE`, else `NAME`, else fail."""
    path = os.environ.get(f"{name}_FILE")
    if path:
        return Path(path).read_text(encoding="ascii").strip()
    value = os.environ.get(name)
    if not value:
        raise KeyError(name)
    return value
