"""Canonical hashing shared by approval tokens and trajectory events."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


def arguments_hash(arguments: Mapping[str, Any]) -> str:
    body = json.dumps(arguments, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode("utf-8")).hexdigest()
