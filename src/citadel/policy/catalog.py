"""Tool catalog loading. A tool absent from the catalog can never be authorised."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: str
    agent: str


def load_catalog() -> dict[str, ToolSpec]:
    raw: dict[str, Any] = json.loads(
        resources.files("citadel.policy").joinpath("tools.json").read_text(encoding="utf-8")
    )
    return {
        name: ToolSpec(name=name, tier=spec["tier"], agent=spec["agent"])
        for name, spec in raw["tools"].items()
    }
