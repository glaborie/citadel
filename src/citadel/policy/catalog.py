"""Tool catalog loading. A tool absent from the catalog can never be authorised."""

from __future__ import annotations

import json
from dataclasses import dataclass
from importlib import resources
from typing import Any


@dataclass(frozen=True)
class Param:
    name: str
    kind: str  # positional | flag
    flag: str | None = None
    required: bool = False
    max_length: int = 64


@dataclass(frozen=True)
class ToolSpec:
    name: str
    tier: str
    agent: str
    command: str | None = None
    params: tuple[Param, ...] = ()


def _param(raw: dict[str, Any]) -> Param:
    return Param(
        name=raw["name"],
        kind=raw.get("in", "positional"),
        flag=raw.get("flag"),
        required=bool(raw.get("required", False)),
        max_length=int(raw.get("max_length", 64)),
    )


def load_catalog() -> dict[str, ToolSpec]:
    raw: dict[str, Any] = json.loads(
        resources.files("citadel.policy").joinpath("tools.json").read_text(encoding="utf-8")
    )
    return {
        name: ToolSpec(
            name=name,
            tier=spec["tier"],
            agent=spec["agent"],
            command=spec.get("command"),
            params=tuple(_param(p) for p in spec.get("params", [])),
        )
        for name, spec in raw["tools"].items()
    }
