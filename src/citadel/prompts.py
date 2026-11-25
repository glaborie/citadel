"""Prompt assembly: the pack's text, and only the tools the agent may ask for.

A prompt is a provenance record as much as an instruction. The digest it returns
is what a trajectory cites, so two runs that claim the same pack can be compared
without storing the text twice - and a run whose pack version disagrees with what
is on disk is refused rather than quietly upgraded.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from citadel.policy.catalog import load_catalog
from citadel.skills import SkillPack, load_pack

GUIDE = """You are the {agent} agent inside Citadel.

How this works:
- You may request one tool per turn by name. The platform authorises every call
  against policy, so a refusal is an answer you have to work with, not an
  obstacle to route around.
- If a task needs something you do not have, say so plainly instead of guessing.
- Answer in the user's language, in prose, and name what you used."""


@dataclass(frozen=True)
class Prompt:
    system: str
    task: str
    pack: str
    version: str
    tools: tuple[dict[str, Any], ...]
    digest: str

    @property
    def pack_id(self) -> str:
        """What a run records as `prompt_pack_version`: the pack's own name.

        `docker-1.0.0`, not `docker-1.0.0@1.0.0`. The name already carries the
        version, `POST /runs` validates the request against `SkillPack.name`, and
        every recorded run and eval fixture uses that form; a second spelling
        made every submitted run fail its own provenance check.
        """
        return self.pack

    def messages(self) -> list[dict[str, str]]:
        return [
            {"role": "system", "content": self.system},
            {"role": "user", "content": self.task},
        ]


def tool_manifest(agent: str) -> tuple[dict[str, Any], ...]:
    """The agent's tools, by name, with the parameters policy will accept."""
    catalog = load_catalog()
    return tuple(
        {
            "name": spec.name,
            "tier": spec.tier,
            "parameters": [
                {"name": param.name, "kind": param.kind, "required": param.required}
                for param in spec.params
            ],
        }
        for spec in sorted(catalog.values(), key=lambda item: item.name)
        if spec.agent == agent
    )


def _digest(*parts: Any) -> str:
    canonical = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def assemble(
    agent: str,
    task: str,
    *,
    pack: SkillPack | None = None,
    references: Sequence[str] = (),
    tools: Sequence[dict[str, Any]] | None = None,
) -> Prompt:
    """Assemble one prompt. `references` is the progressive-disclosure part."""
    loaded = pack if pack is not None else load_pack(agent)
    manifest = tuple(tools) if tools is not None else tool_manifest(agent)
    system = "\n\n".join([GUIDE.format(agent=agent), loaded.prompt(*references)])
    return Prompt(
        system=system,
        task=task,
        pack=loaded.name,
        version=loaded.version,
        tools=manifest,
        digest=_digest(system, task, loaded.name, loaded.version, list(manifest)),
    )
