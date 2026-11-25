"""Hash-pinned skill packs: documentation the model may read, never authority.

ADR-011. A pack is a directory under `skills/` with an index (`SKILL.md`),
optional references, and a `manifest.json` that pins the SHA-256 of every file.
Loading recomputes the hashes, so a pack that changed on disk without a version
bump is refused instead of served, and a file the manifest does not list cannot
be loaded at all.

Nothing here can grant a tool. Permissions live in `policy/tools.json` and
OpenFGA, and the loop still asks `authorize` for every call; the pack is text
that becomes a system message, and system messages are DLP-gated like prompts.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

MANIFEST = "manifest.json"
INDEX = "SKILL.md"
# A pack directory name comes from a request, so it is matched, never joined blind.
AGENT_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")


class SkillPackError(RuntimeError):
    """A pack exists but cannot be trusted: bad manifest, hash or file set."""


class SkillPackMissing(SkillPackError):
    """No pack directory for this agent."""


@dataclass(frozen=True)
class SkillPack:
    agent: str
    name: str  # what a run records as prompt_pack_version
    version: str
    index: str
    references: Mapping[str, str]

    def prompt(self, *wanted: str) -> str:
        """Index plus only the references asked for: progressive disclosure."""
        missing = [name for name in wanted if name not in self.references]
        if missing:
            raise SkillPackError(
                f"pack {self.name} has no reference {missing[0]!r};"
                f" available: {sorted(self.references)}"
            )
        return "\n\n".join([self.index, *(self.references[name] for name in wanted)])


def skills_root() -> Path:
    return Path(os.environ.get("CITADEL_SKILLS_DIR", "skills"))


def load_pack(agent: str, directory: Path | None = None) -> SkillPack:
    """Load one agent's pack, or refuse. Never returns unverified text."""
    if not AGENT_NAME.match(agent):
        raise SkillPackMissing(f"no skill pack for agent {agent!r}")
    root = skills_root() if directory is None else directory
    folder = root / agent
    if not folder.is_dir():
        raise SkillPackMissing(f"no skill pack for agent {agent!r} in {root}")
    manifest = _manifest(folder, agent)

    references = MappingProxyType(
        {
            name: _verified(folder, name, digest)
            for name, digest in manifest["files"].items()
            if name != INDEX
        }
    )
    _refuse_unpinned(folder, manifest["files"])
    return SkillPack(
        agent=agent,
        name=manifest["pack"],
        version=manifest["version"],
        index=_verified(folder, INDEX, manifest["files"][INDEX]),
        references=references,
    )


def write_manifests(root: Path | None = None) -> list[Path]:
    """Re-hash each pack from disk. Bump `version` and `pack` in the same change."""
    base = skills_root() if root is None else root
    written: list[Path] = []
    for folder in sorted(path for path in base.iterdir() if path.is_dir()):
        path = folder / MANIFEST
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        manifest = {
            "agent": folder.name,
            "pack": current.get("pack", f"{folder.name}-1.0.0"),
            "version": current.get("version", "1.0.0"),
            "files": {
                name: f"sha256:{_digest((folder / name).read_bytes())}"
                for name in sorted(_files(folder))
            },
        }
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


def _manifest(folder: Path, agent: str) -> dict[str, Any]:
    path = folder / MANIFEST
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SkillPackError(f"{path} is unreadable: {exc}") from exc
    if not isinstance(raw, dict):
        raise SkillPackError(f"{path} is not an object")
    if raw.get("agent") != agent:
        # A pack may not claim another agent's identity.
        raise SkillPackError(f"{path} declares agent {raw.get('agent')!r}, not {agent!r}")
    for key in ("pack", "version"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise SkillPackError(f"{path} has no {key}")
    files = raw.get("files")
    if not isinstance(files, dict) or INDEX not in files:
        raise SkillPackError(f"{path} does not pin {INDEX}")
    return raw


def _verified(folder: Path, name: str, expected: str) -> str:
    path = folder / name
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise SkillPackError(f"{name} is pinned but missing from {folder}") from exc
    if expected != f"sha256:{_digest(data)}":
        raise SkillPackError(f"{name} does not match its pinned hash; bump the pack version")
    return data.decode("utf-8")


def _refuse_unpinned(folder: Path, pinned: Mapping[str, str]) -> None:
    extra = _files(folder) - set(pinned)
    if extra:
        raise SkillPackError(f"{folder} contains unpinned files: {sorted(extra)}")


def _files(folder: Path) -> set[str]:
    return {
        str(path.relative_to(folder)).replace(os.sep, "/")
        for path in folder.rglob("*")
        if path.is_file() and path.name != MANIFEST
    }


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":  # pragma: no cover - developer tool
    for written in write_manifests():
        print(written)
