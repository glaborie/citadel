"""Hash-pinned skill packs: documentation the model may read, never authority.

ADR-011. A pack is a directory under `skills/` with an index (`SKILL.md`),
optional references, and a `manifest.json` that pins the SHA-256 of every file.
Loading recomputes the hashes, so a pack that changed on disk without a version
bump is refused instead of served, and a file the manifest does not list cannot
be loaded at all. Manifest names are contained to the pack folder and symlinks
are refused outright: a pack is a closed artefact, so nothing in it may point
at content elsewhere on disk.

Nothing here can grant a tool. Permissions live in `policy/tools.json` and
OpenFGA, and the loop still asks `authorize` for every call; the pack is text
that becomes a system message, and system messages are DLP-gated like prompts.
"""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import Any

MANIFEST = "manifest.json"
INDEX = "SKILL.md"
# A pack directory name comes from a request, so it is matched, never joined into
# a path: load_pack finds the directory on disk and uses the name for equality only.
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
    # An acting pack: its tasks are done by calling a tool, so an answer with no
    # tool observation is a plan. The flag can only tighten a run - it grants
    # nothing - so it stays documentation, not authority.
    requires_tool: bool = False

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


def _pack_directory(root: Path, agent: str) -> Path:
    """Pick the pack directory off the listing of `root`, never out of the request.

    `agent` arrives from a request body, so the old `root / agent` join put
    attacker-shaped data in a path expression (code scanning alert #66): the
    regex and the containment check made it safe, but the taint stayed. Matching
    a real entry instead uses the request value only for equality, so no path is
    ever built from it.
    """
    try:
        entries = list(root.iterdir())
    except OSError as exc:
        raise SkillPackMissing(f"no skill pack for agent {agent!r} in {root}") from exc
    for entry in entries:
        if entry.name == agent:
            return _contained_pack(entry, root, agent)
    raise SkillPackMissing(f"no skill pack for agent {agent!r} in {root}")


def _contained_pack(entry: Path, root: Path, agent: str) -> Path:
    """The real directory behind a matched entry: no links, no escape from the root.

    A symlink named like a pack is refused the way `write_manifests` refuses one,
    and the containment check stays even after `resolve`, because a link could be
    swapped in between the listing and the open.
    """
    if entry.is_symlink():
        raise SkillPackError(f"{entry} is a symlink; packs must be real directories")
    if not entry.is_dir():
        raise SkillPackMissing(f"no skill pack for agent {agent!r} in {root}")
    folder = entry.resolve()
    try:
        folder.relative_to(root)
    except ValueError as exc:
        raise SkillPackMissing(f"no skill pack for agent {agent!r}") from exc
    return folder


def load_pack(agent: str, directory: Path | None = None) -> SkillPack:
    """Load one agent's pack, or refuse. Never returns unverified text."""
    if not AGENT_NAME.match(agent):
        raise SkillPackMissing(f"no skill pack for agent {agent!r}")
    root = (skills_root() if directory is None else directory).resolve()
    folder = _pack_directory(root, agent)
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
        requires_tool=manifest.get("requires_tool", False),
    )


def write_manifests(root: Path | None = None) -> list[Path]:
    """Re-hash each pack from disk. Bump `version` and `pack` in the same change."""
    base = skills_root() if root is None else root
    written: list[Path] = []
    for folder in sorted(path for path in base.iterdir() if path.is_dir()):
        if folder.is_symlink():
            raise SkillPackError(f"{folder} is a symlink; packs must be real directories")
        path = folder / MANIFEST
        if path.is_symlink():
            raise SkillPackError(f"{path} is a symlink; refusing to lock through it")
        current = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        manifest = {
            "agent": folder.name,
            "pack": current.get("pack", f"{folder.name}-1.0.0"),
            "version": current.get("version", "1.0.0"),
            "requires_tool": current.get("requires_tool", False),
            "files": {
                name: f"sha256:{_digest(_read_nofollow(folder / name))}"
                for name in sorted(_files(folder))
            },
        }
        path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


def _manifest(folder: Path, agent: str) -> dict[str, Any]:
    path = folder / MANIFEST
    if path.is_symlink():
        # A link here would let the whole pin set come from outside the pack.
        raise SkillPackError(f"{path} is a symlink; the manifest must be a real file")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SkillPackError(f"{path} is unreadable: {exc}") from exc
    return _check_manifest(raw, path, agent)


def _check_manifest(raw: Any, path: Path, agent: str) -> dict[str, Any]:
    """The manifest contract: identity, string pack/version, boolean flag, pinned index."""
    if not isinstance(raw, dict):
        raise SkillPackError(f"{path} is not an object")
    if raw.get("agent") != agent:
        # A pack may not claim another agent's identity.
        raise SkillPackError(f"{path} declares agent {raw.get('agent')!r}, not {agent!r}")
    for key in ("pack", "version"):
        if not isinstance(raw.get(key), str) or not raw[key]:
            raise SkillPackError(f"{path} has no {key}")
    # `"requires_tool": "false"` is truthy; the type is part of the contract.
    if not isinstance(raw.get("requires_tool", False), bool):
        raise SkillPackError(f"{path} has a non-boolean requires_tool")
    files = raw.get("files")
    if not isinstance(files, dict) or INDEX not in files:
        raise SkillPackError(f"{path} does not pin {INDEX}")
    return raw


def _verified(folder: Path, name: str, expected: str) -> str:
    path = _pinned_path(folder, name)
    try:
        data = _read_nofollow(path)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise SkillPackError(f"{name} reads through a symlink") from exc
        raise SkillPackError(f"{name} is pinned but missing from {folder}") from exc
    if expected != f"sha256:{_digest(data)}":
        raise SkillPackError(f"{name} does not match its pinned hash; bump the pack version")
    return data.decode("utf-8")


def _pinned_path(folder: Path, name: str) -> Path:
    """The real path a manifest key may name, refusing escapes and links.

    A manifest key is data, not a path: an absolute, `..` or empty name is
    refused, no component below the folder may be a symlink, and the resolved
    file must stay inside the pack (issue #242) - a link would let the pack
    read content it does not pin, from anywhere the link points.
    """
    relative = PurePosixPath(name)
    if not name or not relative.parts:
        raise SkillPackError(f"manifest name {name!r} names no file inside the pack")
    if relative.is_absolute() or ".." in relative.parts:
        raise SkillPackError(f"manifest name {name!r} is not a plain relative path")
    if "\x00" in name:
        raise SkillPackError(f"manifest name {name!r} contains a NUL byte")
    _refuse_links(folder, name)
    path = folder / name
    try:
        path.resolve().relative_to(folder.resolve())
    except ValueError as exc:
        raise SkillPackError(f"manifest name {name!r} escapes the pack folder") from exc
    return path


def _refuse_links(folder: Path, name: str) -> None:
    """No component of the pinned name may be a symlink, final or mid-path."""
    current = folder.resolve()
    for part in PurePosixPath(name).parts:
        current = current / part
        if current.is_symlink():
            raise SkillPackError(f"manifest name {name!r} reads through a symlink")


def _read_nofollow(path: Path) -> bytes:
    """Read a file without following a last-component symlink, where available.

    The component walk in `_pinned_path` closes the manifest holes; this closes
    the gap between that check and the open on platforms with `O_NOFOLLOW`.
    """
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        return handle.read()


def _refuse_unpinned(folder: Path, pinned: Mapping[str, str]) -> None:
    extra = _files(folder) - set(pinned)
    if extra:
        raise SkillPackError(f"{folder} contains unpinned files: {sorted(extra)}")


def _files(folder: Path) -> set[str]:
    """Every file in the pack, relative to it, with any symlink refused.

    `rglob` skipped links silently: a symlinked directory hid unpinned files
    from this enumeration, and a symlinked file got pinned to whatever its
    target held when the pack was locked (issue #242). A link is an error
    wherever it sits, even if it points back inside the pack.
    """

    def _unreadable(error: OSError) -> None:
        raise SkillPackError(f"{folder} is not fully walkable: {error}")

    names: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(folder, followlinks=False, onerror=_unreadable):
        here = Path(dirpath)
        for entry in dirnames:
            if (here / entry).is_symlink():
                raise SkillPackError(f"{folder} contains a symlinked directory: {here / entry}")
        for entry in filenames:
            path = here / entry
            if path.is_symlink():
                raise SkillPackError(f"{folder} contains a symlinked file: {path}")
            if entry != MANIFEST:
                names.add(path.relative_to(folder).as_posix())
    return names


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


if __name__ == "__main__":  # pragma: no cover - developer tool
    for written in write_manifests():
        print(written)
