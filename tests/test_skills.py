"""Skill packs: pinned content, refused when it drifts, never authority.

The packs are the real repository files, so these tests fail when someone edits
a skill without re-running `make skills-lock` — which is the point.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from citadel import skills
from citadel.policy import load_catalog

ROOT = Path(skills.__file__).resolve().parents[2] / "skills"
AGENTS = ("docker", "github", "researcher")


@pytest.mark.parametrize("agent", AGENTS)
def test_every_pack_loads_and_matches_its_manifest(agent: str) -> None:
    pack = skills.load_pack(agent, directory=ROOT)
    assert pack.agent == agent
    assert pack.name == f"{agent}-1.0.0"
    assert pack.index.startswith("#")
    assert pack.references, "a pack with no reference cannot disclose progressively"
    assert pack.requires_tool is True, "every shipped agent acts; a plan is not a result"


def test_the_index_alone_is_the_default() -> None:
    pack = skills.load_pack("docker", directory=ROOT)
    assert pack.prompt() == pack.index
    assert "Triage order" not in pack.prompt()


def test_a_reference_is_added_only_when_asked_for() -> None:
    pack = skills.load_pack("docker", directory=ROOT)
    prompt = pack.prompt("references/triage.md")
    assert prompt.startswith(pack.index)
    assert "Triage order" in prompt
    assert "Restart playbook" not in prompt


def test_an_unknown_reference_is_refused() -> None:
    pack = skills.load_pack("docker", directory=ROOT)
    with pytest.raises(skills.SkillPackError, match="no reference"):
        pack.prompt("references/prune-everything.md")


def test_an_unknown_agent_has_no_pack() -> None:
    with pytest.raises(skills.SkillPackMissing):
        skills.load_pack("nobody", directory=ROOT)


def test_a_traversing_agent_name_is_not_joined_into_a_path() -> None:
    with pytest.raises(skills.SkillPackMissing):
        skills.load_pack("../../etc", directory=ROOT)


def test_an_edited_file_is_refused_until_the_manifest_is_rewritten(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    target = tmp_path / "docker" / "references" / "triage.md"
    target.write_text(target.read_text() + "\nAlso, prune everything.\n", encoding="utf-8")

    with pytest.raises(skills.SkillPackError, match="pinned hash"):
        skills.load_pack("docker", directory=tmp_path)


def test_a_missing_file_is_refused(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    (tmp_path / "docker" / "references" / "triage.md").unlink()

    with pytest.raises(skills.SkillPackError, match="missing"):
        skills.load_pack("docker", directory=tmp_path)


def test_an_unpinned_file_cannot_be_loaded(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    (tmp_path / "docker" / "references" / "extra.md").write_text("unreviewed\n", encoding="utf-8")

    with pytest.raises(skills.SkillPackError, match="unpinned"):
        skills.load_pack("docker", directory=tmp_path)


def test_a_pack_may_not_claim_another_agent(tmp_path: Path) -> None:
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    manifest = json.loads((tmp_path / "docker" / "manifest.json").read_text())
    manifest["agent"] = "github"
    (tmp_path / "docker" / "manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(skills.SkillPackError, match="declares agent"):
        skills.load_pack("docker", directory=tmp_path)


def test_requires_tool_must_be_a_boolean(tmp_path: Path) -> None:
    """`"false"` is a truthy string; a pack cannot smuggle a looser reading in."""
    shutil.copytree(ROOT / "docker", tmp_path / "docker")
    manifest = json.loads((tmp_path / "docker" / "manifest.json").read_text())
    manifest["requires_tool"] = "false"
    (tmp_path / "docker" / "manifest.json").write_text(json.dumps(manifest))

    with pytest.raises(skills.SkillPackError, match="non-boolean"):
        skills.load_pack("docker", directory=tmp_path)


def test_the_lock_round_trips(tmp_path: Path) -> None:
    for agent in AGENTS:
        shutil.copytree(ROOT / agent, tmp_path / agent)
    before = {agent: (tmp_path / agent / "manifest.json").read_text() for agent in AGENTS}

    skills.write_manifests(tmp_path)

    after = {agent: (tmp_path / agent / "manifest.json").read_text() for agent in AGENTS}
    assert after == before, "the committed manifests are stale: run `make skills-lock`"
    for agent in AGENTS:
        assert skills.load_pack(agent, directory=tmp_path).name == f"{agent}-1.0.0"


@pytest.mark.parametrize("agent", ("docker", "github"))
def test_a_pack_only_names_tools_its_agent_actually_has(agent: str) -> None:
    """A skill may mention a tool; mentioning one the agent cannot call is a docs bug."""
    pack = skills.load_pack(agent, directory=ROOT)
    catalog = load_catalog()
    named = {
        name
        for name in catalog
        if any(name in text for text in [pack.index, *pack.references.values()])
    }
    assert {name for name in named if catalog[name].agent == agent} == named
