"""Prompt assembly: provenance, and only the tools the agent may ask for."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from citadel.policy.catalog import load_catalog
from citadel.prompts import assemble, tool_manifest
from citadel.skills import load_pack

ROOT = Path(__file__).parents[1] / "skills"


def test_the_manifest_lists_only_this_agents_tools() -> None:
    manifest = tool_manifest("docker")
    catalog = load_catalog()

    names = {entry["name"] for entry in manifest}
    assert names == {name for name, spec in catalog.items() if spec.agent == "docker"}
    assert "restart_service" in names, "the docker agent's T1 tool must be visible to it"
    assert "open_remediation_pr" not in names, "another agent's tool leaked into the manifest"


def test_the_manifest_carries_the_parameters_policy_will_accept() -> None:
    entry = next(item for item in tool_manifest("github") if item["name"] == "open_remediation_pr")

    assert entry["tier"] == "T1"
    described = {param["name"] for param in entry["parameters"]}
    assert described, "a tool with no parameters cannot be called correctly"
    assert all(isinstance(param["required"], bool) for param in entry["parameters"])


def test_the_prompt_carries_the_pack_text_and_the_task() -> None:
    pack = load_pack("docker", ROOT)
    prompt = assemble("docker", "why is checkout-api restarting?", pack=pack)

    assert pack.index in prompt.system
    assert prompt.task == "why is checkout-api restarting?"
    assert prompt.pack_id == f"{pack.name}@{pack.version}"
    messages = prompt.messages()
    assert [message["role"] for message in messages] == ["system", "user"]
    assert messages[1]["content"] == prompt.task


def test_references_are_pulled_in_only_when_asked_for() -> None:
    pack = load_pack("docker", ROOT)
    wanted = sorted(pack.references)[0]

    without = assemble("docker", "task", pack=pack)
    with_reference = assemble("docker", "task", pack=pack, references=[wanted])

    assert pack.references[wanted] not in without.system
    assert pack.references[wanted] in with_reference.system


def test_the_digest_changes_when_the_prompt_does() -> None:
    pack = load_pack("docker", ROOT)
    base = assemble("docker", "task one", pack=pack)
    other_task = assemble("docker", "task two", pack=pack)
    wanted = sorted(pack.references)[0]
    more_context = assemble("docker", "task one", pack=pack, references=[wanted])

    assert base.digest != other_task.digest
    assert base.digest != more_context.digest
    assert base.digest == assemble("docker", "task one", pack=pack).digest


def test_the_digest_is_a_sha256_over_canonical_parts() -> None:
    pack = load_pack("docker", ROOT)
    prompt = assemble("docker", "task", pack=pack)
    canonical = json.dumps(
        [prompt.system, prompt.task, prompt.pack, prompt.version, list(prompt.tools)],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )

    assert prompt.digest == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
