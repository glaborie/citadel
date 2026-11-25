"""The system prompt: the agent's pack plus exactly the tools it may request."""

from __future__ import annotations

from citadel.model.prompt import system_prompt, tool_schemas
from citadel.policy import load_catalog


def test_the_prompt_carries_the_pack_and_its_references() -> None:
    text = system_prompt("docker")
    assert text.startswith("# Docker specialist")
    assert "Restart playbook" in text, "references travel with the pack"


def test_the_prompt_names_only_this_agent_s_tools() -> None:
    text = system_prompt("docker")
    assert "`restart_service` (T1)" in text
    assert "`inspect_containers` (T0)" in text
    assert "`open_remediation_pr`" not in text


def test_tool_schemas_are_derived_from_the_catalog() -> None:
    catalog = load_catalog()
    schemas = tool_schemas("github")
    names = {schema["function"]["name"] for schema in schemas}

    assert names == {name for name, spec in catalog.items() if spec.agent == "github"}
    restart = next(
        schema
        for schema in tool_schemas("docker")
        if schema["function"]["name"] == "restart_service"
    )
    parameters = restart["function"]["parameters"]
    assert parameters["required"] == ["service"]
    assert parameters["additionalProperties"] is False


def test_an_agent_without_a_pack_gets_no_prompt() -> None:
    import pytest

    from citadel.skills import SkillPackMissing

    with pytest.raises(SkillPackMissing):
        system_prompt("nobody")
