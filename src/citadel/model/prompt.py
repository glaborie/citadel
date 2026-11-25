"""The system prompt a specialist run starts with.

Two sources, both already authoritative somewhere else: the agent's
hash-verified skill pack (documentation, ADR-011) and the tool catalog (the only
list of tools that exist). Assembling them here does not grant anything — every
requested call still goes through `authorize`.

Every reference in the pack is included. The pack is the unit of disclosure: an
agent gets its own pack and never another's, and there is no retrieval path by
which a model could ask for one more reference mid-run.
"""

from __future__ import annotations

from typing import Any

from citadel.policy import load_catalog
from citadel.policy.catalog import ToolSpec
from citadel.skills import load_pack


def tool_schemas(agent: str) -> list[dict[str, Any]]:
    """OpenAI function schemas for exactly the tools this agent may request."""
    catalog = load_catalog()
    return [_schema(spec) for _, spec in sorted(catalog.items()) if spec.agent == agent]


def system_prompt(agent: str) -> str:
    """Pack index, its references, and the tool manifest the model may call."""
    pack = load_pack(agent)
    catalog = load_catalog()
    mine = [spec for _, spec in sorted(catalog.items()) if spec.agent == agent]
    tools = "\n".join(f"- `{spec.name}` ({spec.tier})" for spec in mine)
    references = "\n\n".join(pack.references[name] for name in sorted(pack.references))
    return (
        f"{pack.index}\n\n"
        f"{references}\n\n"
        "## Tools you may request\n\n"
        f"{tools}\n\n"
        "Requesting a tool is a proposal: policy decides, and a T1 call waits for "
        "a human. A tool that is not in this list does not exist."
    )


def _schema(spec: ToolSpec) -> dict[str, Any]:
    properties = {
        param.name: {"type": "string", "maxLength": param.max_length} for param in spec.params
    }
    return {
        "type": "function",
        "function": {
            "name": spec.name,
            "description": f"{spec.tier} tool for the {spec.agent} specialist",
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": [param.name for param in spec.params if param.required],
                "additionalProperties": False,
            },
        },
    }
