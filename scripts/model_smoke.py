"""One real completion through OmniRoute, with the prompt gated by Presidio.

This is the only place the runtime talks to a provider, so it is the only place
a smoke test can be honest about cost. It exercises three things and prints
what came back:

* the prompt passes (or is blocked by) the live detector before egress;
* the gateway answers with a tool call and reports tokens and cost;
* the loop enforces the budget it was given.

Policy is deliberately a stub here. Authorisation is covered by the unit and
red-team suites, which must not need a provider to run.

Run it inside the compose network, where both services are reachable:

    make model-smoke
"""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Mapping
from typing import Any

from citadel import dlp
from citadel.model import Budget, OmniRouteClient, run_agent
from citadel.policy import Decision

ALLOWED = "inspect_containers"


def authorize_tool(tool: str) -> Decision:
    """Smoke-only: allow the read tool, deny everything else."""
    if tool == ALLOWED:
        return Decision(outcome="allow", rule_id="policy.allowed", reason="smoke", tier="T0")
    return Decision(outcome="deny", rule_id="tool.unknown", reason="smoke denies", tier="unknown")


def main() -> int:
    alias = os.environ.get("MODEL_ALIAS_FAST", "auto/best-fast")
    client = OmniRouteClient(
        base_url=os.environ["OMNIROUTE_URL"],
        api_key=os.environ["OMNIROUTE_API_KEY"],
        analyzer_url=os.environ["CITADEL_DLP_URL"],
        alias=alias,
    )

    def execute(name: str, arguments: Mapping[str, Any]) -> str:
        return "citadel-api running, citadel-postgres healthy, checkout-api running"

    def gate(text: str, surface: str) -> str:
        return dlp.gate(
            text, surface=surface, analyzer_url=os.environ["CITADEL_DLP_URL"]
        )[0]

    trajectory = run_agent(
        complete=client.complete,
        messages=[
            {
                "role": "user",
                "content": "Which containers are running? Use the inspect_containers tool.",
            }
        ],
        tools=[
            {
                "type": "function",
                "function": {
                    "name": "inspect_containers",
                    "description": "List running containers",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }
        ],
        authorize=authorize_tool,
        execute=execute,
        gate=gate,
        budget=Budget(max_steps=3, max_tokens=4000, max_cost_usd=0.01),
    )

    print(json.dumps({"alias": alias, **trajectory.summary()}, indent=2))
    print(trajectory.text[:200])
    return 0 if trajectory.usage.total else 1


if __name__ == "__main__":
    sys.exit(main())
