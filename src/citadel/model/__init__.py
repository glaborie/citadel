"""The model in the loop: one client, one bounded loop, no SDK."""

from citadel.model.client import ModelUnavailable, OmniRouteClient
from citadel.model.loop import run_agent
from citadel.model.scripted import ScriptedClient
from citadel.model.types import Budget, Reply, RequestedTool, Step, Trajectory, Usage

__all__ = [
    "Budget",
    "ModelUnavailable",
    "OmniRouteClient",
    "Reply",
    "RequestedTool",
    "ScriptedClient",
    "Step",
    "Trajectory",
    "Usage",
    "run_agent",
]
