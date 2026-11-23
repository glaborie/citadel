"""Policy: the single authorisation chokepoint over a versioned OpenFGA model."""

from citadel.policy.authorize import (
    AuthorizationRequest,
    Decision,
    Outcome,
    RelationChecker,
    RunStore,
    authorize,
    tool_object,
)
from citadel.policy.catalog import ToolSpec, load_catalog

__all__ = [
    "AuthorizationRequest",
    "Decision",
    "Outcome",
    "RelationChecker",
    "RunStore",
    "ToolSpec",
    "authorize",
    "load_catalog",
    "tool_object",
]


class PolicyError(Exception):
    """Raised when the policy service cannot be consulted."""
