"""Policy: the single authorisation chokepoint over a versioned OpenFGA model."""

from citadel.policy.authorize import (
    ApprovalAuthorization,
    AuthorizationRequest,
    Decision,
    Outcome,
    RelationChecker,
    RunStore,
    authorize,
    authorize_approval,
    tool_object,
)
from citadel.policy.catalog import ToolSpec, load_catalog

__all__ = [
    "ApprovalAuthorization",
    "AuthorizationRequest",
    "Decision",
    "Outcome",
    "RelationChecker",
    "RunStore",
    "ToolSpec",
    "authorize",
    "authorize_approval",
    "load_catalog",
    "tool_object",
]


class PolicyError(Exception):
    """Raised when the policy service cannot be consulted."""
