"""Tool metadata from outside the catalog is registered, never trusted.

An MCP server offers tool definitions: a name, a description, a parameter schema.
That description is prose written by someone else, and prose aimed at a model is
what a prompt injection looks like. Citadel's answer is the one it gives
everywhere else: the metadata is data, it is pinned by digest, and a description
nobody reviewed cannot reach a model.

Three rules, in this order:

1. The entry carries only fields this codebase knows. A registry cannot add a field
   to the shape and hope something renders it.
2. The name must already be in the tool catalog. A server cannot introduce a tool:
   the catalog decides what exists, and policy decides who may call it.
3. The description's digest must equal a reviewed pin. A changed byte is refused
   until a human puts the new digest in `description_pins.json`, which is a code
   change with a review attached.

Every decision is written to the audit ledger with the digest and the reason, never
with the description itself. Copying attacker prose into an append-only log would
make the ledger the next injection channel - and the log already has enough of that
kind of problem without help.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from importlib import resources
from typing import Any, Protocol

from citadel.hashing import arguments_hash
from citadel.policy.catalog import ToolSpec, load_catalog

# The fields a registry entry may carry. Anything else is refused rather than
# dropped: a field this codebase does not know is a field it cannot reason about.
# The protocol's own field names: a real `tools/list` entry offers `inputSchema`.
# The schema is carried for the digest and never rendered: the manifest the model
# sees is built from the catalog's parameters, not from a server's opinion of them.
ENTRY_FIELDS = frozenset({"name", "description", "inputSchema"})
REGISTERED = "tool.registration"
REFUSED = "tool.registration_refused"
REVIEWED = "the description is the reviewed one"


class Ledger(Protocol):
    """The slice of `AuditLedger` this module needs."""

    def append(
        self,
        *,
        tenant_id: str,
        event_type: str,
        actor_type: str,
        actor_id: str,
        payload: dict[str, Any],
    ) -> Any: ...


@dataclass(frozen=True)
class Registration:
    name: str
    digest: str
    accepted: bool
    reason: str


def description_digest(entry: Mapping[str, Any]) -> str:
    """The digest of the metadata as a whole, so a changed byte changes the pin."""
    shape = {field: entry.get(field) for field in sorted(ENTRY_FIELDS) if field in entry}
    return arguments_hash(shape)


def load_pins() -> dict[str, str]:
    """The reviewed digests. Empty by default: nothing remote is trusted yet."""
    raw = json.loads(
        resources.files("citadel.tools")
        .joinpath("description_pins.json")
        .read_text(encoding="utf-8")
    )
    return {str(name): str(digest) for name, digest in raw.get("pins", {}).items()}


def _name(entry: Mapping[str, Any]) -> str:
    name = entry.get("name")
    return name if isinstance(name, str) else ""


def _denial(entry: Mapping[str, Any], catalog: dict[str, ToolSpec], pins: dict[str, str]) -> str:
    """The first reason to refuse, or an empty string when the entry may pass."""
    unexpected = set(entry) - ENTRY_FIELDS
    if unexpected:
        return f"unknown metadata field(s): {sorted(unexpected)}"
    name = _name(entry)
    if not name:
        return "the entry has no name"
    if name not in catalog:
        return "not in the tool catalog, so no policy decision can cover it"
    if not isinstance(entry.get("description"), str):
        return "the description is not a string"
    pinned = pins.get(name)
    if pinned is None:
        return "no reviewed digest for this description"
    if pinned != description_digest(entry):
        return "the description is not the reviewed one"
    return ""


@dataclass(frozen=True)
class Request:
    """Who is offering the metadata, and where the decision is recorded."""

    tenant_id: str
    actor_id: str
    ledger: Ledger


def evaluate(
    entry: Any,
    *,
    pins: dict[str, str] | None = None,
    catalog: dict[str, ToolSpec] | None = None,
) -> Registration:
    """The decision, without recording it: what `register` does before it writes."""
    tools = catalog if catalog is not None else load_catalog()
    reviewed = pins if pins is not None else load_pins()
    if isinstance(entry, Mapping):
        name, digest = _name(entry), description_digest(entry)
        reason = _denial(entry, tools, reviewed)
    else:
        name, digest, reason = "", description_digest({}), "the entry is not an object"
    return Registration(
        name=name, digest=digest, accepted=not reason, reason=reason or REVIEWED
    )


def register(
    entry: Any,
    *,
    request: Request,
    pins: dict[str, str] | None = None,
    catalog: dict[str, ToolSpec] | None = None,
) -> Registration:
    """Evaluate a registry entry, record the decision, return it.

    A refusal is a decision, not an exception, so the flag is what a caller reads.
    """
    registration = evaluate(entry, pins=pins, catalog=catalog)
    request.ledger.append(
        tenant_id=request.tenant_id,
        event_type=REGISTERED if registration.accepted else REFUSED,
        actor_type="agent",
        actor_id=request.actor_id,
        payload={
            "name": registration.name,
            "digest": registration.digest,
            "reason": registration.reason,
        },
    )
    return registration
