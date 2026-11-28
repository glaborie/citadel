"""Report drift between the OpenFGA store and the versioned policy. Read-only.

    make policy-drift

Policy has one source of truth: `policy/model.fga` (generated into
`policy/model.json`), the tool catalog, and the tuple set `tuples_for` derives
from them. The store is a copy of that intent, and nothing compared the copy with
the source (#277):

- a tool added to the catalog but never bootstrapped has no tuple, so
  `authorize()` denies it for every user - fail closed, but the tool is silently
  unusable;
- a tuple for a membership or agent relation the versioned set no longer grants
  is authority nobody reviewed;
- a model written to the store and not to `model.fga` skipped review, and
  `policy_version()` hashes the committed file, so the cache key stops describing
  what is actually enforced.

`make policy-bootstrap` repairs by writing. This check only reports, so it is safe
on a live stack and in cron, and it can say that the model itself drifted.

It runs through the `policy-bootstrap` one-shot because resolving a dev username
to the Keycloak sub a tuple names needs the credential that one-shot mounts, and
no long-running service may carry it (#273).

Exit codes: 0 no drift, 1 drift, 2 could not compare (store absent, credential
absent, service unreachable). A non-zero exit is the point: a check nobody acts
on is the same as no check.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from openfga_sdk.client.models import ClientTuple

from citadel.net import open_url
from citadel.policy import PolicyError, bootstrap
from citadel.policy.openfga import resolve_store_id

TupleKey = tuple[str, str, str]
USAGE: Final = "usage: python -m citadel.policy.drift"
REQUEST_TIMEOUT_SECONDS: Final = 20


@dataclass(frozen=True)
class TupleDrift:
    """What the store lacks, and what it holds beyond the versioned set."""

    missing: tuple[TupleKey, ...]
    unexpected: tuple[TupleKey, ...]


@dataclass(frozen=True)
class Report:
    store_id: str
    model_id: str
    model_problems: tuple[str, ...]
    missing: tuple[TupleKey, ...]
    unexpected: tuple[TupleKey, ...]
    expected: int

    @property
    def drifted(self) -> bool:
        return bool(self.model_problems or self.missing or self.unexpected)


def key_of(tuple_: ClientTuple) -> TupleKey:
    return (str(tuple_.user), str(tuple_.relation), str(tuple_.object))


def tuple_drift(desired: Iterable[ClientTuple], existing: set[TupleKey]) -> TupleDrift:
    """Compare the versioned tuple set with the store, sorted so two runs agree."""
    wanted = {key_of(t) for t in desired}
    return TupleDrift(
        missing=tuple(sorted(wanted - existing)),
        unexpected=tuple(sorted(existing - wanted)),
    )


def _types(model: dict[str, Any]) -> dict[str, dict[str, Any]]:
    definitions = model.get("type_definitions") or []
    return {str(d["type"]): d for d in definitions if isinstance(d, dict) and "type" in d}


# The two userset markers whose value is legitimately an empty object.
MARKER_KEYS: Final = frozenset({"this", "wildcard"})


def _strip_defaults(value: Any) -> Any:
    """The meaning of a model value, without protobuf-JSON's defaults.

    The same model reads differently depending on where it came from: the API
    answers `module: ""`, `source_info: null`, `conditions: {}` and
    `directly_related_user_types[].condition: ""`, none of which `model.json`
    carries. Comparing the raw serialisations therefore reports every type as
    drifted on a store that is exactly right (measured against the local stack).

    Lists are sorted because the only ordered list in a model is `union.child`,
    a set in meaning.
    """
    if isinstance(value, dict):
        stripped: dict[str, Any] = {}
        for key, item in value.items():
            if key not in MARKER_KEYS and item in ("", None, [], {}):
                continue
            stripped[key] = _strip_defaults(item)
        return stripped
    if isinstance(value, list):
        return sorted(
            (_strip_defaults(item) for item in value),
            key=lambda item: json.dumps(item, sort_keys=True),
        )
    return value


def _canonical(value: Any) -> str:
    return json.dumps(_strip_defaults(value), sort_keys=True, separators=(",", ":"))


def model_problems(committed: dict[str, Any], loaded: dict[str, Any]) -> tuple[str, ...]:
    """The differences that decide what the store enforces, named by type."""
    problems: list[str] = []
    if committed.get("schema_version") != loaded.get("schema_version"):
        problems.append(
            "schema version: committed "
            f"{committed.get('schema_version')!r}, enforced {loaded.get('schema_version')!r}"
        )
    committed_types, loaded_types = _types(committed), _types(loaded)
    only_stored = sorted(set(loaded_types) - set(committed_types))
    only_committed = sorted(set(committed_types) - set(loaded_types))
    changed = sorted(
        name
        for name in set(committed_types) & set(loaded_types)
        if _canonical(committed_types[name]) != _canonical(loaded_types[name])
    )
    if only_stored:
        problems.append("types only in the store: " + ", ".join(only_stored))
    if only_committed:
        problems.append("types only in policy/model.json: " + ", ".join(only_committed))
    if changed:
        problems.append("types that differ: " + ", ".join(changed))
    return tuple(problems)


def latest_model(api_url: str, store_id: str) -> dict[str, Any]:
    """The model the store enforces: the newest one it holds."""
    url = f"{api_url}/stores/{store_id}/authorization-models?page_size=1"
    with open_url(urllib.request.Request(url), timeout=REQUEST_TIMEOUT_SECONDS) as response:
        page: dict[str, Any] = json.loads(response.read())
    models = page.get("authorization_models") or []
    if not models:
        raise PolicyError("the store holds no authorization model; run `make policy-bootstrap`")
    return dict(models[0])


def check(api_url: str, store_name: str) -> Report:
    """Read both sides and report. Every failure raises: see `main`."""
    committed: dict[str, Any] = json.loads(
        Path(bootstrap.MODEL_PATH).read_text(encoding="utf-8")
    )
    store_id = resolve_store_id(api_url, store_name)
    desired = bootstrap.tuples_for(bootstrap.sub_ids())
    existing = bootstrap.existing_tuples(api_url, store_id)
    loaded = latest_model(api_url, store_id)
    drift = tuple_drift(desired, existing)
    return Report(
        store_id=store_id,
        model_id=str(loaded.get("id", "")),
        model_problems=model_problems(committed, loaded),
        missing=drift.missing,
        unexpected=drift.unexpected,
        expected=len({key_of(t) for t in desired}),
    )


def render(report: Report) -> str:
    """The report as an operator reads it: object ids only, no credential."""
    lines = [f"store {report.store_id} (enforcing model {report.model_id or 'none'})"]
    if report.model_problems:
        lines.append("model: DRIFTED from policy/model.json")
        lines.extend(f"  {problem}" for problem in report.model_problems)
    else:
        lines.append("model: matches policy/model.json")
    present = report.expected - len(report.missing)
    lines.append(
        f"tuples: {present} of {report.expected} present, {len(report.unexpected)} unexpected"
    )
    lines.extend("  missing     " + " ".join(key) for key in report.missing)
    lines.extend("  unexpected  " + " ".join(key) for key in report.unexpected)
    if report.drifted:
        lines.append(
            "drift: `make policy-bootstrap` writes the missing tuples and reloads the "
            "committed model; an unexpected tuple is a grant the versioned policy does not "
            "make, so remove it deliberately rather than re-seeding around it"
        )
    else:
        lines.append("ok: the store matches the versioned policy")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        print(USAGE, file=sys.stderr)
        return 2
    api_url = os.environ.get("OPENFGA_API_URL", "http://openfga:8080")
    store_name = os.environ.get("OPENFGA_STORE_NAME", "citadel")
    try:
        report = check(api_url, store_name)
    except Exception as exc:  # noqa: BLE001 - "could not look" must never read as "clean"
        print(f"cannot check policy drift: {exc}", file=sys.stderr)
        return 2
    print(render(report))
    return 1 if report.drifted else 0


if __name__ == "__main__":
    raise SystemExit(main())
