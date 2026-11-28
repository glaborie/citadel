"""Issue #277: `make policy-drift` reports store drift and never writes.

The two failure modes it exists for: a tool that is in the catalog but has no
tuple (denied for everyone, silently), and a tuple the versioned policy no longer
grants (authority nobody reviewed).
"""

from __future__ import annotations

import pathlib

import pytest
from openfga_sdk.client.models import ClientTuple

from citadel.policy import PolicyError, drift


def _tuple(user: str, relation: str, obj: str) -> ClientTuple:
    return ClientTuple(user=user, relation=relation, object=obj)


def test_a_store_that_matches_reports_no_drift() -> None:
    desired = [_tuple("tenant:lab-a", "tenant", "tool:lab-a/compose_config")]
    existing = {("tenant:lab-a", "tenant", "tool:lab-a/compose_config")}

    diff = drift.tuple_drift(desired, existing)

    assert diff.missing == ()
    assert diff.unexpected == ()


def test_a_catalog_tool_that_was_never_bootstrapped_is_reported() -> None:
    """`tuples_for` writes two tuples per tool; a tool added since the last
    bootstrap is missing both, and `authorize()` denies it without a clue why."""
    desired = [
        _tuple("tenant:lab-a", "tenant", "tool:lab-a/compose_config"),
        _tuple("agent:lab-a/docker", "agent", "tool:lab-a/compose_config"),
        _tuple("tenant:lab-a", "tenant", "tool:lab-a/read_logs"),
    ]
    existing = {("tenant:lab-a", "tenant", "tool:lab-a/read_logs")}

    diff = drift.tuple_drift(desired, existing)

    assert diff.missing == (
        ("agent:lab-a/docker", "agent", "tool:lab-a/compose_config"),
        ("tenant:lab-a", "tenant", "tool:lab-a/compose_config"),
    )
    assert diff.unexpected == ()


def test_a_grant_the_versioned_policy_does_not_make_is_reported() -> None:
    """The dangerous direction: the store allows something no reviewed file does."""
    desired = [_tuple("tenant:lab-a", "tenant", "tool:lab-a/read_logs")]
    existing = {
        ("tenant:lab-a", "tenant", "tool:lab-a/read_logs"),
        ("agent:lab-b/github", "can_approve", "tool:lab-a/restart_service"),
    }

    diff = drift.tuple_drift(desired, existing)

    assert diff.unexpected == (
        ("agent:lab-b/github", "can_approve", "tool:lab-a/restart_service"),
    )
    assert diff.missing == ()


def test_the_report_is_ordered_so_two_runs_print_the_same_lines() -> None:
    desired = [
        _tuple("tenant:lab-a", "tenant", f"tool:lab-a/{name}") for name in ("zeta", "alpha")
    ]

    diff = drift.tuple_drift(desired, set())

    assert [key[2] for key in diff.missing] == ["tool:lab-a/alpha", "tool:lab-a/zeta"]


def test_a_model_that_matches_has_no_problems() -> None:
    model = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}

    assert drift.model_problems(model, model) == ()


def test_a_relation_widened_in_the_store_is_reported_by_type() -> None:
    committed = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {"type": "tool", "relations": {"can_call": {"this": {}}}},
        ],
    }
    loaded = {
        "id": "01M8",
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {"type": "tool", "relations": {"can_call": {"union": {"child": [{"this": {}}]}}}},
        ],
    }

    problems = drift.model_problems(committed, loaded)

    assert problems == ("types that differ: tool",)


def test_a_type_only_the_store_has_is_reported() -> None:
    committed = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}
    loaded = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "user"}, {"type": "service_account"}],
    }

    assert drift.model_problems(committed, loaded) == (
        "types only in the store: service_account",
    )


def test_protobuf_defaults_are_not_drift() -> None:
    """The API answers `module: ""`, `source_info: null` and
    `directly_related_user_types[].condition: ""`, which `model.json` never
    carries. Comparing raw serialisations called every type drifted on a store
    that was exactly right - measured against the local stack."""
    committed = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "user"},
            {
                "type": "tenant",
                "metadata": {
                    "relations": {"member": {"directly_related_user_types": [{"type": "user"}]}}
                },
                "relations": {"member": {"this": {}}},
            },
        ],
    }
    loaded = {
        "id": "01M8",
        "schema_version": "1.1",
        "conditions": {},
        "type_definitions": [
            {"type": "user", "metadata": None, "relations": {}},
            {
                "type": "tenant",
                "metadata": {
                    "module": "",
                    "source_info": None,
                    "relations": {
                        "member": {
                            "module": "",
                            "source_info": None,
                            "directly_related_user_types": [
                                {"condition": "", "type": "user"}
                            ],
                        }
                    },
                },
                "relations": {"member": {"this": {}}},
            },
        ],
    }

    assert drift.model_problems(committed, loaded) == ()


def test_union_order_is_not_drift() -> None:
    committed = {
        "schema_version": "1.1",
        "type_definitions": [
            {
                "type": "agent",
                "relations": {
                    "invoker": {
                        "union": {
                            "child": [
                                {"this": {}},
                                {"tupleToUserset": {"tupleset": {"relation": "tenant"}}},
                            ]
                        }
                    }
                },
            }
        ],
    }
    loaded = {
        "schema_version": "1.1",
        "type_definitions": [
            {
                "type": "agent",
                "relations": {
                    "invoker": {
                        "union": {
                            "child": [
                                {"tupleToUserset": {"tupleset": {"relation": "tenant"}}},
                                {"this": {}},
                            ]
                        }
                    }
                },
            }
        ],
    }

    assert drift.model_problems(committed, loaded) == ()


def test_a_schema_version_change_is_reported() -> None:
    committed = {"schema_version": "1.1", "type_definitions": []}
    loaded = {"schema_version": "1.0", "type_definitions": []}

    problems = drift.model_problems(committed, loaded)

    assert any("schema version" in problem for problem in problems), problems


def test_the_render_names_the_drift_and_the_repair() -> None:
    report = drift.Report(
        store_id="01M84AEV3Y39912S4DK9855R15",
        model_id="01M8MODEL",
        model_problems=(),
        missing=(("agent:lab-a/docker", "agent", "tool:lab-a/compose_config"),),
        unexpected=(),
        expected=3,
    )

    text = drift.render(report)

    assert "model: matches policy/model.json" in text
    assert "tuples: 2 of 3 present, 0 unexpected" in text
    assert "missing     agent:lab-a/docker agent tool:lab-a/compose_config" in text
    assert "make policy-bootstrap" in text


def test_a_clean_store_exits_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    clean = drift.Report(
        store_id="store",
        model_id="model",
        model_problems=(),
        missing=(),
        unexpected=(),
        expected=65,
    )
    monkeypatch.setattr(drift, "check", lambda api_url, store_name: clean)

    assert drift.main([]) == 0


def test_drift_exits_one(monkeypatch: pytest.MonkeyPatch) -> None:
    drifted = drift.Report(
        store_id="store",
        model_id="model",
        model_problems=(),
        missing=(("tenant:lab-a", "tenant", "tool:lab-a/compose_config"),),
        unexpected=(),
        expected=65,
    )
    monkeypatch.setattr(drift, "check", lambda api_url, store_name: drifted)

    assert drift.main([]) == 1


def test_a_store_that_cannot_be_read_is_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail closed: "could not compare" is its own exit code, never 0."""

    def broken(api_url: str, store_name: str) -> drift.Report:
        raise PolicyError("openfga store 'citadel' does not exist")

    monkeypatch.setattr(drift, "check", broken)

    assert drift.main([]) == 2


def test_usage_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(drift, "check", lambda api_url, store_name: pytest.fail("checked"))

    assert drift.main(["--fix"]) == 2


def test_the_check_is_read_only() -> None:
    """The promise `make policy-drift` makes: no model write, no tuple write.

    A future edit that reaches for either has to delete this test, which is the
    review conversation that change needs.
    """
    source = pathlib.Path(drift.__file__).read_text(encoding="utf-8")

    assert "write_tuples" not in source
    assert "write_authorization_model" not in source
