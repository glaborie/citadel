"""Approval references: scoped, single use and never a credential in history."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from types import SimpleNamespace
from typing import Any

import pytest

from citadel import approvals
from citadel.approvals import resolve_approval, validate_approval
from citadel.hashing import arguments_hash
from citadel.identity import IdentityError

ARGS = {"service": "checkout-api"}
CREATED_AT = 900.0
NOW = 1000.0


def record(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "run_id": "run-1",
        "tool": "restart_service",
        "approver": "user-carol",
        "decision": "approved",
        "ttl": 300,
        "args_hash": arguments_hash(ARGS),
    }
    base.update(overrides)
    return base


def check(entry: dict[str, Any], **overrides: Any) -> approvals.ApprovalClaims:
    base: dict[str, Any] = {
        "created_at": CREATED_AT,
        "tenant_id": "lab-a",
        "ref": "2f0c1e2a-0000-4000-8000-000000000001",
        "run_id": "run-1",
        "tool": "restart_service",
        "arguments": ARGS,
        "now": NOW,
    }
    base.update(overrides)
    return validate_approval(entry, **base)


def test_valid_approval_is_accepted() -> None:
    claims = check(record())
    assert claims.approver == "user-carol"
    assert claims.ref
    assert claims.arguments_hash == arguments_hash(ARGS)


def test_arguments_hash_is_order_independent() -> None:
    assert arguments_hash({"a": 1, "b": 2}) == arguments_hash({"b": 2, "a": 1})


@pytest.mark.parametrize(
    ("overrides", "match"),
    [
        ({"run_id": "run-2"}, "another run"),
        ({"tool": "open_remediation_pr"}, "another tool"),
        ({"args_hash": arguments_hash({"service": "database"})}, "does not match these"),
        ({"decision": "denied"}, "was not granted"),
        ({"approver": ""}, "names no approver"),
        ({"ttl": 0}, "no usable lifetime"),
        ({"ttl": "300"}, "no usable lifetime"),
    ],
)
def test_bad_records_are_rejected(overrides: dict[str, Any], match: str) -> None:
    """An approval for one action must not authorise another."""
    with pytest.raises(IdentityError, match=match):
        check(record(**overrides))


def test_expired_approval_is_rejected() -> None:
    with pytest.raises(IdentityError, match="expired"):
        check(record(), now=CREATED_AT + 301)


def test_run_token_string_is_not_a_usable_reference() -> None:
    """Red team: a delegated run token has no meaning to the operator."""
    with pytest.raises(IdentityError, match="not valid"):
        resolve_approval(
            dsn="unused",
            tenant_id="lab-a",
            ref="eyJhbGciOiJFZERTQSJ9.payload.signature",
            run_id="run-1",
            tool="restart_service",
            arguments=ARGS,
        )


def test_resolve_reads_the_audit_row(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def fake_connection(_dsn: str, _tenant: str) -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(
            execute=lambda *_a: SimpleNamespace(fetchone=lambda: (record(), CREATED_AT))
        )

    monkeypatch.setattr(approvals, "tenant_connection", fake_connection)
    claims = resolve_approval(
        dsn="unused",
        tenant_id="lab-a",
        ref="2f0c1e2a-0000-4000-8000-000000000001",
        run_id="run-1",
        tool="restart_service",
        arguments=ARGS,
        now=NOW,
    )
    assert claims.approver == "user-carol"


def test_unknown_reference_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    @contextmanager
    def fake_connection(_dsn: str, _tenant: str) -> Iterator[SimpleNamespace]:
        yield SimpleNamespace(execute=lambda *_a: SimpleNamespace(fetchone=lambda: None))

    monkeypatch.setattr(approvals, "tenant_connection", fake_connection)
    with pytest.raises(IdentityError, match="no approval"):
        resolve_approval(
            dsn="unused",
            tenant_id="lab-a",
            ref="2f0c1e2a-0000-4000-8000-000000000001",
            run_id="run-1",
            tool="restart_service",
            arguments=ARGS,
        )
