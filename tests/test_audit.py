"""Audit ledger: hash-chain semantics."""

from __future__ import annotations

from citadel.audit import GENESIS, canonical, event_hash


def chain(*bodies: str) -> list[str]:
    prev = GENESIS
    hashes = []
    for index, body in enumerate(bodies, start=1):
        prev = event_hash(
            prev_hash=prev,
            tenant_id="lab-a",
            seq=index,
            event_type="policy.decision",
            actor_type="user",
            actor_id="u1",
            body=body,
        )
        hashes.append(prev)
    return hashes


def test_canonical_json_is_key_order_independent() -> None:
    assert canonical({"b": 2, "a": 1}) == canonical({"a": 1, "b": 2})


def h(
    prev_hash: str = GENESIS,
    tenant_id: str = "lab-a",
    seq: int = 1,
    event_type: str = "x",
    actor_type: str = "user",
    actor_id: str = "u1",
    body: str = "{}",
) -> str:
    return event_hash(
        prev_hash=prev_hash,
        tenant_id=tenant_id,
        seq=seq,
        event_type=event_type,
        actor_type=actor_type,
        actor_id=actor_id,
        body=body,
    )


def test_hash_is_deterministic() -> None:
    assert h() == h()
    assert len(h()) == 64


def test_hash_covers_every_input() -> None:
    baseline = h()
    assert h(prev_hash="f" * 64) != baseline
    assert h(tenant_id="lab-b") != baseline
    assert h(seq=2) != baseline
    assert h(event_type="y") != baseline
    assert h(body='{"a":1}') != baseline
    # Actor spoofing must be as detectable as payload edits.
    assert h(actor_id="attacker") != baseline
    assert h(actor_type="agent") != baseline


def test_chain_links_each_event_to_the_previous() -> None:
    first, second, third = chain("a", "b", "c")
    assert len({first, second, third}) == 3
    # Recomputing from the same prefix must reproduce the identical chain.
    assert chain("a", "b", "c") == [first, second, third]


def test_changing_one_event_breaks_all_later_hashes() -> None:
    """Tamper evidence: editing event 2 must invalidate events 2 and 3."""
    original = chain("a", "b", "c")
    tampered = chain("a", "CHANGED", "c")
    assert tampered[0] == original[0], "earlier events are unaffected"
    assert tampered[1] != original[1]
    assert tampered[2] != original[2], "the break propagates forward"


def test_genesis_is_a_fixed_anchor() -> None:
    assert GENESIS == "0" * 64
