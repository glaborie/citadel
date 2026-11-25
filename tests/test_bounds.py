"""Tests for the bounds that render large tool output safe to keep."""

from __future__ import annotations

import hashlib

from citadel.tools.bounds import Bounded, bound


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def test_small_output_is_returned_unchanged() -> None:
    result = bound("ok\n", limit=1024)

    assert isinstance(result, Bounded)
    assert result.text == "ok\n"
    assert result.sha256 == sha("ok\n")
    assert result.kept_bytes == result.original_bytes == 3
    assert result.truncated is False
    assert result.omitted_bytes == 0


def test_large_output_fits_the_budget_and_keeps_both_ends() -> None:
    text = "HEAD" + ("a" * 100_000) + "TAIL"
    result = bound(text, limit=1_000)

    assert len(result.text.encode("utf-8")) <= 1_000
    assert result.text.startswith("HEAD")
    assert result.text.endswith("TAIL")
    assert result.original_bytes == len(text.encode())
    assert result.truncated is True


def test_the_digest_proves_the_text_that_was_cut() -> None:
    """The visible part is a fraction; the digest is the whole thing."""
    text = "x" * 50_000
    result = bound(text, limit=2_000)

    assert result.sha256 == sha(text)
    assert result.text.count("x") < 50_000
    # A different full text must not collide with this one's claim.
    assert result.sha256 != sha(text + ".")


def test_omitted_bytes_accounts_for_everything() -> None:
    text = "b" * 40_000
    result = bound(text, limit=4_000)

    assert result.kept_bytes == len(result.text.encode("utf-8"))
    assert result.kept_bytes + result.omitted_bytes == result.original_bytes


def test_the_marker_says_what_was_removed_and_names_the_digest() -> None:
    text = "c" * 20_000
    result = bound(text, limit=1_000)

    assert "bytes omitted" in result.text
    assert result.sha256[:16] in result.text


def test_a_budget_smaller_than_the_marker_still_respects_it() -> None:
    """Degenerate limits must return something bounded, not something long."""
    result = bound("d" * 10_000, limit=64)

    assert len(result.text.encode("utf-8")) <= 64


def test_multibyte_text_is_not_split_into_invalid_utf8() -> None:
    text = "é" * 10_000
    result = bound(text, limit=1_000)

    assert len(result.text.encode("utf-8")) <= 1_000
    # A slice through a multi-byte character would raise here, not show up later.
    assert result.text.encode("utf-8").decode("utf-8")
    assert result.sha256 == sha(text)
