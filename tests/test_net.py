"""The HTTP door: only http(s) gets opened, every other scheme raises first."""

from __future__ import annotations

from typing import Any
from urllib.request import Request

import pytest

from citadel import net


class Reply:
    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, request: Any, timeout: Any = None) -> Reply:
        self.calls += 1
        return self

    def __enter__(self) -> Reply:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


@pytest.mark.parametrize("url", ["http://keycloak:8080/x", "https://api.github.com/x"])
def test_http_schemes_are_opened(url: str) -> None:
    opener = Reply()
    with net.open_url(Request(url), timeout=5, opener=opener):
        pass
    assert opener.calls == 1


@pytest.mark.parametrize(
    "url",
    [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/x",
    ],
)
def test_every_other_scheme_is_refused_before_the_transport_runs(url: str) -> None:
    opener = Reply()
    with pytest.raises(net.UnsafeUrl):
        net.open_url(Request(url), timeout=5, opener=opener)
    assert opener.calls == 0, "the URL must be rejected before anything is opened"
