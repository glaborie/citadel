"""The fetcher's other limits: byte cap, MIME allowlist, redirects, no cookies.

The connection is a fake, so the test never opens a socket. The guard is still
real, with a resolver that answers with a public address.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from citadel.research.fetch import FetchFailed, fetch, fetch_page
from citadel.research.urlguard import UrlRefused

PUBLIC = "93.184.216.34"


def resolver(_host: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC,)


class FakeResponse:
    def __init__(self, status: int, headers: dict[str, str], body: bytes) -> None:
        self.status = status
        self._headers = headers
        self._body = body

    def getheader(self, name: str) -> str | None:
        return self._headers.get(name)

    def read(self, amount: int = -1) -> bytes:
        return self._body if amount < 0 else self._body[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse, seen: list[dict[str, str]]) -> None:
        self._response = response
        self._seen = seen
        self.closed = False

    def request(self, _method: str, _path: str, headers: dict[str, str] | None = None) -> None:
        self._seen.append(headers or {})

    def getresponse(self) -> FakeResponse:
        return self._response

    def close(self) -> None:
        self.closed = True


def connect(
    response: FakeResponse, seen: list[dict[str, str]] | None = None
) -> Callable[..., FakeConnection]:
    seen = seen if seen is not None else []

    def factory(*_args: object) -> FakeConnection:
        return FakeConnection(response, seen)

    return factory


def test_a_page_over_the_cap_is_truncated_and_marked() -> None:
    page = fetch(
        "https://example.com/long",
        max_bytes=5,
        connect=connect(FakeResponse(200, {"Content-Type": "text/html"}, b"0123456789")),
        resolver=resolver,
    )
    assert page.body == b"01234"
    assert page.truncated is True


def test_a_page_under_the_cap_is_not_marked() -> None:
    page = fetch(
        "https://example.com/short",
        max_bytes=50,
        connect=connect(FakeResponse(200, {"Content-Type": "text/plain"}, b"hello")),
        resolver=resolver,
    )
    assert page.body == b"hello"
    assert page.truncated is False


@pytest.mark.parametrize(
    "content_type", ["application/pdf", "image/png", "application/octet-stream"]
)
def test_a_non_allowlisted_content_type_is_refused(content_type: str) -> None:
    with pytest.raises(FetchFailed):
        fetch(
            "https://example.com/file",
            connect=connect(FakeResponse(200, {"Content-Type": content_type}, b"x")),
            resolver=resolver,
        )


def test_a_non_2xx_answer_is_a_failure_not_a_retry() -> None:
    with pytest.raises(FetchFailed) as caught:
        fetch(
            "https://example.com/missing",
            connect=connect(FakeResponse(404, {"Content-Type": "text/html"}, b"no")),
            resolver=resolver,
        )
    assert caught.value.status == 404


def test_a_redirect_to_an_internal_target_is_refused_before_the_second_hop() -> None:
    hops: list[str] = []

    def factory(
        scheme: str, host: str, _address: str, _port: int, _timeout: float
    ) -> FakeConnection:
        hops.append(f"{scheme}://{host}")
        return FakeConnection(FakeResponse(302, {"Location": "http://127.0.0.1/admin"}, b""), [])

    with pytest.raises(UrlRefused):
        fetch("https://example.com/start", connect=factory, resolver=resolver)
    assert hops == ["https://example.com"], "the internal hop must never be opened"


def test_a_public_redirect_is_followed() -> None:
    responses = iter(
        [
            FakeResponse(302, {"Location": "https://example.com/final"}, b""),
            FakeResponse(200, {"Content-Type": "text/plain"}, b"final"),
        ]
    )

    def factory(*_args: object) -> FakeConnection:
        return FakeConnection(next(responses), [])

    page = fetch("https://example.com/start", connect=factory, resolver=resolver)
    assert page.url == "https://example.com/final"
    assert page.body == b"final"


def test_no_cookie_header_is_sent() -> None:
    seen: list[dict[str, str]] = []
    fetch(
        "https://example.com/",
        connect=connect(FakeResponse(200, {"Content-Type": "text/plain"}, b"ok"), seen),
        resolver=resolver,
    )
    assert seen, "the request headers were not captured"
    assert not any(name.lower() == "cookie" for name in seen[0])


def test_extraction_returns_the_title_and_the_readable_text() -> None:
    html = (
        b"<html><head><title>Runbook</title></head><body>"
        b"<nav>menu</nav><article><p>The probe is a 30-second check.</p></article>"
        b"</body></html>"
    )

    document = fetch_page(
        "https://example.com/runbook",
        connect=connect(FakeResponse(200, {"Content-Type": "text/html"}, html)),
        resolver=resolver,
    )
    assert document.title == "Runbook"
    assert "30-second check" in document.text
    assert document.truncated is False
