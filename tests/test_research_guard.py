"""The fetcher's URL guard: nothing reaches the host or the compose network.

The resolver is injected, so the test proves the decision without a DNS lookup.
A hostname that resolves to a private address is refused even when the name
looks public; a literal address never gets that far.
"""

from __future__ import annotations

import pytest

from citadel.research.urlguard import UrlRefused, check

PUBLIC = "93.184.216.34"


def public(_host: str, _port: int) -> tuple[str, ...]:
    return (PUBLIC,)


@pytest.mark.parametrize(
    "url",
    [
        "http://169.254.169.254/latest/meta-data",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
        "http://10.1.2.3/",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://100.64.0.1/",
        "http://localhost/",
        "http://metadata.google.internal/",
        "http://postgres/",
        "http://searxng:8080/",
        "http://example.com:8080/",
        "ftp://example.com/file",
        "file:///etc/passwd",
        "http://user:password@example.com/",
        "http:///nohost",
    ],
)
def test_an_internal_or_non_http_target_is_refused(url: str) -> None:
    with pytest.raises(UrlRefused):
        check(url, resolver=public)


@pytest.mark.parametrize(
    ("host", "addresses"),
    [
        ("rebind.example", ("10.0.0.5",)),
        ("mixed.example", (PUBLIC, "203.0.113.9")),
        ("linklocal.example", ("169.254.169.254",)),
        ("v6.local", ("fd00::1",)),
    ],
)
def test_a_public_name_that_resolves_inward_is_refused(
    host: str, addresses: tuple[str, ...]
) -> None:
    with pytest.raises(UrlRefused):
        check(f"https://{host}/page", resolver=lambda _h, _p: addresses)


def test_a_public_page_is_allowed_and_keeps_its_query_without_the_fragment() -> None:
    target = check("https://example.com/docs?q=1#section", resolver=public)
    assert target.host == "example.com"
    assert target.port == 443
    assert target.path == "/docs?q=1"
    assert target.addresses == (PUBLIC,)


def test_a_literal_public_address_is_allowed_without_resolving() -> None:
    def must_not_resolve(_host: str, _port: int) -> tuple[str, ...]:
        raise AssertionError("a literal address must not be resolved")

    target = check("http://93.184.216.34/", resolver=must_not_resolve)
    assert target.addresses == (PUBLIC,)
