"""Refuse a URL that could reach the host, the compose network or cloud metadata.

The guard runs before a socket opens and again after every redirect. It resolves
the name and checks every answer, because a hostname is not a promise: a name
that looks public can resolve to a private address, and `169.254.169.254` is the
address that turns a fetcher into a credential service.

Only ports 80 and 443 are allowed. A public host on another port is either a
non-HTTP service or an attempt to reach one, and neither belongs in a page
fetcher.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

ALLOWED_SCHEMES = frozenset({"http", "https"})
ALLOWED_PORTS = frozenset({80, 443})
# Cloud metadata endpoints, in case a resolver hands one back as a hostname.
METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),  # AWS/GCP/Azure IMDS
        ipaddress.ip_address("fd00:ec2::254"),  # AWS IPv6 IMDS
    }
)
BLOCKED_HOSTS = frozenset(
    {
        "localhost",
        "metadata",
        "metadata.google.internal",
        "instance-data",
        "instance-data.ec2.internal",
    }
)
BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".localdomain")

Resolver = Callable[[str, int], tuple[str, ...]]


class UrlRefused(ValueError):
    """The URL could reach something it must not. Nothing was opened."""


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    addresses: tuple[str, ...]
    path: str


def _allowed_address(raw: str) -> bool:
    try:
        address = ipaddress.ip_address(raw.split("%", 1)[0])
    except ValueError:
        return False
    # is_global excludes loopback, private, link-local, shared, reserved,
    # multicast and unspecified in one predicate.
    return address.is_global and address not in METADATA_ADDRESSES


def _resolve(host: str, port: int) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UrlRefused(f"cannot resolve {host!r}") from exc
    addresses = tuple(sorted({str(info[4][0]).split("%", 1)[0] for info in infos}))
    if not addresses:
        raise UrlRefused(f"{host!r} resolves to no address")
    return addresses


def _parts(raw: str) -> SplitResult:
    try:
        parts = urlsplit(raw)
    except ValueError as exc:
        raise UrlRefused("the URL cannot be parsed") from exc
    scheme = parts.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UrlRefused(f"scheme {scheme or 'none'!r} is not allowed; only http and https are")
    if parts.username or parts.password:
        raise UrlRefused("credentials in a URL are not allowed")
    return parts


def _host(parts: SplitResult) -> str:
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UrlRefused("the URL has no host")
    if not host.isascii():
        raise UrlRefused("use a punycode hostname; a non-ASCII host is not allowed")
    if host in BLOCKED_HOSTS or host.endswith(BLOCKED_SUFFIXES):
        raise UrlRefused(f"{host!r} is not a public host")
    return host


def _port(parts: SplitResult, scheme: str) -> int:
    try:
        port = parts.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UrlRefused("the URL has an invalid port") from exc
    if port not in ALLOWED_PORTS:
        raise UrlRefused(f"port {port} is not allowed; only 80 and 443 are")
    return port


def _addresses(host: str, port: int, resolver: Resolver) -> tuple[str, ...]:
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if not _allowed_address(str(literal)):
            raise UrlRefused(f"{host!r} is not a global unicast address")
        return (str(literal),)
    if "." not in host:
        raise UrlRefused(f"{host!r} is a single-label name, not a public host")
    addresses = resolver(host, port)
    if any(not _allowed_address(address) for address in addresses):
        raise UrlRefused(f"{host!r} resolves to a non-public address")
    return addresses


def check(url: str, *, resolver: Resolver = _resolve) -> Target:
    """Validate one absolute http(s) URL and return the addresses it resolved to."""
    raw = url.strip()
    parts = _parts(raw)
    scheme = parts.scheme.lower()
    host = _host(parts)
    port = _port(parts, scheme)
    addresses = _addresses(host, port, resolver)
    path = parts.path or "/"
    if parts.query:
        path = f"{path}?{parts.query}"
    return Target(
        url=raw.split("#", 1)[0],
        scheme=scheme,
        host=host,
        port=port,
        addresses=addresses,
        path=path,
    )
