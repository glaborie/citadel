"""The bounded fetcher: one GET, a byte cap, a MIME allowlist and no cookies.

The connection is pinned to the address the guard checked, so a short-TTL DNS
answer cannot swap in an internal address between the check and the connect.
Redirects are followed here, never by urllib, and every hop goes through the
same guard.

Extraction is trafilatura, imported only in the fetcher image (the `fetcher`
extra). The rest of the app never loads it.
"""

from __future__ import annotations

import http.client
import os
import socket
import ssl
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from citadel.research.urlguard import Resolver, Target, UrlRefused, check

ALLOWED_TYPES = frozenset({"text/html", "application/xhtml+xml", "text/plain"})
MAX_REDIRECTS = 3
DEFAULT_MAX_BYTES = int(os.environ.get("CITADEL_FETCH_MAX_BYTES", "2000000"))
DEFAULT_TIMEOUT = float(os.environ.get("CITADEL_FETCH_TIMEOUT", "10"))
USER_AGENT = "Citadel-Fetcher/0.1 (+read-only; no cookies)"

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9",
    # No Accept-Encoding: a compressed body would be capped before it is read,
    # so the cap would measure the wrong bytes.
    "Accept-Language": "en",
}

# Tests replace the transport with a fake; the real one is a pinned HTTP(S)
# connection. Any keeps the seam honest without teaching every fake to subclass
# http.client.
Connect = Callable[..., Any]


class FetchFailed(RuntimeError):
    """The target answered, but not with something a reader may be served."""

    def __init__(self, reason: str, status: int = 0) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass(frozen=True)
class Page:
    url: str
    content_type: str
    body: bytes
    truncated: bool


@dataclass(frozen=True)
class Document:
    url: str
    title: str
    text: str
    content_type: str
    truncated: bool
    bytes: int


def _connect(
    scheme: str, host: str, address: str, port: int, timeout: float
) -> http.client.HTTPConnection:
    """A connection whose socket is already open to the checked address.

    Pinning here rather than overriding `connect` keeps the guard's decision and
    the address that is dialled the same value, without a second DNS lookup.
    """
    if scheme == "https":
        context = ssl.create_default_context()
        # Explicit floor: create_default_context leaves the minimum to OpenSSL,
        # and the code-scanning rule (rightly) refuses an implicit TLSv1.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        # The context is create_default_context(): certificate and hostname
        # verification are on, which is the warning the rule exists to raise.
        # nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
        connection: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=context
        )
        sock = socket.create_connection((address, port), timeout)
        connection.sock = context.wrap_socket(sock, server_hostname=host)
        return connection
    connection = http.client.HTTPConnection(host, port, timeout=timeout)
    connection.sock = socket.create_connection((address, port), timeout)
    return connection


def _decode(body: bytes, content_type: str) -> str:
    # HTML's own encoding declaration is ignored here; trafilatura accepts a
    # string, and UTF-8 with replacement is the least surprising default for the
    # pages a homelab runbook points at. A page in another encoding still yields
    # its ASCII structure, and the truncated marker is computed on bytes.
    del content_type
    return body.decode("utf-8", errors="replace")


def extract(body: bytes, content_type: str) -> tuple[str, str]:
    """Return (title, text). A page the extractor cannot read yields no text."""
    text = _decode(body, content_type)
    if content_type == "text/plain":
        return "", text
    try:
        import trafilatura
    except ImportError as exc:  # pragma: no cover - the fetcher image installs it
        raise FetchFailed("the extractor is not installed in this image") from exc
    metadata = trafilatura.extract_metadata(text)
    title = str(getattr(metadata, "title", "") or "")
    extracted = trafilatura.extract(
        text,
        include_links=False,
        include_comments=False,
        favor_precision=True,
    )
    return title, str(extracted or "")


def _hop(target: Target, connection: Any, max_bytes: int) -> tuple[str | None, str, bytes, bool]:
    connection.request("GET", target.path, headers=HEADERS)
    response = connection.getresponse()
    status = response.status
    content_type = (response.getheader("Content-Type") or "").split(";")[0].strip().lower()
    if 300 <= status < 400:
        return response.getheader("Location"), content_type, b"", False
    if not 200 <= status < 300:
        raise FetchFailed(f"HTTP {status}", status)
    if content_type not in ALLOWED_TYPES:
        raise FetchFailed(
            f"content type {content_type or 'missing'!r} is not on the allowlist", status
        )
    body = response.read(max_bytes + 1)
    return None, content_type, body[:max_bytes], len(body) > max_bytes


def _open(
    target: Target,
    *,
    timeout: float,
    max_bytes: int,
    connect: Connect,
) -> tuple[str | None, str, bytes, bool]:
    """One hop. Returns (redirect location, content type, body, truncated)."""
    last: Exception | None = None
    for address in target.addresses:
        connection: Any = None
        try:
            connection = connect(target.scheme, target.host, address, target.port, timeout)
            return _hop(target, connection, max_bytes)
        except (OSError, http.client.HTTPException) as exc:
            last = exc
        finally:
            if connection is not None:
                connection.close()
    raise FetchFailed(f"transport: {last}")


def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    connect: Connect = _connect,
    resolver: Resolver | None = None,
) -> Page:
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        target = check(current) if resolver is None else check(current, resolver=resolver)
        location, content_type, body, truncated = _open(
            target, timeout=timeout, max_bytes=max_bytes, connect=connect
        )
        if location is None:
            return Page(url=current, content_type=content_type, body=body, truncated=truncated)
        current = urljoin(current, location)
    raise FetchFailed(f"more than {MAX_REDIRECTS} redirects")


def fetch_page(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    connect: Connect = _connect,
    resolver: Resolver | None = None,
) -> Document:
    page = fetch(url, timeout=timeout, max_bytes=max_bytes, connect=connect, resolver=resolver)
    title, text = extract(page.body, page.content_type)
    return Document(
        url=page.url,
        title=title,
        text=text,
        content_type=page.content_type,
        truncated=page.truncated,
        bytes=len(page.body),
    )


__all__ = [
    "Document",
    "FetchFailed",
    "Page",
    "UrlRefused",
    "extract",
    "fetch",
    "fetch_page",
]
