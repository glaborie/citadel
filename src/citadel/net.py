"""One HTTP door: http(s) only, so a dynamic value cannot choose a scheme.

`urllib` speaks `file://` and `ftp://` as readily as `https://`, which turns a
configuration value or a header into a local file read if it ever becomes
attacker-influenced. Every direct `urlopen` in this repository lives here, behind
a scheme check, so there is one place to audit and one place the scanners have to
be told about.

Call sites that accept an injected opener (the DLP client, the gateway client,
the tool runner) keep it: the tests replace the transport, and a scheme check in
front of a test double would only be theatre.
"""

from __future__ import annotations

import urllib.parse
from typing import Any
from urllib.request import Request, urlopen

SAFE_SCHEMES = frozenset({"http", "https"})


class UnsafeUrl(ValueError):
    """The URL is not http(s). Nothing was opened."""


def open_url(request: Request, *, timeout: float, opener: Any = None) -> Any:
    """Open an http(s) URL. Any other scheme raises before a connection."""
    scheme = urllib.parse.urlsplit(request.full_url).scheme.lower()
    if scheme not in SAFE_SCHEMES:
        raise UnsafeUrl(f"refusing {scheme or 'schemeless'!r} URL: only http and https are allowed")
    # The scheme check above is the control; this is the transport it guards.
    transport = opener or urlopen
    return transport(request, timeout=timeout)
