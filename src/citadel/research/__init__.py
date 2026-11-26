"""Public-web research: a bounded fetcher and the labels its content carries.

The fetcher is the only component that opens an arbitrary URL. The guard in
`urlguard` refuses anything that is not a global unicast address on port 80 or
443, and it resolves before it checks, so a hostname that points at the compose
network or at cloud metadata is refused before a socket opens.

`labels` is deterministic on purpose: an injection flag is a fact about the
text, not a model opinion, and it never blocks a read - the run continues
read-only and the trajectory says why.
"""

from __future__ import annotations

from citadel.research.labels import PROMPT_INJECTION, UNTRUSTED, external_flags, label_untrusted
from citadel.research.urlguard import UrlRefused, check

__all__ = [
    "PROMPT_INJECTION",
    "UNTRUSTED",
    "UrlRefused",
    "check",
    "external_flags",
    "label_untrusted",
]
