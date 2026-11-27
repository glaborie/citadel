"""The CLI's one HTTP call site, so there is one thing to justify.

Every URL the CLI reaches is operator configuration (a base URL from the environment plus a
fixed path); nothing an attacker or a response controls chooses the host, the scheme or a
file path.
"""

from __future__ import annotations

import urllib.request


def reachable(url: str, timeout: float = 5.0) -> int:
    """The status code, or an exception if nothing answered. The body is not read.

    A health endpoint's answer is the status, not the payload: parsing whatever comes back
    turns "mlflow is up and says OK" into a JSON error.
    """
    request = urllib.request.Request(url, method="GET")
    # nosemgrep: python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return int(response.status)
