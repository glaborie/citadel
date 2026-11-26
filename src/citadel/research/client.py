"""Worker-side calls to SearXNG and the fetcher.

Both services are internal; this module is the only place the researcher worker
opens them. It never follows a result URL: a search result is text and a
candidate for a later, separately guarded `fetch_page` call.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
from collections.abc import Callable, Mapping
from typing import Any
from urllib.request import Request

from citadel.net import open_url

Opener = Callable[..., Any]
MAX_RESPONSE_BYTES = 5_000_000
SEARCH_TIMEOUT = 15
FETCH_TIMEOUT = 30


class ResearchError(RuntimeError):
    """A research service could not answer, or answered with the wrong shape."""


class ResearchRefused(ResearchError):
    """The fetcher refused the target before opening it (bad URL, internal host)."""


def _read(response: Any, limit: int = MAX_RESPONSE_BYTES) -> bytes:
    body: bytes = response.read(limit)
    return body


def _detail(raw: bytes) -> str:
    try:
        payload = json.loads(raw)
    except ValueError:
        return raw.decode("utf-8", errors="replace")[:200]
    if isinstance(payload, dict):
        return str(payload.get("detail", ""))[:300]
    return ""


def _search_payload(query: str, base_url: str, opener: Opener | None) -> object:
    params = urllib.parse.urlencode({"q": query, "format": "json", "safesearch": "1"})
    request = Request(
        f"{base_url.rstrip('/')}/search?{params}",
        headers={"Accept": "application/json", "User-Agent": "Citadel-Researcher/0.1"},
        method="GET",
    )
    try:
        with open_url(request, timeout=SEARCH_TIMEOUT, opener=opener) as response:
            return json.loads(_read(response))
    except urllib.error.HTTPError as exc:
        raise ResearchError(f"SearXNG refused the query: HTTP {exc.code}") from exc
    except (OSError, ValueError) as exc:
        raise ResearchError(f"SearXNG did not answer: {exc}") from exc


def _render_search(results: list[Any], limit: int) -> str:
    lines: list[str] = []
    for item in results:
        if not isinstance(item, Mapping):
            continue
        url = str(item.get("url", ""))
        if not url.startswith(("http://", "https://")):
            continue
        title = str(item.get("title", ""))[:200].strip()
        snippet = " ".join(str(item.get("content", "")).split())[:300]
        lines.append(f"[{len(lines) + 1}] {title}\n{url}\n{snippet}")
        if len(lines) >= max(1, min(limit, 10)):
            break
    return "\n\n".join(lines) if lines else "no results"


def search_web(
    query: str,
    *,
    base_url: str,
    limit: int = 5,
    opener: Opener | None = None,
) -> str:
    """Search SearXNG and return a bounded, human-readable result list."""
    payload = _search_payload(query, base_url, opener)
    results = payload.get("results") if isinstance(payload, Mapping) else None
    if not isinstance(results, list):
        raise ResearchError("SearXNG returned no result list")
    return _render_search(results, limit)


def _fetcher_payload(url: str, base_url: str, opener: Opener | None) -> object:
    body = json.dumps({"url": url}).encode()
    request = Request(
        f"{base_url.rstrip('/')}/fetch",
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with open_url(request, timeout=FETCH_TIMEOUT, opener=opener) as response:
            return json.loads(_read(response))
    except urllib.error.HTTPError as exc:
        detail = _detail(exc.read())
        if exc.code in (400, 422):
            raise ResearchRefused(detail or "the fetcher refused the target") from exc
        raise ResearchError(f"the fetcher failed: HTTP {exc.code} {detail}".strip()) from exc
    except (OSError, ValueError) as exc:
        raise ResearchError(f"the fetcher did not answer: {exc}") from exc


def fetch_page(
    url: str,
    *,
    base_url: str,
    opener: Opener | None = None,
) -> dict[str, Any]:
    """Ask the fetcher for one page. A refused target is a denial, not a retry."""
    payload = _fetcher_payload(url, base_url, opener)
    if not isinstance(payload, dict):
        raise ResearchError("the fetcher returned no object")
    if not isinstance(payload.get("text"), str) or not isinstance(payload.get("url"), str):
        raise ResearchError("the fetcher returned no page text")
    return payload
