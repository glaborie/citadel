"""The fetcher service: one endpoint, one bounded GET, no model and no policy.

Policy decides whether the Researcher may call `fetch_page`; this service
decides whether the URL is a public page. It holds no secret and reaches only
the public web, so an internal caller that bypasses the worker still cannot use
it to read the compose network.
"""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from citadel import __version__
from citadel.research.fetch import FetchFailed, fetch_page
from citadel.research.urlguard import UrlRefused

app = FastAPI(title="Citadel Fetcher", version=__version__)


class FetchRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=8, max_length=2048)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.post("/fetch")
def fetch(request: FetchRequest) -> dict[str, Any]:
    try:
        document = fetch_page(request.url)
    except UrlRefused as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FetchFailed as exc:
        raise HTTPException(status_code=502, detail=exc.reason) from exc
    return asdict(document)
