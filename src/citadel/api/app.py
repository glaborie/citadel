"""Citadel API skeleton. Authentication and tenant middleware arrive in step 3."""

from fastapi import FastAPI

from citadel import __version__

app = FastAPI(title="Citadel API", version=__version__)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
