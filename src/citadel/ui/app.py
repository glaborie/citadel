"""Approval console skeleton. The five views and Keycloak SSO arrive in step 8."""

from fastapi import FastAPI

from citadel import __version__

app = FastAPI(title="Citadel Approval Console", version=__version__)


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}
