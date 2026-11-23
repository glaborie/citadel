"""The API and approval console must come up and answer their health probe."""

from fastapi.testclient import TestClient

from citadel.api.app import create_app
from citadel.ui.app import app as ui_app


def test_api_healthz() -> None:
    response = TestClient(create_app()).get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_ui_healthz() -> None:
    response = TestClient(ui_app).get("/healthz")
    assert response.status_code == 200
