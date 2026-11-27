"""The run launcher's contract with the API, which is stricter than it looks.

`RunRequest` forbids extra fields, so a body with one key too many is a 422 that reads like
an auth failure. These tests keep the launcher's body and the API's model in step.
"""

from __future__ import annotations

import importlib.util
import pathlib
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "start-run.py"


def _launcher() -> Any:
    spec = importlib.util.spec_from_file_location("start_run", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_body_is_exactly_the_fields_the_api_accepts() -> None:
    from citadel.api.app import RunRequest

    body = _launcher().run_body(
        agent="docker", risk_tier="T0", pack="docker-1.0.0", alias="auto/best-fast", task="hi"
    )
    assert set(body) == set(RunRequest.model_fields)
    assert RunRequest.model_validate(body)


def test_the_tenant_and_user_are_never_in_the_body() -> None:
    """Both come from the token; a body that names them is a request to be someone else."""
    body = _launcher().run_body(
        agent="docker", risk_tier="T0", pack="docker-1.0.0", alias="auto/best-fast", task=""
    )
    assert "tenant_id" not in body
    assert "user_id" not in body


def test_a_setting_prefers_the_environment_and_then_the_secret_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    launcher = _launcher()
    monkeypatch.setattr(launcher, "SECRETS_DIR", tmp_path)
    (tmp_path / "keycloak_admin_password").write_text("from-file\n", encoding="utf-8")

    monkeypatch.delenv("KEYCLOAK_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("KEYCLOAK_ADMIN_PASSWORD_FILE", raising=False)
    assert launcher.setting("KEYCLOAK_ADMIN_PASSWORD") == "from-file"

    monkeypatch.setenv("KEYCLOAK_ADMIN_PASSWORD", "from-env")
    assert launcher.setting("KEYCLOAK_ADMIN_PASSWORD") == "from-env"


def test_a_setting_that_exists_nowhere_is_empty_not_an_error(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    launcher = _launcher()
    monkeypatch.setattr(launcher, "SECRETS_DIR", tmp_path)
    monkeypatch.delenv("CITADEL_DEV_PASSWORD", raising=False)
    monkeypatch.delenv("CITADEL_DEV_PASSWORD_FILE", raising=False)
    assert launcher.setting("CITADEL_DEV_PASSWORD") == ""
