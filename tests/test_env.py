"""Secret lookup: a mounted file first, the environment only as a fallback."""

from __future__ import annotations

from pathlib import Path

import pytest

from citadel.env import optional_secret, secret


def test_mounted_file_wins(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    path = tmp_path / "value"
    path.write_text("from-file\n", encoding="ascii")
    monkeypatch.setenv("DEMO_SECRET_FILE", str(path))
    monkeypatch.setenv("DEMO_SECRET", "from-env")
    assert secret("DEMO_SECRET") == "from-file"


def test_environment_is_the_local_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEMO_SECRET_FILE", raising=False)
    monkeypatch.setenv("DEMO_SECRET", "from-env")
    assert secret("DEMO_SECRET") == "from-env"


def test_unset_secret_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEMO_SECRET_FILE", raising=False)
    monkeypatch.delenv("DEMO_SECRET", raising=False)
    with pytest.raises(KeyError):
        secret("DEMO_SECRET")


def test_optional_secret_is_empty_when_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DEMO_SECRET_FILE", raising=False)
    monkeypatch.delenv("DEMO_SECRET", raising=False)
    assert optional_secret("DEMO_SECRET") == ""
