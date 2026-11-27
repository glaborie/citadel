"""The CLI's contract with a caller that is not a person.

ADR-026 promises three things these tests hold: `--json` is one document and nothing else,
the exit code separates "failed" from "a dependency is down", and no command needs a prompt.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from citadel.cli import EXIT_OK, EXIT_UNAVAILABLE, EXIT_USAGE, doctor, main
from citadel.cli.doctor import Check, Report, run_checks

ROOT = pathlib.Path(__file__).resolve().parents[1]
DYNAMIC_URL = "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected"


def _ok(name: str) -> Check:
    return Check(name, doctor.OK, "fine")


def _down(name: str) -> Check:
    return Check(name, doctor.DOWN, "nothing answered", "make up")


def test_no_command_is_a_usage_error_not_success() -> None:
    assert main([]) == EXIT_USAGE


def test_an_unknown_command_is_a_usage_error() -> None:
    with pytest.raises(SystemExit) as raised:
        main(["fly"])
    assert raised.value.code == EXIT_USAGE


def test_doctor_is_healthy_when_every_probe_answers() -> None:
    report = run_checks([lambda: _ok("api"), lambda: _ok("mlflow")])
    assert report.healthy
    assert report.as_dict()["healthy"] is True


def test_one_down_dependency_makes_the_report_unhealthy() -> None:
    report = run_checks([lambda: _ok("api"), lambda: _down("mlflow")])
    assert not report.healthy


def test_a_down_dependency_exits_unavailable_not_failed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An agent must be able to tell 'denied' from 'broken' from 'dependency is down'."""
    monkeypatch.setattr(doctor, "run_checks", lambda: Report(checks=[_down("mlflow")]))
    assert doctor.run(as_json=True) == EXIT_UNAVAILABLE
    assert capsys.readouterr().out


def test_a_healthy_report_exits_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(doctor, "run_checks", lambda: Report(checks=[_ok("api")]))
    assert doctor.run(as_json=True) == EXIT_OK
    assert capsys.readouterr().out


def test_json_is_one_parseable_document(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(doctor, "run_checks", lambda: Report(checks=[_ok("api"), _down("mlflow")]))
    doctor.run(as_json=True)
    payload = json.loads(capsys.readouterr().out)
    assert payload["healthy"] is False
    assert {check["name"] for check in payload["checks"]} == {"api", "mlflow"}
    assert payload["checks"][1]["hint"] == "make up"


def test_the_text_report_names_the_hint(capsys: pytest.CaptureFixture[str]) -> None:
    doctor.emit(
        Report(checks=[_down("mlflow")]).as_dict(),
        as_json=False,
        text=doctor.render(Report(checks=[_down("mlflow")])),
    )
    out = capsys.readouterr().out
    assert "mlflow" in out and "make up" in out


def test_the_cli_suppresses_exactly_one_rule() -> None:
    """One call site for every request, on the same terms as the eval reader."""
    text = (ROOT / "src" / "citadel" / "cli" / "http.py").read_text(encoding="utf-8")
    assert text.count("# nosemgrep") == 1
    assert f"# nosemgrep: {DYNAMIC_URL}" in text
