"""Issue #281: the scheduled drift check turns its exit code into an alert.

A scheduled check is only worth having if its failure reaches someone. The
wrapper's contract is three exit codes, and the units have to run the wrapper:
both are asserted here, without a stack or a daemon.
"""

from __future__ import annotations

import configparser
import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "policy-drift-alert.py"
SERVICE = ROOT / "deploy" / "systemd" / "citadel-policy-drift.service"
TIMER = ROOT / "deploy" / "systemd" / "citadel-policy-drift.timer"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("policy_drift_alert", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cli = _load()


def _unit(path: Path) -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(path, encoding="utf-8")
    return parser


def test_a_clean_store_is_quiet(capsys: object) -> None:
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 0, notify=lambda p, m: alerts.append((p, m))) == 0
    assert alerts == [], "a passing hourly job must not send anything"


def test_drift_alerts_at_crit_and_exits_one(capsys: object) -> None:
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 1, notify=lambda p, m: alerts.append((p, m))) == 1
    assert [priority for priority, _ in alerts] == ["crit"]
    message = alerts[0][1]
    assert "POLICY DRIFT" in message
    assert "make policy-drift" in message and "make policy-bootstrap" in message


def test_could_not_compare_is_its_own_alert() -> None:
    """Exit 2 is a broken check, not a drifted store; conflating them gets the unit muted."""
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 2, notify=lambda p, m: alerts.append((p, m))) == 2
    assert [priority for priority, _ in alerts] == ["err"]
    assert "could not compare" in alerts[0][1]
    assert "POLICY DRIFT:" not in alerts[0][1]


def test_an_unexpected_exit_code_is_not_a_pass() -> None:
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 125, notify=lambda p, m: alerts.append((p, m))) == 2
    assert "check exited 125" in alerts[0][1]


def test_the_wrapper_runs_the_read_only_target() -> None:
    assert cli.COMMAND[-1] == "make policy-drift", (
        "the scheduled job must run the read-only target, never the bootstrap"
    )
    assert "policy-bootstrap" not in " ".join(cli.COMMAND)
    # sops 3.13 reads every further positional as a file, so the command stays
    # one argument; measured: two arguments answer "missing file to decrypt".
    assert len(cli.COMMAND) == 4


def test_the_service_runs_the_wrapper_as_a_user_unit() -> None:
    service = _unit(SERVICE)["Service"]

    assert service["type"] == "oneshot"
    assert service["execstart"].endswith("scripts/policy-drift-alert.py")
    assert "openfga" in service["execcondition"], (
        "a skipped run while the store is down is not a drift alert"
    )
    assert service["conditionpathexists"].endswith("scripts/policy-drift-alert.py"), (
        "a checkout without the wrapper must skip the hour, not fail it"
    )
    assert service["workingdirectory"].endswith("projects/citadel")


def test_the_timer_schedules_the_service_hourly() -> None:
    timer = _unit(TIMER)["Timer"]

    assert timer["oncalendar"] == "hourly"
    assert timer["persistent"] == "true"
    assert timer["unit"] == "citadel-policy-drift.service"
    assert _unit(TIMER)["Install"]["wantedby"] == "timers.target"


def test_the_unit_points_at_the_script_in_this_checkout() -> None:
    """`%h/projects/citadel` is the documented checkout; resolve its tail here."""
    assert SCRIPT.exists()
    execstart = _unit(SERVICE)["Service"]["execstart"]
    relative = execstart.split("projects/citadel/", 1)[1]
    assert (ROOT / relative).exists(), f"ExecStart points at {relative}, which does not exist"
