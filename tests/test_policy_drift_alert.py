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

    assert cli.main(check=lambda: 0, notify=lambda p, m: alerts.append((p, m)),
             push_metrics=lambda _c: None) == 0
    assert alerts == [], "a passing hourly job must not send anything"


def test_drift_alerts_at_crit_and_exits_one(capsys: object) -> None:
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 1, notify=lambda p, m: alerts.append((p, m)),
             push_metrics=lambda _c: None) == 1
    assert [priority for priority, _ in alerts] == ["crit"]
    message = alerts[0][1]
    assert "POLICY DRIFT" in message
    assert "make policy-drift" in message and "make policy-bootstrap" in message


def test_could_not_compare_is_its_own_alert() -> None:
    """Exit 2 is a broken check, not a drifted store; conflating them gets the unit muted."""
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 2, notify=lambda p, m: alerts.append((p, m)),
             push_metrics=lambda _c: None) == 2
    assert [priority for priority, _ in alerts] == ["err"]
    assert "could not compare" in alerts[0][1]
    assert "POLICY DRIFT:" not in alerts[0][1]


def test_an_unexpected_exit_code_is_not_a_pass() -> None:
    alerts: list[tuple[str, str]] = []

    assert cli.main(check=lambda: 125, notify=lambda p, m: alerts.append((p, m)),
             push_metrics=lambda _c: None) == 2
    assert "check exited 125" in alerts[0][1]


def test_the_wrapper_runs_the_read_only_check_through_the_shared_script() -> None:
    assert cli.COMMAND[-1] == "scripts/policy-drift.sh", (
        "the target and the timer must not run different commands"
    )
    # make rewrites a failed recipe to exit 2: a drift verdict reached the wrapper
    # as "could not compare" and the critical alert never fired (#287).
    assert "make" not in " ".join(cli.COMMAND), "nothing behind make may decide the exit code"

    script = (ROOT / "scripts" / "policy-drift.sh").read_text(encoding="utf-8")
    assert "python -m citadel.policy.drift" in script
    assert "make policy-bootstrap" not in script, "the check must never repair what it reports"


def test_the_make_target_calls_the_shared_script() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    target = makefile.split("policy-drift:", 1)[1].split("\n\n", 1)[0]

    assert "bash scripts/policy-drift.sh" in target, (
        "the human target and the timer must run the same command"
    )


def test_the_service_runs_the_wrapper_as_a_user_unit() -> None:
    service = _unit(SERVICE)["Service"]

    assert service["type"] == "oneshot"
    assert service["execstart"].endswith("scripts/policy-drift-alert.py")
    assert "openfga" in service["execcondition"], (
        "a skipped run while the store is down is not a drift alert"
    )
    condition = service["execcondition"]
    assert "State.Running" in condition and "Health.Status" not in condition, (
        "openfga has no healthcheck, so a health condition skips the unit forever (#287)"
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
