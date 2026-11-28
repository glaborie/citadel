"""Issue #281: the scheduled drift check turns its exit code into an alert.

A scheduled check is only worth having if its failure reaches someone. The
wrapper's contract is three exit codes, and the units have to run the wrapper:
both are asserted here, without a stack or a daemon.
"""

from __future__ import annotations

import configparser
import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

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


def _stand_ins(tmp_path: Path, status: str) -> tuple[Path, Path]:
    """A `sops` that execs its single command argument, and a `docker` that exits `status`.

    These are the only two things between the real script and the real verdict, so
    the test keeps the production path and replaces decryption and Docker. `shift
    2` is deliberate: `sops exec-env <file> '<command>'` is the shape the script
    relies on, and a change to it should break this loudly rather than quietly.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    argv_log = tmp_path / "sops.argv"
    sops = bin_dir / "sops"
    sops.write_text(
        "#!/bin/sh\n"
        f'printf "%s\\n" "$#" >> "{argv_log}"\n'
        f'for arg in "$@"; do printf "%s\\n" "$arg" >> "{argv_log}"; done\n'
        "shift 2\n"
        'exec sh -c "$1"\n',
        encoding="utf-8",
    )
    docker = bin_dir / "docker"
    docker.write_text(f"#!/bin/sh\nexit {status}\n", encoding="utf-8")
    sops.chmod(0o755)
    docker.chmod(0o755)
    return bin_dir, argv_log


@pytest.mark.parametrize(
    ("stand_in_status", "expected_code", "expected_alert"),
    [("0", 0, None), ("1", 1, "crit"), ("2", 2, "err")],
)
def test_every_exit_code_reaches_its_alert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    stand_in_status: str,
    expected_code: int,
    expected_alert: str | None,
) -> None:
    """The bug of #287: a layer between the check and the wrapper rewrote the code.

    `make` turned the check's 1 into 2, so real drift raised the warning alert and
    never the critical one. Nothing asserted the code that came back, only the
    shape of the command. Here the real script and the real `run_check` run end to
    end; whatever the check returns is what the wrapper has to classify.
    """
    bin_dir, argv_log = _stand_ins(tmp_path, stand_in_status)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    alerts: list[tuple[str, str]] = []

    code = cli.main(
        check=lambda: cli.run_check(ROOT),
        notify=lambda priority, message: alerts.append((priority, message)),
        push_metrics=lambda _code: None,
    )

    assert code == expected_code, f"the check said {stand_in_status}, the wrapper returned {code}"
    assert [priority for priority, _ in alerts] == (
        [] if expected_alert is None else [expected_alert]
    )

    argv = argv_log.read_text(encoding="utf-8").splitlines()
    assert argv[0] == "3", "sops takes exec-env, the file and ONE command argument"
    assert argv[1] == "exec-env" and argv[2] == "secrets/citadel.env"
    assert "python -m citadel.policy.drift" in argv[3]
    assert "make" not in argv[3], "no make in the path, or the code is not the check's"


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
