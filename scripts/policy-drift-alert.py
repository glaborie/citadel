"""Run the policy drift check on a schedule and raise an alert when it drifts.

Scheduled by `deploy/systemd/citadel-policy-drift.timer`; the install steps and
the alert wiring are in `docs/operations/policy-drift-check.md`.

`make policy-drift` (#277) is read-only, so a scheduled run is safe on a live
stack. This wrapper is the part a scheduler needs:

* exit 0 - nothing to say. A passing check that logs every hour is how people
  learn to ignore the unit.
* exit 1 - drift. Logs a `crit` line naming the repair and exits 1, so the unit
  enters `failed` and `systemctl --user --failed`, plus any `OnFailure=` unit,
  see it.
* exit 2 - the check could not compare (store absent, credential absent, stack
  down). Alerted at `err` and kept distinct from drift: a broken check that
  reports "drift" every hour is a check that gets muted, and one that reports
  "fine" is worse.

The stack ships no Alertmanager (#256), so delivery is the journal, the failed
unit state and one `OnFailure=` line the operator points at their own channel.
Nothing here writes to the store: the wrapper runs the read-only target.
"""

from __future__ import annotations

import http.client
import os
import subprocess
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Final
from urllib.parse import urlsplit

TAG: Final = "citadel-policy-drift"

DRIFT: Final = (
    "POLICY DRIFT: the OpenFGA store does not match policy/model.json, the tool "
    "catalog or the versioned tuple set. Run `make policy-drift` for the diff, "
    "then `make policy-bootstrap` for the missing tuples; an unexpected tuple is a "
    "grant no reviewed file makes, so remove it deliberately rather than "
    "re-seeding around it."
)

UNKNOWN: Final = (
    "POLICY DRIFT CHECK FAILED: the check could not compare (store absent, "
    "credential absent, or the stack is down). This is not 'no drift'."
)

# `make policy-drift` needs the compose project and the Keycloak admin password,
# and both come from the SOPS file the Makefile targets already use. The command
# is ONE argv element on purpose: sops 3.13 reads every further positional as
# another file to decrypt and answers `error: missing file to decrypt`.
COMMAND: Final[tuple[str, ...]] = (
    "sops",
    "exec-env",
    "secrets/citadel.env",
    "make policy-drift",
)

# The loopback publish of `pushgateway` in compose.yaml. Prometheus cannot scrape
# a host timer, so the verdict travels the other way (see docs/architecture/metrics.md).
PUSH_DEFAULT: Final = "http://127.0.0.1:19091"
JOB: Final = "citadel_policy_drift"

Check = Callable[[], int]
Notify = Callable[[str, str], None]
Push = Callable[[int], None]


def repo_root() -> Path:
    return Path(os.environ.get("CITADEL_REPO_DIR", Path(__file__).resolve().parents[1]))


def run_check(repo: Path) -> int:
    """Run the documented target in the repository; its exit code is the verdict."""
    try:
        return int(subprocess.run(COMMAND, cwd=repo, check=False).returncode)
    except OSError as exc:  # sops or make missing: could not check, not drift
        print(f"cannot run {COMMAND[0]}: {exc}", file=sys.stderr)
        return 2


def syslog(priority: str, message: str) -> None:
    """A journal line an operator, or a log shipper, can alert on."""
    try:
        subprocess.run(
            ["logger", "-p", f"user.{priority}", "-t", TAG, message],
            check=False,
        )
    except OSError:
        # No logger on this host is not a reason to lose the alert.
        print(f"{TAG}: {message}", file=sys.stderr)


def payload(code: int, now: float) -> str:
    """The gauges one run leaves behind, whatever the verdict.

    The verdict is numeric so the alert is `max(...) > 0` rather than a label
    comparison, and drift and "could not run" are different series so the second
    can never satisfy the first.
    """
    drift = 1 if code == 1 else 0
    failed = 0 if code in (0, 1) else 1
    return (
        "# TYPE citadel_policy_drift gauge\n"
        f"citadel_policy_drift {drift}\n"
        "# TYPE citadel_policy_drift_check_failed gauge\n"
        f"citadel_policy_drift_check_failed {failed}\n"
        "# TYPE citadel_policy_drift_last_run_timestamp_seconds gauge\n"
        f"citadel_policy_drift_last_run_timestamp_seconds {now:.0f}\n"
    )


def push(code: int, url: str | None = None) -> None:
    """Replace this job's series in the pushgateway. Raises on any failure."""
    base = url or os.environ.get("CITADEL_PUSHGATEWAY_URL") or PUSH_DEFAULT
    parts = urlsplit(base)
    if parts.scheme != "http" or not parts.hostname:
        raise ValueError(f"pushgateway URL must be http://host[:port], got {base!r}")
    connection = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=5)
    try:
        connection.request(
            "POST",
            f"/metrics/job/{JOB}",
            body=payload(code, time.time()).encode(),
            headers={"Content-Type": "text/plain"},
        )
        response = connection.getresponse()
        response.read()
        if response.status >= 300:
            raise OSError(f"pushgateway answered {response.status}")
    finally:
        connection.close()


def main(
    check: Check | None = None,
    notify: Notify | None = None,
    push_metrics: Push | None = None,
) -> int:
    runner = check if check is not None else (lambda: run_check(repo_root()))
    send = notify if notify is not None else syslog
    publish = push_metrics if push_metrics is not None else push

    code = runner()
    try:
        publish(code)
    except (OSError, ValueError) as exc:
        # Telemetry is not a control (ADR-015): a pushgateway that is down must not
        # turn a clean check into a failure, nor a drift into silence - the journal
        # line and the unit state still carry the verdict.
        send("err", f"policy drift metrics not pushed: {exc}")

    if code == 0:
        print("policy drift: none")
        return 0

    message = DRIFT if code == 1 else f"{UNKNOWN} (check exited {code})"
    send("crit" if code == 1 else "err", message)
    print(message, file=sys.stderr)
    return 1 if code == 1 else 2


if __name__ == "__main__":
    raise SystemExit(main())
