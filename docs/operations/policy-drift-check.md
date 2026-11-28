# Scheduled policy drift check (#281)

`make policy-drift` compares the OpenFGA store with the versioned policy and exits
1 when they disagree (#277). This is how it runs without a human: an hourly user
timer, a `crit` journal line when it drifts, and a failed unit that `OnFailure=`
can route anywhere.

## Install

```bash
mkdir -p ~/.config/systemd/user
cp ~/projects/citadel/deploy/systemd/citadel-policy-drift.{service,timer} ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now citadel-policy-drift.timer
systemctl --user list-timers citadel-policy-drift.timer
```

`cp` rather than `systemctl --user link` so the units can be installed from a
branch before they are merged, and re-copied after an edit. `link` tracks the
repository copies instead, once they are on the default branch.

The service skips the hour instead of failing it when the checkout has no
`scripts/policy-drift-alert.py` (`ConditionPathExists`), so a rollback or a
bisect does not page anyone.

A **user** unit, not a system one: the check unwraps `secrets/citadel.env` with
the operator's SOPS age key. Root does not have that key, and granting root the
secrets to make a read-only check run is the wrong trade.

## Verify

```bash
systemctl --user start citadel-policy-drift.service
journalctl --user -u citadel-policy-drift.service -n 30
```

Exit 0 prints `policy drift: none` and sends nothing. Exit 1 logs a `crit` line
naming the repair and leaves the unit failed. Exit 2 logs at `err`: the stack is
down, the credential is missing, or the check itself is broken.

`make policy-drift` and the timer both run `scripts/policy-drift.sh`. That is not
cosmetic: GNU make rewrites a failed recipe to exit 2, so a target in this path
made a real drift verdict arrive as "could not compare" and fired the warning
alert instead of the critical one (#287).

If the store container is not healthy the unit is **skipped**, not failed
(`ExecCondition` in the service): "the stack is off" is not drift, and an hourly
false alarm is how a unit gets muted.

## What fires

| Situation | Journal | Unit | Exit |
|---|---|---|---|
| store matches the versioned policy | the report, no alert | success | 0 |
| store drifted | `crit` `POLICY DRIFT: …` | failed | 1 |
| could not compare | `err` `POLICY DRIFT CHECK FAILED: …` | failed | 2 |
| store container not healthy | — | skipped | — |

Repair: `make policy-drift` for the diff, then `make policy-bootstrap` to write
the missing tuples and reload the committed model. An **unexpected** tuple is a
grant no reviewed file makes — remove it deliberately rather than re-seeding
around it, because re-seeding leaves it in place.

## The gauge (#285)

Every run, whatever the verdict, pushes three series to the stack's
`pushgateway` (published on `127.0.0.1:19091`, scraped by Prometheus over the
internal network):

| Series | Value |
|---|---|
| `citadel_policy_drift` | 1 when the store drifted, 0 otherwise |
| `citadel_policy_drift_check_failed` | 1 when the run could not compare (exit 2) |
| `citadel_policy_drift_last_run_timestamp_seconds` | when the run happened |

`CITADEL_PUSHGATEWAY_URL` overrides the default. A pushgateway that is down is
logged at `err` and changes nothing else: the exit code and the journal still
carry the verdict, because telemetry is not a control (ADR-015).

The service joins `edge` as well as `internal`: Docker **ignores a published
port on an internal-only network**, silently, so the host job could not reach it
and every push failed with a connection refused while the check still exited 0
(#287). The bind is `127.0.0.1`, so nothing off-host reaches the gauges.

`docker/prometheus/rules/citadel.yml` turns those series into three alerts, all
visible in Grafana's "Firing alerts" panel and Prometheus' `/alerts`:

| Alert | Fires when |
|---|---|
| `CitadelPolicyDrift` | the last run found drift (critical, 1 m) |
| `CitadelPolicyDriftCheckFailed` | the last run could not compare (warning, 5 m) |
| `CitadelPolicyDriftStale` | no report for two hours, or never (warning, 10 m) |

The staleness alert is the one that matters as much as the others: a timer that
stopped is indistinguishable from a store that matches.

## Delivery

The stack ships no Alertmanager (#256), so nothing pages out of the box. Four
surfaces exist today:

- `CitadelPolicyDrift` and its two siblings firing in Grafana (below);
- `systemctl --user --failed` — the unit is failed on 1 and 2;
- `journalctl --user -p crit -t citadel-policy-drift` — and any log shipper that
  reads the journal;
- the unit's exit status, which any `OnFailure=` unit receives.

To route it elsewhere, one line in the service's `[Unit]` section:

```ini
OnFailure=citadel-alert@%n.service
```

with a template unit that calls whatever the site already uses. The check and its
alert are here; the delivery channel is the operator's, which is why this is a
documented limit rather than a hidden default.

## Without systemd

```bash
# crontab -e
17 * * * * cd "$HOME/projects/citadel" && /usr/bin/python3 scripts/policy-drift-alert.py >> "$HOME/policy-drift.log" 2>&1
```

The wrapper sets `CITADEL_REPO_DIR` from its own location, so `cd` is a
convenience. cron reports a non-zero exit to the owner when a mail transport
exists; the log file carries the report either way.

## Limits

`sops exec-env` failing to unwrap the secrets exits 1, the same code as drift, so
a broken unwrap is reported as drift. The sops error sits above the alert in the
same log, and either way the unit fails: a scheduled check that cannot produce
its report is a problem, never a pass.

`pushgateway` has no authentication, so anything that can reach it on the
`internal` network can replace the series — including with a `0` that hides a
drift. It is not a control for that reason: the journal, the unit state and the
check's own output are the record, and the gauge exists to make drift visible in
the dashboards. The alternative, a long-running container holding the Keycloak
admin credential to export its own metric, trades that risk for a worse one.
