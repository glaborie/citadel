# Policy drift runbook (#300)

What to do when `CitadelPolicyDrift`, `CitadelPolicyDriftCheckFailed` or
`CitadelPolicyDriftStale` fires, or when the hourly unit shows as failed.
`policy-drift-check.md` explains how the chain works and how to install it; this
file is the response. Everything here is safe to run on a live stack: the check is
read-only, and the two writes named below are the ones that repair.

## First two minutes

```bash
systemctl --user list-timers citadel-policy-drift.timer
systemctl --user show citadel-policy-drift.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp
journalctl --user -u citadel-policy-drift.service -n 40 --no-pager
```

The last two journal lines say which case you are in: `policy drift: none` (exit
0), `POLICY DRIFT: …` (1) or `POLICY DRIFT CHECK FAILED: …` (2). Then ask the
store directly, which is slower and authoritative:

```bash
make policy-drift        # 0 clean, 1 drifted, 2 could not compare
```

It must run from the checkout that holds `secrets/` and the operator's age key,
because the check unwraps `secrets/citadel.env` through sops.

| Verdict | Alert | Section |
|---|---|---|
| 1, drift reported | `CitadelPolicyDrift` (critical) | [The store really differs](#a-verdict-of-1-the-store-really-differs) |
| 2, nothing compared | `CitadelPolicyDriftCheckFailed` (warning) | [Nothing was compared](#a-verdict-of-2-nothing-was-compared) |
| no report for 2 h | `CitadelPolicyDriftStale` (warning) | [Nothing reported](#nothing-reported-for-two-hours) |

The dashboard's "Policy drift verdict" panel shows the same split: a green `0`
next to `could not compare 1` is the second case, not health.

## A verdict of 1: the store really differs

`make policy-drift` prints a `model:` line and a `tuples:` line. Those two lines
name the shape of the problem:

| Report | Meaning | Repair |
|---|---|---|
| `model: DRIFTED` | the model enforcing the store is not `policy/model.json` | [model](#the-model-drifted) |
| `tuples: N of M present`, N < M | a grant the reviewed set makes is absent, so a tool or a membership silently denies | `make policy-bootstrap` |
| `unexpected` names a tuple | a grant no reviewed file makes: authority nobody reviewed | [unexpected tuple](#an-unexpected-tuple) |

### Missing tuples

```bash
make policy-bootstrap     # writes the committed model, adds every missing tuple
make policy-drift         # expect exit 0 and "0 unexpected"
```

Bootstrap only adds. It never removes a tuple, which is why re-seeding is not a
repair for the next case.

### The model drifted

```bash
make policy-model         # regenerate policy/model.json from policy/model.fga
make policy-bootstrap     # write that model to the store
make policy-drift
```

Only run `make policy-model` if `policy/model.fga` is the intended model. If
someone wrote the store by hand instead, do **not** regenerate to match it:
`model.fga` is the reviewed artifact, `policy_version()` hashes the committed
file, so an in-place edit both skips review and leaves the cache key describing
something other than what is enforced. Revert the store to the committed model,
then treat whatever change was in it as a normal reviewed change.

### An unexpected tuple

An unexpected tuple is a grant no reviewed file makes. It is the case the check
exists for, and there are only two honest outcomes: remove it, or admit it into
the versioned set. Re-seeding leaves it in place, so `make policy-bootstrap` is
not a fix here.

Remove it, using the store id from the report:

```bash
docker run --rm --network citadel_internal \
  openfga/cli:latest@sha256:7a7f9fb0a27a788a0fa7907eb5fc751c3134ca0776245578308e011606b61091 \
  tuple delete --store-id "$STORE" --api-url http://openfga:8080 \
  user:<subject> <relation> <object>
```

The CLI is pinned to the same digest `make policy-model` uses. `--on-missing
ignore` makes the command idempotent; it prints `{}` and exits 0 either way (that
path is what was verified against the live store, on a tuple that did not exist).
Read the tuple before deleting it: removing a reviewed grant denies someone
silently, which is the failure the check reports in the other direction.

To admit it instead, add the tuple to `tuples_for()` in
`src/citadel/policy/bootstrap.py`. The versioned set is code, so the grant arrives
through review like any other change; then `make policy-bootstrap` and
`make policy-drift`.

## A verdict of 2: nothing was compared

Exit 2 is not drift and not clean: the store was never compared. The journal line
is `POLICY DRIFT CHECK FAILED: …`. In this order:

1. **sops.** `sops exec-env secrets/citadel.env 'true'` fails here when the age
   key is missing or the secrets file is broken. A sops failure exits 1 and
   therefore *looks like drift*: if the journal has no `store …` line, the check
   never ran and the drift alert is the wrong one.
2. **The stack.** `docker compose ps openfga keycloak` — both healthy. When
   openfga is not running the unit is *skipped*, so a skip means the stack was
   off, not that a comparison failed.
3. **The credential.** The check runs through the `policy-bootstrap` one-shot
   because resolving dev usernames needs the Keycloak admin password for that
   run. `make policy-bootstrap` surfaces the same failure with its reason.
4. **The check itself.** `make policy-drift` prints the traceback. `make
   policy-drift-live` proves the path end to end by mounting a mutated model and
   expecting exit 1; if that fails, fix the path before trusting any verdict.

## Nothing reported for two hours

`CitadelPolicyDriftStale` fires when the pushed timestamp is older than 7200 s,
or when it is absent. Absent is the harsher case: nothing ever reported.

```bash
systemctl --user list-timers citadel-policy-drift.timer
systemctl --user status citadel-policy-drift.timer
systemctl --user is-failed citadel-policy-drift.service
journalctl --user -u citadel-policy-drift.service --since "3 hours ago"
```

`is-failed` answers with this unit only (`failed` for exit 1 or 2, `inactive` for a
skipped run). `systemctl --user --failed` on its own lists every unit on the host,
so it reports unrelated failures — a dead `pulseaudio.service` is not your
incident.

- **Timer missing or inactive.** Install or re-enable it; the steps are in
  `policy-drift-check.md`. A user timer also stops when the user manager exits at
  logout: `loginctl enable-linger "$USER"` if the host must check with nobody
  logged in.
- **Unit failed on 1 or 2.** Not a stale report: work the two sections above.
- **Unit skipped, stack off on purpose.** Expected. No run means no push, so the
  timestamp ages and the alert says exactly what is true — nothing compared.
  Keep the stack up, or accept the alert as the cost of a maintenance window.
- **Journal clean, runs hourly, gauge missing.** The push failed; the wrapper
  logs it at `err` and still exits with the verdict (telemetry is not a control,
  ADR-015). Check `curl -s http://127.0.0.1:19091/metrics | grep '^citadel_policy_drift'`
  and `docker compose ps pushgateway`.

## Confirm the fix, whatever it was

```bash
make policy-drift         # exit 0
make policy-drift-live    # exit 0: the post-deploy gate
systemctl --user start citadel-policy-drift.service
systemctl --user show citadel-policy-drift.service -p Result -p ExecMainStatus
curl -s http://127.0.0.1:19091/metrics | grep '^citadel_policy_drift'
```

Expect `Result=success`, exit 0, `drift 0`, `check_failed 0` and a fresh
timestamp. Prometheus resolves the alert after its `for:` (1 m for drift, 5 m for
check-failed, 10 m for stale) plus a scrape, and the two panels in "Citadel
controls" read `0`, `0` and an age under an hour.

## What to record

The verdict line, the `model:` and `tuples:` lines, what the difference was, and
which decision was taken for an unexpected tuple — removed, or versioned in
`tuples_for()`. The journal and the unit state are the record; the gauge is not,
because `pushgateway` has no authentication and anyone on the `internal` network
can replace the series. Keep tenant identities, subject ids and credentials out of
the repository and out of the ticket where it is not needed: the tuple subjects
here are dev usernames, but a real IdP subject belongs with the incident.
