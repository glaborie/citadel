# Policy drift detection (#277)

`make policy-drift` compares the OpenFGA store with the versioned policy and
exits non-zero when they disagree. It writes nothing.

## Why it exists

The versioned policy is three files: `policy/model.fga` (generated into
`policy/model.json`), the tool catalog `src/citadel/policy/tools.json`, and the
tuple set `citadel.policy.bootstrap.tuples_for` derives from them. The store is a
copy of that intent, and until #277 nothing compared the copy with the source.

The failure that motivated it is the one from #273: `compose_config` and
`inspect_container` were in the catalog but had no tuples, so `authorize()`
denied them for every user. Fail-closed is correct there — the symptom was not a
leak but a tool that silently did not work, with the denial visible only by
digging the run out of Temporal. The other two directions never show up at all:
a tuple the versioned set no longer grants stays in the store as authority nobody
reviewed, and a model written to the store without editing `model.fga` skipped
review (and `policy_version()` keeps hashing the committed file, so the cache key
stops describing what is enforced).

## What it compares

| Check | Meaning of a difference |
|---|---|
| tuples in the versioned set that the store lacks | a denial that will happen, per `(user, relation, object)` |
| tuples in the store the versioned set does not grant | a stale grant: authority no reviewed file expresses |
| the model the store enforces, per type, against `policy/model.json` | a policy change that skipped review, or a store that was never loaded |

The model the store enforces is the newest one it holds (`GET
/stores/{id}/authorization-models?page_size=1`), which is what OpenFGA uses when
a check names no model id.

The expected tuple set is built by the same `tuples_for` and `sub_ids` helpers
`make policy-bootstrap` writes with, so the check cannot drift from the write.
Both need the Keycloak admin credential to resolve dev usernames to subs, which
is why `make policy-drift` runs through the existing `policy-bootstrap` one-shot:
that credential is mounted for the one run and is not held by any long-running
service (#273).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | the store matches the versioned policy |
| 1 | drift; the report names every difference |
| 2 | could not compare — store absent, credential absent, service unreachable, bad usage |

`2` is separate from `1` on purpose: "I could not look" must never be read as
"clean", and an operator repairing drift needs to know which one happened.

## Read-only, and proven so

The module makes no write call; `tests/test_policy_drift.py` asserts the source
does not contain `write_tuples` or `write_authorization_model`, so a future edit
that turns the check into a repair has to delete the test. That is what makes the
target safe on a live stack and in cron — unlike `make policy-bootstrap`, which
writes.

## Measured against the local stack

Clean, 2026-11-28:

```
$ make policy-drift
store 01M84AEV3Y39912S4DK9855R15 (enforcing model 01M8GX01QKE7XA1ZD4N654DZDS)
model: matches policy/model.json
tuples: 65 of 65 present, 0 unexpected
ok: the store matches the versioned policy
exit 0
```

Positive control: the same check against a copy of the committed model with one
extra type (`service_account`), passed as `CITADEL_POLICY_MODEL` and mounted
read-only. Nothing in the store was touched:

```
model: DRIFTED from policy/model.json
  types only in policy/model.json: service_account
tuples: 65 of 65 present, 0 unexpected
exit 1
```

## Traps recorded

- **The API's model JSON is not the file's JSON.** OpenFGA answers
  protobuf-JSON defaults the committed file never carries — `module: ""`,
  `source_info: null`, `conditions: {}`, `directly_related_user_types[].condition:
  ""`, `computedUserset.object: ""`, and `relations: {}` on a type that has none.
  A raw canonical comparison reported **all four types drifted on a store that was
  exactly right**; that was the check's first live run. `_strip_defaults` removes
  those defaults before comparing, keeping `this` and `wildcard`, whose empty
  object is the meaning.
- **`union.child` order is not meaning.** It is a list in the JSON and a set in
  the model, so both sides sort it before comparing and a reordered store does not
  read as drift.
- **The model id is a ULID, not a content hash.** It changes on every write of an
  identical model, so the check compares type definitions rather than ids, and
  `policy_version()` stays the digest for cache keys.
- **A missing tuple can be named; an unknown object cannot.** The expected set is
  built from `TENANTS` and the catalog. A tenant or membership created outside
  them shows up as an unexpected tuple, never as a missing one.

## Limits

- Offline CI does not run it: it needs the stack, Keycloak and the admin
  credential. `make check` stays offline; this is an operator target, like
  `make audit-verify`.
- Tuples other components might write in a later milestone would appear as
  unexpected until the expected set learns about them. Nothing writes tuples
  except the bootstrap today.
