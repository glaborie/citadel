# v0.1 exit review

**Date:** 2026-11-25
**Basis:** a live Compose stack on the owner's host (17 containers healthy), a
clean clone of `master` at `486180e`, and the red-team pack with the live cases
enabled.
**Scope:** `docs/milestones.md` §v0.1, `docs/adr/ADR-008.md` decision 5.

## Verdict

The v0.1 controls are built and verified end to end. Four of the five exit
criteria are met as written. The fifth cannot be met as written, because it asks
for something the project's own ground rules forbid — recorded as **D1** and left
for the owner to reword rather than quietly changed here. Two scope deltas
(**D2**, **D3**) mean the milestone is complete as *specified* but not as
*imagined*: the model loop is not wired into the workflow, so no run sends a
prompt.

| # | Exit criterion | Verdict |
|---|---|---|
| 1 | A fresh clone with no hidden files starts the stack and passes all tests | **Partial** — install and tests proven; stack start is impossible by design (**D1**) |
| 2 | Red-team suite proves the five listed attacks are blocked | **Met** — 21 of 21 v0.1 cases pass, live |
| 3 | One recorded trace shows policy, DLP, approval and tool with matching audit IDs | **Met** — re-verified in MLflow and in `audit_events` |
| 4 | `ADR-008` roadmap reconciled with delivered scope | **Met** — reconciliation section added to the ADR |
| 5 | Skill packs for the three specialists, hash-pinned and versioned | **Met** — content, loader and checked provenance; consumption is **D2** |

## Criterion 1 — clean clone

`./scripts/clean-clone-check.sh` clones the repository into a temporary directory
and fails if the clone carries anything ignored or untracked. This run:

| Step | Result |
|---|---|
| `git status --porcelain --ignored` on the clone | empty |
| `uv sync --frozen` | ok |
| `uv run ruff check .` | clean |
| `uv run mypy` | clean, 88 files |
| `uv run pytest` | 357 passed, 31 skipped |

**D1.** The criterion also says *starts the stack*. It cannot, and should not: the
stack needs `POSTGRES_PASSWORD`, `CITADEL_DB_PASSWORD`, the run-token keys and the
OmniRoute secrets, which ground rule 7 keeps out of the repository and which the
owner supplies through an untracked `.env`. A clone with no hidden files therefore
has no secrets by construction. The stack is verified on the host instead (17
containers running, 17 healthy, health checks green) and `docker compose config -q`
validates the file from a clean tree. Proposed wording for v0.2: *"a fresh clone
with no hidden files installs, passes all tests and validates its Compose
configuration; starting the stack requires the owner's untracked secrets."*

## Criterion 2 — red-team proofs

Regenerated live (`CITADEL_LIVE=1 CITADEL_REDTEAM_REPORT=1 pytest -m "redteam or
live"`, report in `docs/evals/red-team-report.md`):

**25 of 29 cases blocked or denied as specified · 0 failing · 0 known gaps · 4
pending.** All 21 v0.1 cases pass. The four pending cases belong to later
milestones — `RT-INJ-02` (v0.2 retrieval), `RT-CACHE-01` and `RT-CACHE-02` (v0.3),
`RT-INJ-06` (v0.4 MCP) — so they do not hold this milestone open.

| Criterion | Case | Observed |
|---|---|---|
| Cross-tenant read blocked | `RT-AUTHZ-01` | live `/runs`: alice sees no foreign run; bob sees only `lab-b` |
| Unauthorized tool blocked | `RT-AUTHZ-03`, `RT-INJ-04` | live `/policy/authorize` → `deny/tool.unknown`; a skill naming `docker_prune_images` → `tool.unknown` |
| DLP failure blocks | `RT-DLP-04` | 503 `dlp_unavailable`, refused, never degraded to a pass |
| Expired approval blocks | `RT-HITL-03` | approval token rejected: `Signature has expired` |
| Duplicate idempotency key returns the original result | `RT-DUR-01`, `RT-DUR-02` | `executed/replayed/failed calls=1`; a seeded executed call with no event is reported by `unaudited()` |

## Criterion 3 — trace with matching audit IDs

Re-read from MLflow today, not quoted from an earlier note:

| Property | Value |
|---|---|
| trace | `tr-72fab0fd70d9442a92d733d1f28f8164`, state `OK`, 8 spans |
| spans | `run.start`, `policy.decision`, `approval.decision`, `dlp.event` ×3, `tool.call`, `run.end` |
| correlation | every span carries `citadel.run_id` and a distinct `citadel.audit_id` |

Queried `audit_events` as `citadel_app` under `SET app.tenant_id = 'lab-a'` — the
RLS-scoped path, not the superuser — and every span's `audit_id` is a row for the
same run, in the same order:

```text
69 run.start         ce8d9265-7e7d-4b22-a83b-8f49ee9ea50c
70 policy.decision   0f703e4a-f528-4075-a0c9-e4436ee61594
71 approval.decision 96b3cee4-7b67-4815-a168-5d72d25e53d9
72 dlp.event         ebc7f806-06cd-48d4-84a3-3f9ce89a83a7
73 dlp.event         c50a5c99-066d-40e2-8cbf-ac79c227ac51
74 dlp.event         197565ef-c079-4cdb-a01a-57f5eeb3c289
75 tool.call         0ceda2b1-6ff3-45d6-864d-0c12397e581d
76 run.end           2d72e7b3-08e3-41e4-90da-42c91c2506e5
```

The ledger chain itself verifies for both tenants (`lab-a` 104 events, `lab-b` 2).

## Criterion 4 — ADR-008 reconciled

See the reconciliation section in `docs/adr/ADR-008.md`. In short: v0.1 delivered
what it listed, with the model gateway delivered as library code rather than a
wired path (**D2**); three v0.2/v0.4 red-team surfaces were exercised early and
pass; no milestone scope moved *out* silently.

## Delivered scope against `docs/milestones.md` v0.1

| Included | State |
|---|---|
| Keycloak 26 OIDC, delegated run tokens, tenant claim | delivered; standard exchange V2 measured, RFC 8693 delegation rejected (`v0.1-verification.md` §5); run tokens are Ed25519-minted by the API |
| Temporal orchestrator + Docker + GitHub child workflows | delivered; approval wait/resume, retries and idempotency keys exercised |
| OpenFGA chokepoint, Postgres RLS, hash-chained audit | delivered; deny-by-default tests and RLS proofs in the red-team pack |
| Presidio DLP with AHV/Swiss IBAN, fail-closed | delivered; person names redacted after a vocabulary filter (PR #16) |
| T0 reads, two T1 writes, all T2 denied | delivered; `restart_service` and `open_remediation_pr` only |
| Approval console: five views | delivered; PKCE SSO, CSRF, server-side authorisation; browser round-trip verified by the owner, not by CI |
| Durable idempotency, OTel → MLflow, one golden trajectory | delivered; criterion 3 above |
| Skill packs, hash-pinned and versioned | delivered as content + loader + checked provenance; **consumption blocked by D2** |
| `.env` gitignored, `.env.example` synthetic | delivered; SOPS-wrapped `.env` unwrapped by `make up` |

## Deviations and deltas

**D1 — clean-clone stack start.** Criterion conflicts with ground rule 7. Not
fixed here; wording proposed above.

**D2 — the model loop is not wired.** `citadel.model.run_agent` and
`OmniRouteClient` exist, are typed, and are exercised by `tests/test_model.py` and
four red-team cases, but no activity or workflow calls them. Consequences: a run's
trajectory is the tool pipeline, not a model conversation; `prompt_pack_version` is
checked against a real pack but the pack text is never sent; `RT-EVAL-01` grades
the harness rather than a live loop. Tracked as an open issue rather than as a
finished result.

**D3 — MLflow human-path auth.** The OTLP write path is internal and unaffected;
the UI is unpublished, so no browser path exists to protect. Deferred until it is
published (ADR-017).

**D4 — skill packs.** Content, hashes, loader and ingress validation delivered;
`load_pack(agent).prompt()` has no caller yet (same root cause as D2).

**D5 — `RT-AUTHZ-01` scope.** The case proves the Postgres RLS surface live.
`retrieval.query.filter_set_hash` appears in its original rationale and is a v0.2
surface; the v0.1 case passes on the surface that exists.

## Residual findings from this review

1. **Nine `tool_calls` rows in `lab-a` have no `tool.call` event** — six written
   2026-11-23, three on 2026-11-25 before this review; 23 rows total. The window
   is structural: `execute_tool` marks the row `executed` and then appends the
   audit event, so a worker killed between the two leaves exactly this gap — the
   condition RT-DUR-02 detects rather than prevents. A fresh T0 run today
   (`dff62b77`, seq 107–112) produced policy, three DLP events, `tool.call` and
   `run.end`, and added no gap. Not an exit-criterion failure; a real finding for
   v0.2, where appending the event before settling the row closes the window.
2. **Documentation drift** — README claimed 265 tests and 15 containers; the
   project now has 357 and 17. Corrected in this change.
3. **`docs/architecture.md` §10** listed `qdrant`, `reranker`, `searxng` and
   `fetcher` among the Compose services; they are v0.2 and not in `compose.yaml`.
   Corrected in this change.

## Not proven

- The full browser OIDC round-trip has been done by the owner, not by CI or by
  this review.
- gVisor `runsc` is unavailable on the host; the Compose flags (`cap_drop: ALL`,
  read-only rootfs, no socket, allowlisted egress) are the actual isolation
  boundary.
- Live cases require the stack; a clone without secrets runs the offline suite
  only, and 31 tests skip by design.
- No judge-scored rubrics; only deterministic assertions run.

## What v0.2 inherits

Wire the model loop to the skill packs (D2/D4); retrieval with ACL filtering and
the Researcher worker; SOPS + age; judge rubrics; MLflow human-path auth only if
the UI is published; close the audit window in residual finding 1.
