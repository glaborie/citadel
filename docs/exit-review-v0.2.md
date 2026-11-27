# v0.2 exit review

**Date:** 2026-11-27
**Basis:** `master` at `ba4c8d1`, the offline suite (800 collected: 765 passed,
35 skipped), a regenerated red-team run, the eval baseline table, and the live
measurements recorded in `docs/implementation-notes/issue-132-secrets.md`. The
host has 24 Compose definitions: 22 long-running services, 20 with health checks
and all 20 healthy; `openfga-migrate` and `mlflow-bootstrap` are one-shot.
**Scope:** `docs/milestones.md` §v0.2, `docs/adr/ADR-008.md` decision 2.

## Verdict

The v0.2 included scope is built and all four exit criteria are met. One scope
delta is recorded rather than claimed as wired end to end: `RetrievalActivities`
is registered on the orchestrator worker and tested, but no workflow calls it
yet (**D1**). The milestone is complete as specified; D1 is the first item a
v0.3 run should close if retrieval is to be part of a live trajectory.

| # | Exit criterion | Verdict |
|---|---|---|
| 1 | ACL-filtered retrieval returns no unauthorized chunk in any tenant combination | **Met** — every pairing of `lab-a`, `lab-b` and `lab-c` reads only its own collection and payload; ACL is inside the Qdrant request |
| 2 | Citation validator fails runs with unsupported operational claims | **Met** — deterministic `citation.supported` fails an uncited claim, a citation to a non-retrieved source, and a `run.end` citation that resolves to nothing |
| 3 | No plaintext secret in repo, skill pack, trace, audit event, eval fixture or approval UI | **Met** — encrypted secret store, offline custody tests, and the recorded live sweep of every named surface |
| 4 | CI publishes a baseline eval result table with pinned model and prompt versions | **Met** — the `eval` job grades, publishes `eval-baseline.md` as the job summary and an artifact, then gates on the baseline |

## Criterion 1 — ACL-filtered retrieval

`tests/test_retrieval.py::test_every_tenant_pairing_only_sees_its_own_chunks`
ingests the same closest vector into a collection for each of three tenants and
then reads as each one. Every read returns its own `source_uri`, its own
collection, and no writer's chunk. The same test file proves:

- the ACL condition is inside the Qdrant prefetch filter, not applied after the
  search;
- the filter is built from the subject's entitlements and a request carrying
  another tenant's entitlements is refused;
- dense and sparse prefetches are fused with RRF, and reranking happens after
  redaction;
- `filter_set_hash` is tenant-scoped and never derived from the query text.

`tests/test_ingest.py::test_one_collection_per_tenant_and_nothing_crosses` covers
the ingestion half. The red-team case `RT-AUTHZ-01` is `live-only` and remains
pending in the offline report; its live executor is
`tests/redteam/live/test_stack.py`, and it is not replaced by the offline
pairing test.

## Criterion 2 — citation validator

`citation.supported` is deterministic. It reads the recorded answer as well as
`run.end.citation_ids`, so a citation list next to an uncited operational
sentence does not pass. Tests cover a missing citation, a citation naming a
source that was never retrieved, a `run.end` citation naming nothing retrieved,
and a general-reasoning sentence that needs no citation.

The graded fixtures are consistent with that rule:

```text
$ uv run python -m citadel.evals --table
155/155 checks passed across 14 cases
$ uv run python -m citadel.evals --gate
gate: 12 gating graders at or above baseline
```

The table is keyed by dataset version, `docker-1.0.0+github-1.0.0+researcher-0.2.0`
prompt packs and `auto/best-fast+auto/best-reasoning` model aliases, so a change
to any of them adds a row instead of rewriting the old one.

## Criterion 3 — no plaintext secret on a named surface

The tracked secret store is SOPS ciphertext. `make up` and `make rebuild` unwrap
it through `sops exec-env` into gitignored files under `secrets/`, and services
read Docker secret files rather than `Config.Env`. `tests/test_secrets_custody.py`
proves the tracked file is ciphertext only, every credential has an
`.env.example` placeholder, and nothing else under `secrets/` is tracked.

The live half is `tests/test_secret_surfaces_live.py`: it reads the provisioned
values without printing them and searches the source tree, eval fixtures, skill
packs, docs, the Postgres `audit_events`, `approval_requests`, `tool_calls` and
`tool_outputs` tables, and the MLflow SQLite store plus artifacts. The recorded
run in `docs/implementation-notes/issue-132-secrets.md` found none of the 15
provisioned values on any surface. That measurement was not repeated in this
review; the stack was up, but no new secret-bearing run was produced.

## Criterion 4 — CI baseline table

`.github/workflows/ci.yml` runs the eval job on the same changes filter as the
test job. It grades the fixtures, writes `eval-baseline.md` to the job summary
and uploads it as the `eval-baseline` artifact before the gate step, so a failing
run still publishes the table that explains the failure. The local equivalent
passes with all 12 gating graders at or above the recorded baseline.

## Delivered scope against `docs/milestones.md` v0.2

| Included | State |
|---|---|
| Filesystem + selected GitHub ingestion, content hashes, per-tenant Qdrant collections | delivered; `citadel.retrieval.ingest`, content-hash revisions, per-tenant collections |
| Dense + sparse hybrid retrieval, ACL inside the query, RRF, TEI reranker, structured citations | delivered; `citadel.retrieval.query`, `rerank`, `activities`; **caller is D1** |
| Researcher specialist: SearXNG + trafilatura fetcher, untrusted-content pipeline | delivered; `citadel.research`, `worker-researcher`, `searxng`, `fetcher`, `search_web`/`fetch_page`; `RT-INJ-02` passes |
| SOPS + age, Docker secrets injection | delivered; `secrets/citadel.env`, `.sops.yaml`, `scripts/provision-secrets.sh` |
| Offline eval suite with deterministic assertions and judge rubrics | delivered; 155/155 deterministic checks across 14 cases, judged rubrics report-only |
| D2/D4 inherited from v0.1: wire the model loop to the skill packs | delivered; `ModelActivities.next_step` assembles the pack and the workflow submits tasks |
| v0.1 residual: close the `tool_calls` audit window | delivered; `execute_tool` appends the audit event before settling the row |

## Red-team status

Regenerated with `make redteam-report`:

**31 of 35 cases blocked or denied as specified · 0 failing · 0 known gaps · 4
pending.** All v0.2 cases pass, including `RT-INJ-02` (retrieved-page injection:
both `prompt_injection` and `untrusted_external` flags reach the trajectory and no
write is executed). The four pending cases are the two live-only durability and
authorization cases (`RT-DUR-02`, `RT-AUTHZ-01`) and the two v0.3 cache cases
(`RT-CACHE-01`, `RT-CACHE-02`); none belongs to v0.2.

## Deviations and deltas

**D1 — retrieval has no workflow caller.** `RetrievalActivities.retrieve` is
constructed and registered on the orchestrator worker, and its query, ingestion,
rerank and citation behaviour is tested. No workflow or specialist calls it, so
no live run has emitted `retrieval.query` or `retrieval.result`. The exit
criterion is about retrieval behaviour and is met at the activity boundary; the
run-level path is not. Documented in `docs/architecture.md` §10.

**D2 — judged rubrics are report-only.** The rubric client and calibration work
are delivered, but no dimension earns a gate: no judge dimension has a measured
kappa that justifies failing a build. This is the documented decision in
`docs/evals/judge-calibration.md`, not a missing v0.2 deliverable.

## Residual findings

1. **Documentation drift.** README still said v0.1 complete, 23 services, 381
   tests and "Qdrant is v0.2"; architecture said 20 Compose definitions and that
   the researcher services were not yet in Compose. Corrected in this change.
2. **Stale red-team report.** The committed report was generated before the
   retrieval surface landed, so it showed `RT-INJ-02` pending and 30/35. It is
   regenerated here from the current pack.
3. **Retrieval producer without a run.** The trajectory schema marks
   `retrieval.query` and `retrieval.result` as live because the activity exists.
   Until D1 is closed, no produced run contains them; the producer table is
   accurate about capability, not about invocation.

## Not proven

- The live secret sweep was not re-run today; criterion 3 relies on the recorded
  2026-11-26 measurement and the offline custody tests.
- `RT-AUTHZ-01` and `RT-DUR-02` are live-only and were not part of the offline
  red-team run. Their live executors exist in `tests/redteam/live/`.
- Retrieval has not been called by a workflow (D1).
- gVisor `runsc` remains unavailable on this host; the hardened Compose flags are
  the actual sandbox boundary.
- The full browser OIDC round-trip remains an owner-run check, not a CI check.

## What v0.3 inherits

- Close D1 by giving retrieval a caller and recording the first run with
  `retrieval.query` / `retrieval.result`.
- Online sampling of real runs into MLflow eval datasets; MLflow dataset and
  scorer logging is still absent.
- Exact + semantic cache under ADR-018, its TTL and invalidation rules, and the
  cross-tenant `RT-CACHE-01` / `RT-CACHE-02` proofs.
- Prometheus metrics, optional Grafana.
