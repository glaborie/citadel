# Issue #183: the retrieval activity's workflow caller (closes v0.2 D1)

The pre-existing state: `RetrievalActivities.retrieve` was registered on the
orchestrator worker and tested at the activity boundary, but no workflow called
it, so no produced run contained `retrieval.query` or `retrieval.result`
(D1 in `docs/exit-review-v0.2.md`).

## Where the caller lives

The **orchestrator's task run**, not the Researcher specialist. Retrieval feeds
the model context, and the orchestrator owns sequencing and the model step; a
specialist caller would have to hand the evidence back through a tool result,
which is a T0 tool call the model did not ask for. The orchestrator calls
`retrieve` once before the first model step, so every step of the run sees the
same evidence.

## What the caller passes

- `run_id`, `tenant_id`, `user_id`, `agent_id` and the task text as the query.
- The run's ACL tag set: `tenant:<tenant_id>`. Roles partition the answer cache;
  the corpus entitlement a run holds today is its tenant. The activity refuses a
  set that does not carry this tenant's tag (`_entitled` in
  `citadel/retrieval/query.py`), and the filter stays inside the Qdrant request.

## What comes back

- `RetrievalOutcome.chunks` is rendered as one evidence block appended to the
  task: `chunk_id`, `source_uri`, `revision`, `score`, then the DLP-cleaned text.
  It is part of the task, not `history`, so the first step stays cacheable under
  ADR-018's "empty history" rule; the exact prompt digest changes with the
  evidence, and the semantic key embeds the evidence text.
- The chunk ids travel in `ToolResult.output["citation_ids"]` and
  `run.end.citation_ids`. The citation grader resolves them against
  `retrieval.result`, so the recorded run cites chunks it actually retrieved.
- A refused retrieval leaves the run without evidence; it is not a gate, and the
  run keeps its pre-#183 trajectory. A Qdrant transport failure still fails the
  activity, as any other activity failure does.

## The citation token fixes this exposed

The first real caller made the model copy `fs:...`/`gh:...` source URIs and bare
chunk ids verbatim. `_CITATION_TOKEN` in `citadel/evals/graders.py` recognized
neither a scheme without a slash (`fs:live-run-183.md`) nor a bare Qdrant point
id (a UUID), so a correct citation graded as "names no retrieved chunk". The token
now accepts both; `tests/test_evals.py` covers each.

## Measured

- `tests/test_run_retrieval.py` runs the real workflow and the real
  `RetrievalActivities.retrieve` in Temporal's time-skipping environment with
  stubbed Qdrant (in-memory), embedder and reranker. It asserts both events,
  schema validity, the evidence in the model request, `run.end.citation_ids`, and
  a passing `citation.supported` grade on the recorded trajectory.
- The same file runs the workflow for `lab-a`, `lab-b` and `lab-c` over one
  shared corpus and asserts each run's evidence and result event name only its
  own source.
- `tests/test_run_loop.py` stubs retrieval as refused, so the loop tests still
  prove sequencing without a corpus.

## Live run on the owner's stack

The stack was rebuilt from this branch (`make rebuild` equivalent) and the
`citadel-app:0.1.0` image restarted. `knowledge/live-run-183.md` (a synthetic
checkout-api runbook, gitignored) was ingested into `citadel_lab-a`, then a task
run was submitted for tenant `lab-a` through `POST /runs`:

| Run | Task | Result |
|---|---|---|
| `bbb4ecd2-d919-4c66-9929-aa49941b4078` | runbook question, tool use allowed | completed; 12 events including `retrieval.query` and `retrieval.result`; `run.end.citation_ids` equals the 3 retrieved chunk ids |
| `aa32ee09-ef37-40cf-a695-73b3514dc3f4` | same question, answer only from evidence, cite every factual sentence | completed; 6 events; all 11 graders pass, including `citation.supported` |

The second run's recording (`citadel.evals.recorder --tenant lab-a --run
aa32ee09-ef37-40cf-a695-73b3514dc3f4`) is schema-valid, `retrieval.query` carries
`collection=citadel_lab-a` and a `sha256:` filter-set digest, and
`retrieval.result` names `fs:live-run-183.md`.

The first live run exposed two defects the stubbed test could not: the model
cited `chunk_id=<uuid>` and `source_uri=fs:live-run-183.md`, and the citation
token regex recognized neither. It now accepts bare UUIDs (Qdrant point ids) and
scheme-qualified sources without a slash (`fs:live-run-183.md`). The first run
still fails `citation.supported` for a different reason: the model added a
paragraph from `inspect_containers` and split some claims from their citation
across sentences, and the rule is per-sentence and retrieval-only by design. The
second run shows the clean path.

Not measured: a live cross-tenant retrieval (the tenant-pairing proof remains
the workflow-level test, and Qdrant collection isolation is unchanged).
