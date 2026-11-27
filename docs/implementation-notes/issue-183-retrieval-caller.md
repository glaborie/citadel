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

## The citation token fix this exposed

The first real caller made the model copy `fs:...`/`gh:...` source URIs
verbatim. `_CITATION_TOKEN` in `citadel/evals/graders.py` did not allow the
scheme, so a correct citation graded as "names no retrieved chunk". The token now
accepts an optional scheme prefix; `tests/test_evals.py` covers it.

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

## Not measured

- No live run on the owner's stack was produced; the proof is the workflow-level
  test with the activity seam real and the clients stubbed. A live run needs the
  stack, an API token, an embedding alias and the Qdrant collection ingested.
