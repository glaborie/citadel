# Online sampling: real runs into the eval dataset

ADR-017 decision 3 asks for real runs to be sampled into the same MLflow store the golden
trajectories are graded in. This is that path, and what it refuses to carry.

## Off until it is measured

```
CITADEL_EVAL_SAMPLE_RATE=0        # 0 disables sampling; 0.1 is one run in ten
CITADEL_EVAL_SAMPLE_CAP=25        # rows per tenant per day
CITADEL_EVAL_DATASET_VERSION=1    # the schema version the row claims
CITADEL_EVAL_JUDGE=               # comma-separated judge dimensions, usually empty
```

The rate stays `0` until the scorer subset below has been measured against a pilot: an
eval set that fills with unlabelled rows nobody grades is a cost with no answer.

## The draw is deterministic

A run is sampled when `sha256(tenant|run|salt)` falls below the rate. Same run, same
answer, on every retry of `finish_run`; a different tenant draws independently. The cap is
counted per tenant per day from the `eval.sample` audit events, so a burst of short runs
cannot turn a 10% rate into hundreds of rows.

## What a row carries

```json
{
  "inputs": {
    "run_id": "…", "tenant": "lab-a",
    "model_alias": "auto/best-fast", "prompt_pack_version": "devops-3",
    "dataset_version": 1, "judge": []
  },
  "outputs": {"trajectory": [ /* docs/evals/trajectory-schema.md */ ]},
  "expectations": {}
}
```

`inputs` is the comparison key. Online rows use the same `baseline.Key` and
`baseline.compare` as the offline suite: dataset version, prompt packs and judge must
match, while the model alias is the variable under test. A run on a new alias is compared
with the accepted row for the same dataset, pack and judge; a changed prompt pack is not
comparable and waits for an accepted row of its own. `expectations` is empty because nobody
wrote any - a sampled run has no right answer, only a trajectory to grade.

The trajectory is the ledger export, so it contains what the schema contains: hashes,
ids, counts, tiers, decisions. It does not contain the prompt, chunk bodies, raw tool
arguments or the approval reason's plaintext.

## The DLP surface is the gate, not a filter

Every free-text field that survives into the row goes through `dlp.gate(surface="record")`
first:

| field | a credential | PII |
|---|---|---|
| `run.end.answer` | the whole sample is refused | redacted in place |
| `approval.decision.reason` | refused | redacted in place |
| `tool.call.output` | refused | redacted; if the redaction breaks the JSON, `output` is dropped and `output_redacted` is set |

A refusal is silent to the run (the run is over) and loud in the log: no row, and no
partially-redacted trajectory pretending to be complete.

## The scorer subset

After a row lands, the deterministic graders from `citadel.evals.graders` run over it -
the ones that read the trajectory itself (`trajectory.valid`, `citations`, `dlp`,
`idempotency`, `policy`, `risk_tier`). The `eval.sample` audit event is the online
counterpart of a baseline row: it carries the same key and per-grader scores, the row it
was compared with, the `regressions` that comparison found, and the rendered markdown
`report`. The next sample reads those rows back from the ledger, so a reviewer sees the
diff in the audit trail. MLflow still holds the trajectory; scoring stays here until the
judge budget moves online.

Judged rubrics are deliberately not run here. A rubric needs a calibrated judge and an
answer; sampling is not the place to spend either.

## The dataset id

The first sample creates `citadel-online-samples` and every `eval.sample` event records
its `dataset_id`; the next sample reads the most recent one, so a rename in MLflow does not
fork the dataset.

Discovery is worth a warning: `/api/3.0/mlflow/datasets/search` filtered by
`experiment_ids` returns an empty object for datasets created through the API, which reads
like "there is no dataset". A `filter_string` on the name **with an explicit `order_by`**
does resolve it - that is how `make eval-samples` finds the dataset without being told an
id, and why the ledger is a fallback rather than the only route.

## Grading a sample offline

`citadel.evals.online.replay(record)` builds a `Case` from a row and runs the same graders
the CI gate runs. No agent, no model, no network:

```python
from citadel.evals import online

grades = online.replay(record)      # list[Grade]
```

That is the acceptance property: a sampled run replays through the offline grader without
re-running anything.
