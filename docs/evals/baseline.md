# The eval baseline

`evals/baseline.json` records what the deterministic suite scored, so a grader change is
judged against numbers rather than memory. `make eval-gate` fails when a gating grader is
below the row it is compared with.

## What a row is keyed by

Everything that can move the numbers, taken from the trajectories rather than from a
constant:

| Part | Where it comes from |
|---|---|
| `dataset` | `dataset_version` in the dataset file |
| `prompts` | every `prompt_pack_version` in a `run.start` event, sorted and joined |
| `model` | every `model_alias` in a `run.start` event, sorted and joined |
| `judge` | the `--judge` alias, or `offline` for the deterministic run CI performs |

A change to any part is a **new row**, not an edit: a model bump, a new prompt pack, a
new dataset version all add a row and leave the old one in place. That is the only way a
later reader can see what the suite used to do.

## Recording one

```bash
make eval-record                       # append a row for this run
make eval-gate                         # compare against the row with this exact key
make eval-table                        # markdown table: every row, plus this run
```

`--record` refuses to rewrite an existing row whose scores differ. A score that moved is
a regression or a fix, and both deserve a deliberate edit to the file, not a silent
overwrite.

## What the gate covers, and what it does not

The gate speaks only for dimensions that can fail a run. Judged rubrics (`judge.*`)
appear in the table with an `*` and never gate, because no kappa has been measured for
them yet ([judge-calibration.md](judge-calibration.md), and #93). A table that gated on
an uncalibrated judge would be the same lie as counting an unrun red-team case as a pass.

The gate also fails when a grader **stops appearing**: unmeasured is not passed. If a
grader is removed on purpose, remove it from the row in the same change.

## Cost

The suite is deterministic and offline - no gateway, no model, no container. CI runs it
three times in the `eval` job (grade, table, gate) because a table that also decided the
exit code could not be published for a failing run.
