# TODO

Open work. Done items get deleted, not ticked.

- [ ] Names are not redacted. Presidio scores `docker` at 0.85, the same as
      `Alice Smith`, so `PERSON` was dropped from `PII_ENTITIES` in step 7.
      Decide between accepting the gap or adding a recognizer that separates
      names from technical nouns.

- [ ] T1 arguments reach the approval UI before DLP sees them. The operator
      blocks execution, but the console renders the values a human is asked to
      approve, which breaks "no plaintext secrets in the approval UI". Needs a
      DLP check at approval-request time in the specialist.

- [ ] Register `docker.inspect`, `docker.compose.config` and `gh.pr.diff` in the
      tool catalog. Their output now passes DLP, but registering a tool means
      extending the OpenFGA model and bootstrap, which is a step 4 change.

- [ ] ADR-022 agent approvers. Still `Proposed` and unimplemented: a permitted
      agent cannot approve a run, so every T1 write waits for a human.

- [ ] PR text limit. Title and body must be one line and cannot contain `..`,
      because the allowlist matcher rejects those tokens. Upgrade path is a
      checkout inside the operator plus `--fill`.

- [ ] Cap tool output held in event history. `execute_tool` returns up to 64 KB
      per call and every result becomes an event-history payload; several calls
      in one run approach the 256 KB warning. Cap or offload before diffs and
      logs flow through.

- [ ] Judge-scored rubrics are absent. Only deterministic hard assertions run;
      `mlflow.genai.evaluate()` and the built-in groundedness/safety scorers
      belong with the v0.2 eval suite.

- [ ] Recorded trajectories cover run start/end, policy, DLP, approval and tool
      spans. `model.call` and `retrieval.*` have no producer until the model and
      retrieval paths exist, so those event types remain fixture-only.

- [ ] No argument-value grader. `tool.call` carries `args_hash`, not the
      canonical arguments, so "argument values match expected form" cannot be
      asserted from a trajectory alone.
