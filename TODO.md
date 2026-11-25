# TODO

Open work. Done items get deleted, not ticked.

- [ ] Console sessions have no refresh. The session cookie and the Keycloak
      access token both last 300 s, so a review longer than five minutes ends
      in a re-login (silent through the SSO session, but the form is lost).

- [ ] Approval detail shows canonical arguments, not a rendered diff. ADR-009
      asks for the diff as well; `open_remediation_pr` reads an existing branch,
      so there is nothing to diff until a checkout exists in the operator.

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

- [ ] MLflow human-path auth. The UI is internal-only and unpublished, so no
      browser path exists yet. If it is exposed, add the Keycloak OAuth2 proxy
      from ADR-017; the worker OTLP write path is internal-only and unaffected.

- [ ] MLflow experiment bootstrap is manual. `make mlflow-bootstrap` creates
      `citadel-trajectories`; a fresh volume needs it before traces resolve.
      Fold it into `make up` or a one-shot init container.

- [ ] Recorded trajectories cover run start/end, policy, DLP, approval and tool
      spans. `model.call` and `retrieval.*` have no producer until the model and
      retrieval paths exist, so those event types remain fixture-only.

- [ ] No argument-value grader. `tool.call` carries `args_hash`, not the
      canonical arguments, so "argument values match expected form" cannot be
      asserted from a trajectory alone.
