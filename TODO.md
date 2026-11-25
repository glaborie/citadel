# TODO

Open work. Done items get deleted, not ticked.

- [ ] Step 7: DLP (Presidio + custom CH/EU recognizers). Unblocks `read_logs`,
      `gh.pr.diff`, `docker.inspect` and `docker.compose.config` — all four are
      refused by the sandbox today because their output can carry secrets.
      Add deterministic hard rules too (known token prefixes, private keys)
      that override the detector score, with the detector's own verdict kept in
      the audit record so the override is reviewable.

- [ ] ADR-022 agent approvers. Still `Proposed` and unimplemented: a permitted
      agent cannot approve a run, so every T1 write waits for a human.

- [ ] PR text limit. Title and body must be one line and cannot contain `..`,
      because the allowlist matcher rejects those tokens. Upgrade path is a
      checkout inside the operator plus `--fill`.

- [ ] Cap tool output held in event history. `execute_tool` returns up to 64 KB
      per call and every result becomes an event-history payload; several calls
      in one run approach the 256 KB warning. Cap or offload before diffs and
      logs flow through.

## Not adopted from the Temporal AI cookbook

Reviewed 4 of 18 recipes: human-in-the-loop, guardrails-hard-rules, claim
check, agentic loop with tool calling.

- Approval `request_id` matching — the specialist child workflow is already one
  per (run, tool), and the signed token, not the signal, is the real control.
- Dynamic activities per tool — `execute_tool` already dispatches on the tool
  name in the payload.
- Claim check via an S3 `PayloadCodec` — no S3 in the stack; the cap/offload
  item above covers the same risk for less.
- ADK / Vercel / OpenAI-Agents multi-agent recipes — AGENTS.md and ADR-001 rule
  out those agent abstractions.
- The approval wait itself needed nothing: `wait_condition(timeout=...)` with
  auto-deny on expiry is already what `SpecialistWorkflow` does.
