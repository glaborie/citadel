# TODO

Open work. Done items get deleted, not ticked.

- [ ] Check the Temporal AI cookbook for ideas — https://docs.temporal.io/ai/cookbook
      Look for anything that changes how the orchestrator, the specialists or the
      approval wait are built. Adopt ideas as new items here; drop the ones that
      do not fit and say why in one line.

- [ ] Step 7: DLP (Presidio + custom CH/EU recognizers). Unblocks `read_logs`,
      `gh.pr.diff`, `docker.inspect` and `docker.compose.config` — all four are
      refused by the sandbox today because their output can carry secrets.

- [ ] ADR-022 agent approvers. Still `Proposed` and unimplemented: a permitted
      agent cannot approve a run, so every T1 write waits for a human.

- [ ] PR text limit. Title and body must be one line and cannot contain `..`,
      because the allowlist matcher rejects those tokens. Upgrade path is a
      checkout inside the operator plus `--fill`.
