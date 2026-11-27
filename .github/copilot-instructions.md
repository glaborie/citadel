#### Citadel Architecture & Security Invariants

You are auditing **Citadel**, a zero-trust Python + Temporal + Docker Compose agentic runtime. Enforce these invariants on every review: 

1. **Identity & Token Downscoping (src/citadel/identity/)**: 

  * Child Temporal workflows must receive scoped run tokens, never the user's raw OIDC token.
  * Every run and state-mutating request must require a verified tenant claim.
2. **Single Policy Chokepoint (src/citadel/policy/)**: 

  * Every tool invocation must pass through authorize() against OpenFGA. Flag any path that bypasses authorize(), defaults to allow, or permits cross-agent escalation.
3. **Fail-Closed DLP & Untrusted Research (src/citadel/dlp.py, src/citadel/research/)**: 

  * DLP must fail closed (block on error/timeout, never pass raw text).
  * External content from research/ must retain untrusted_external provenance labels and cannot flow into privileged tool arguments or system prompts unsanitized.
4. **Privilege Separation (src/citadel/tools/, compose.yaml)**: 

  * Only operator may execute T1 write tools (restart_service, open_remediation_pr), and only with a single-use approval reference matching exact arguments.
  * Sandbox containers must never mount the Docker socket directly or bypass squid/github-egress.conf.
5. **Tenancy, Idempotency & Audit (migrations/, src/citadel/audit.py)**: 

  * Postgres queries must run under the non-owner app role so RLS policies are enforced.
  * Tool executions must enforce durable idempotency keys and append to the per-tenant hash-chained audit ledger.

#### GitHub Issue Creation Rules (gh)

* Read #file:docs/architecture.md, #file:docs/exit-review-v0.2.md, and #file:AGENTS.md first so you do not file issues for intentional non-goals or already-tracked items.
* Before creating any issue, run gh issue list --state all --limit 100 --json number,title,state to prevent duplicates.
* Only create issues for verified **High** or **Medium** severity findings backed by exact file:line references and concrete execution/data-flow proof.
* Do not modify any code files during an audit run.
