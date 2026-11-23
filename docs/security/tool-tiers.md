# Tool Safety Tiers

Every tool is classified before it can be registered. Unclassified tools are denied. Classification is part of the tool manifest and is enforced by OpenFGA at the single `authorize()` chokepoint, not by prompts or skills.

## T0 — Read-only

**Default: allowed without HITL.**

Examples: `inspect_containers`, `read_logs`, `get_service_health`, `read_file` (allowlisted paths), `search_code`, `get_pr_status`, `search_docs`, `fetch_page`.

Controls: tenant-scoped token, OpenFGA allow, DLP on input and output, source citation for retrieval, cache permitted with full partition key, audit event still emitted, sandbox still applies.

## T1 — Reversible write

**Default: requires HITL approval.**

v0.1 allowlist contains exactly two tools:

| Tool | Specialist | Effect | Rollback |
|---|---|---|---|
| `restart_service` | Docker | Restarts one named container/service | Service returns to previous running state |
| `open_remediation_pr` | GitHub | Opens a draft PR with proposed change | PR can be closed without merge |

Controls: T0 controls plus — full argument preview with rendered diff, policy rule that triggered the gate, retrieved evidence/citations, single approver, 15-minute TTL with **auto-deny**, mandatory reason, durable idempotency key, audit event written before Temporal resume. User cannot approve a run they requested.

## T2 — Destructive / irreversible

**Default: denied outright in v0.1.**

Examples (design placeholders, not registered tools): delete volume, prune images, host reboot, firewall change, secret rotation, force-push, merge PR to production.

If enabled in a later milestone: two distinct approvers, hardware/second-channel confirmation for the highest impact, explicit per-call allowlist, no caching, no automatic retry, short-lived elevation scoped to one call.

## Approval workflow

1. Specialist requests tool execution; policy returns `requires_approval` with tier and rule ID.
2. Temporal workflow emits a signal to the approval console and waits.
3. Approver authenticates via Keycloak; UI shows tool, canonical args, diff, evidence, risk and TTL.
4. Approve/deny with reason is authorised server-side; event is hash-chained into audit **before** the workflow resumes.
5. On approve, tool executes once with idempotency key. On deny/expiry, run records denial and stops that branch.

## Deny-by-default rules

- Unknown tool name → deny and alert.
- Missing tenant, run ID or delegated token → deny.
- Policy service unreachable → deny (fail closed).
- DLP detector unavailable → deny (fail closed).
- Skill file asks for a new tool or scope → deny and flag for review; skills never grant authority.
- Any write tool called without idempotency key → hard error.

## Test obligations

Each tier requires unit tests for allow/deny, an integration test through the worker, and a red-team test attempting to cross tiers (e.g. Researcher calling `restart_service`, cached T0 result replayed into a T1 call, expired approval reused).
