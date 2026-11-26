# Tool Safety Tiers

Every tool is classified before it can be registered. Unclassified tools are denied. Classification is part of the tool manifest and is enforced by OpenFGA at the single `authorize()` chokepoint, not by prompts or skills.

## T0 — Read-only

**Default: allowed without HITL.**

Registered in v0.1: `inspect_containers`, `inspect_container`, `read_logs`, `get_service_health`, `compose_config`, `search_code`, `get_pr_status`, `pr_diff`. Design placeholders, not yet registered: `read_file` (allowlisted paths), `search_docs`, `fetch_page`.

Controls: tenant-scoped token, OpenFGA allow, DLP on input and output, source citation for retrieval, cache permitted with full partition key, audit event still emitted, sandbox still applies.

The sandbox itself requires the caller's signed run token on every call and takes the agent identity from the verified claims. The body's `agent` string must match those claims, so a workload on the `internal` or `sandbox` network cannot run a T0 command as an agent whose token it does not hold, and the audit's `agent_id` is the token's, not a self-declaration.

### Pinned arguments

A tool may point at a command that discloses secrets by design — `docker inspect`
prints `.Config.Env`, `docker compose config` prints values resolved from `.env`.
It may do so only if its catalog entry pins the arguments that decide how much is
printed:

| Tool | Command | Pinned | Effect |
|---|---|---|---|
| `inspect_container` | `docker inspect` | `--format` with a template that selects name, status, restart count and image | the environment is not reachable from the call |
| `compose_config` | `docker compose config` | `--no-interpolate --quiet` | variable references instead of resolved values |

Pinned arguments are placed before any caller-supplied one and are not declared as
parameters, so a call that tries to supply `format` is refused as an unknown
argument rather than accepted with a different template. The rule is enforced both
ways: a test asserts every tool wired to a `content_risk: definitive` command pins
at least one argument, and `RT-AUTHZ-07` proves three widened calls are refused.

Output still passes DLP before it is served, and for credentials the action is a
**refusal**, not a redaction: a diff or a config file with a token in it is not the
artifact a reviewer asked for, so it is not served at all.

## T1 — Reversible write

**Default: requires HITL approval.**

v0.1 allowlist contains exactly two tools:

| Tool | Specialist | Effect | Rollback |
|---|---|---|---|
| `restart_service` | Docker | Restarts one named container/service | Service returns to previous running state |
| `open_remediation_pr` | GitHub | Opens a draft PR with proposed change | PR can be closed without merge |

Controls: T0 controls plus — full argument preview with rendered diff, policy rule that triggered the gate, retrieved evidence/citations, single approver, configurable TTL (default 5 minutes, `CITADEL_APPROVAL_TTL_SECONDS`) with **auto-deny**, mandatory reason, durable idempotency key, audit event written before Temporal resume. User cannot approve a run they requested.

## T2 — Destructive / irreversible

**Default: denied outright in v0.1.**

Examples (design placeholders, not registered tools): delete volume, prune images, host reboot, firewall change, secret rotation, force-push, merge PR to production.

If enabled in a later milestone: two distinct approvers, hardware/second-channel confirmation for the highest impact, explicit per-call allowlist, no caching, no automatic retry, short-lived elevation scoped to one call.

## Approval workflow

1. Specialist requests tool execution; policy returns `requires_approval` with tier and rule ID.
2. The specialist records a pending approval row (arguments DLP-checked first) and the workflow waits.
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
