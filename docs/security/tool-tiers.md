# Tool Safety Tiers

Every tool is classified before it can be registered. Unclassified tools are denied. Classification is part of the tool manifest and is enforced by OpenFGA at the single `authorize()` chokepoint, not by prompts or skills.

## T0 — Read-only

**Default: allowed without HITL.**

Registered in v0.1: `inspect_containers`, `inspect_container`, `read_logs`, `get_service_health`, `compose_config`, `search_code`, `get_pr_status`, `pr_diff`. Registered in v0.2: `search_web`, `fetch_page` (Researcher only). Design placeholders, not yet registered: `read_file` (allowlisted paths), `search_docs`.

Controls: tenant-scoped token, OpenFGA allow, DLP on input and output, source citation for retrieval, cache permitted with full partition key, audit event still emitted, sandbox still applies.

Every component on the execution path requires the caller's signed run token and takes identity from the verified claims, never from the request or the workflow payload: the worker verifies the token in `authorize_tool` and `execute_tool` before any policy decision, idempotency row or audit event is written and refuses a payload whose tenant, user, run or agent fields disagree with the claims (ADR-027); the sandbox additionally binds the body's `agent`, `tenant_id` and `run_id` to the token; the operator requires the token on every call and takes the tenant only from its claims. A workload on the `internal` or `sandbox` network therefore cannot run a command, reach the policy decision or write a ledger event as a tenant, user or agent whose token it does not hold.

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

### Web research

`search_web` and `fetch_page` belong to the Researcher and to no other agent. They
are T0, and they run in the worker rather than the sandbox: the fetcher is the
only component with an egress route, so the model-influenced sandbox never gains
one (ADR-020).

- The fetcher resolves a URL, refuses any answer that is not global unicast, then
  pins the connection to the checked address. Only ports 80 and 443 are allowed;
  every redirect is checked again.
- A page is fetched with no cookies, no credentials, a 10-second timeout, a MIME
  allowlist and a 2 MB cap. A page over the cap is truncated and marked, not
  served in full.
- The query and the fetched text pass the same input/output DLP gates as any CLI
  tool. A credential blocks; PII is redacted.
- The text is prefixed `untrusted_external` before it reaches a model. A lexical
  detector adds `prompt_injection` when the page instructs the reader; the run
  continues read-only and both labels reach `tool.call` and `run.end`.
- The labels accumulate on the run and ride on every tool call the orchestrator
  delegates afterwards (`ToolCall.content_flags`), so a T1 request made after a
  flagged observation carries the taint to the approval.
- A T1 call suggested by a page still needs a human approval, and the Researcher
  has no T1 tool to call in the first place.

## T1 — Reversible write

**Default: requires HITL approval.**

v0.1 allowlist contains exactly two tools:

| Tool | Specialist | Effect | Rollback |
|---|---|---|---|
| `restart_service` | Docker | Restarts one named container/service | Service returns to previous running state |
| `open_remediation_pr` | GitHub | Opens a draft PR with proposed change | PR can be closed without merge |

Controls: T0 controls plus — full argument preview with rendered diff, policy rule that triggered the gate, retrieved evidence/citations, `content_flags_on_approval_requests` (the run's accumulated labels persist on the pending row and the console renders them, with a refusal-styled warning for `prompt_injection`), single approver, configurable TTL (default 5 minutes, `CITADEL_APPROVAL_TTL_SECONDS`) with **auto-deny**, mandatory reason, durable idempotency key, audit event written before Temporal resume. User cannot approve a run they requested. An agent approver is opt-in per tenant/tool through the `can_approve` relation and may approve only a run another agent proposed (ADR-022); `agent_approval_refused_on_prompt_injection` — a call the run proposed after reading content flagged `prompt_injection` is refused to an agent approver and waits for a human (ADR-028).

## T2 — Destructive / irreversible

**Default: denied outright in v0.1.**

Examples (design placeholders, not registered tools): delete volume, prune images, host reboot, firewall change, secret rotation, force-push, merge PR to production.

If enabled in a later milestone: two distinct approvers, hardware/second-channel confirmation for the highest impact, explicit per-call allowlist, no caching, no automatic retry, short-lived elevation scoped to one call.

## Approval workflow

1. Specialist requests tool execution; policy returns `requires_approval` with tier and rule ID.
2. The specialist records a pending approval row (arguments DLP-checked first, content flags persisted) and the workflow waits.
3. Approver authenticates via Keycloak; UI shows tool, canonical args, diff, evidence, risk, content flags and TTL.
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
