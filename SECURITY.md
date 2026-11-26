# Security policy

Citadel is a reference implementation of a contained agent platform: an allowlist, a
policy decision, an approval gate, DLP on the way in and out, and a hash-chained audit
ledger. A gap in any of those is the subject of this file.

## Supported versions

| Version | Supported |
|---|---|
| `v0.1.x` | yes |
| `main` | bugs are welcome as issues; advisories are written against a release |
| anything else | no - nothing after v0.1 is released |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**<https://github.com/glaborie/citadel/security/advisories/new>** (Security tab ->
"Report a vulnerability"). It is enabled on this repository, and it keeps the report
private until there is a fix.

Please do **not** open a public issue, pull request, or discussion about it, and do not
attach a working exploit anywhere public - this repository is read as a worked example,
so a public proof of concept is a template.

A useful report says: the component and the version or commit, what you did, what
happened, what you expected, and the smallest reproduction you have. If the finding
involves a credential, say what kind it was and rotate it before you send anything; do
not paste a live secret into the report.

## What to expect

- An acknowledgement within **3 working days**.
- An assessment - accepted, duplicate, or out of scope with the reason - within
  **10 working days**.
- A fix, a mitigation, or an explicit "won't fix" with the reasoning. Fixes are
  best-effort: this is one person's project, not a product with an on-call rota.
- Credit in the advisory, if you want it.

**There is no bug bounty.** Saying so is better than implying one.

## Scope

In scope: `src/citadel`, the services and their configuration in `compose.yaml` as
shipped, and the default policy in `src/citadel/policy/`.

The findings that matter most here are the ones the design claims to prevent:

- a tool call that reaches a command past the allowlist, the policy decision or the
  approval gate;
- data that crosses a tenant boundary, or a read that ignores row-level security;
- a secret that reaches a prompt, a tool argument, a trajectory, the audit ledger or a
  log line without DLP seeing it;
- an operator action that runs something a human did not approve.

Out of scope:

- **The deliberate non-goals** in `README.md` and `AGENTS.md`: no local GPU inference,
  no multi-tenant SaaS control plane, no billing, no agent marketplace, no reversible
  DLP token vault in v0.1.
- **A threat model changed by the operator.** Disabling DLP, widening an allowlist,
  publishing the console, or running the sandbox without the Compose flags are
  configuration decisions, and the docs say what each one costs. A finding that needs
  one of those to reproduce is not a vulnerability in the defaults.
- **Third-party components** - Temporal, Keycloak, OpenFGA, Qdrant, Presidio, Squid,
  MLflow, OmniRoute. Report those upstream. If our default wiring makes an upstream
  flaw exploitable, that wiring *is* in scope; say so and point at it.

## Testing

Run the stack against your own deployment: `make up` on a host you control. Do not test
against infrastructure you do not own.

The repository ships a red-team pack (`docs/evals/red-team-report.md`, cases in
`tests/redteam/`). If one of those cases already covers your finding, mention it - and if
none does, that is worth knowing too, because the pack is meant to grow.
