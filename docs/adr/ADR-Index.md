# ADR Index

Citadel records one ADR per architectural decision. Numbers are sequential; ADR-008 is the evolution roadmap referenced by other records.

| ADR | Title | Status |
|-----|-------|--------|
| 001 | Clean-slate Citadel repository and scope | Accepted |
| 002 | Temporal as the durable execution core | Accepted |
| 003 | Keycloak 26 for identity and delegated agent identity | Accepted |
| 004 | OpenFGA as the single authorisation store | Accepted |
| 005 | Multi-tenancy enforced from the first line of code | Accepted |
| 006 | OmniRoute constrained to provider routing | Accepted |
| 007 | Hosted inference with local DLP only | Accepted |
| 008 | Four-milestone evolution roadmap | Accepted |
| 009 | Bespoke HITL approval console | Accepted |
| 010 | Tool safety tiers and v0.1 allowlist | Accepted |
| 011 | Skills as documentation, never authority | Accepted |
| 012 | Hardened sidecar sandbox with gVisor upgrade path | Accepted |
| 013 | Fail-closed local DLP without a v0.1 reversible vault | Accepted |
| 014 | Durable idempotency with honest semantics | Accepted |
| 015 | Separate audit ledger from traces and Temporal history | Accepted |
| 016 | Permission-aware Qdrant retrieval with rerank and citations | Accepted |
| 017 | MLflow 3.x for trajectory evaluation | Accepted |
| 018 | Tenant-scoped cache and staged semantic routing | Accepted |
| 019 | Secrets and supply-chain hygiene | Accepted |
| 020 | Isolated untrusted web research pipeline | Accepted |
| 021 | MCP and A2A behind adapter seams | Accepted |
| 022 | Agent approvers for T1 calls | Accepted |
| 023 | CLI access from the sandbox, never from a worker | Accepted |
| 024 | Approvals travel as a single-use reference, not a token in history | Accepted |

## ADR-008 evolution roadmap

| Milestone | Theme | Key ADRs |
|---|---|---|
| v0.1 | Secure vertical slice | 001, 002, 003, 004, 005, 006, 007, 009, 010, 011, 012, 013, 014, 015, 019 |
| v0.2 | Knowledge and real credentials | 016, 017, 019, 020 |
| v0.3 | Evaluation and cache | 017, 018 |
| v0.4 | Protocols and routing | 018, 021 |

Keep this table reconciled with `docs/milestones.md` at every milestone exit review.

## Adding an ADR

1. Use the next sequential number; never skip a number.
2. Keep sections in order: Context → Decision → Consequences.
3. Reference concrete components, APIs and data flows in each decision item.
4. Include at least one Pro and one Con.
5. Add a row above and update the roadmap table if the decision affects milestone scope.
