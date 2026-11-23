# Milestones and Exit Criteria

Design confirmed 2026-11-23. Four milestones, each with a demonstrable exit test. No milestone may be declared complete on documentation alone.

## v0.1 — Secure vertical slice

**Goal:** one DevOps request traverses every core control.

**Included**
- Keycloak 26 OIDC, delegated run tokens, tenant claim extraction.
- Temporal server + orchestrator + Docker + GitHub specialist child workflows.
- OpenFGA policy chokepoint; Postgres RLS; append-only hash-chained audit.
- Presidio DLP with at least AHV/Swiss IBAN custom recognizers; fail-closed.
- T0 read tools; exactly two T1 tools: `restart_service`, `open_remediation_pr`. All T2 denied.
- Approval console: run list, timeline, pending approvals, approval detail, audit search.
- Durable idempotency keys; OTel traces into MLflow; one recorded golden trajectory.
- Skill packs for the three specialists, hash-pinned and versioned.
- Gitignored `.env` + `.env.example` with synthetic values only.

**Exit criteria**
- A fresh clone with no hidden files starts the stack and passes all tests.
- Red-team suite proves: cross-tenant read blocked, unauthorized tool blocked, DLP failure blocks, expired approval blocks, duplicate idempotency key returns original result.
- One recorded trace shows policy decision, DLP event, approval and tool result with matching audit IDs.
- `docs/adr/ADR-008.md` roadmap reconciled with actual delivered scope.

## v0.2 — Knowledge and real credentials

**Goal:** permission-aware retrieval and safe secret handling.

**Included**
- Filesystem + selected GitHub ingestion, content-hash versioning, per-tenant Qdrant collections.
- Dense + sparse hybrid retrieval, ACL filter inside query, RRF, TEI reranker, structured citations.
- Researcher specialist: SearXNG + trafilatura fetcher, untrusted-content pipeline.
- SOPS + age migration for versioned/shared secrets; Docker secrets injection.
- Offline eval suite with deterministic tool/argument assertions + judge rubrics.

**Exit criteria**
- ACL-filtered retrieval returns no unauthorized chunk in any tenant combination.
- Citation validator fails runs with unsupported operational claims.
- No plaintext secret in repo, skill pack, trace, audit event, eval fixture or approval UI.
- CI publishes a baseline eval result table with pinned model and prompt versions.

## v0.3 — Evaluation, online grading and cache

**Goal:** measure quality continuously and reduce tail latency safely.

**Included**
- Online sampling of real runs into MLflow eval datasets.
- Regression comparisons across runs and model aliases.
- Exact + semantic cache with partition key `(tenant, entitlement_hash, agent, prompt_pack_version, model, tool_context_version)`.
- Tenant/permission change invalidation; red-team cross-tenant cache prompt test.
- Prometheus metrics (optional Grafana).

**Exit criteria**
- Cache hit never crosses tenant or entitlement boundary in the red-team test.
- Model alias change produces a comparable eval diff rather than an incomparable result.
- All cached entries have TTL; no T1/T2 effects or approval decisions cached.

## v0.4 — Protocols and optimisation

**Goal:** interoperability and model-cost routing without widening the trust boundary.

**Included**
- MCP consume adapter behind a tool-source interface (no admin exposure).
- A2A seam behind an `AgentConnector` interface; no dependency on ecosystem maturity.
- Code mode only inside the sandbox; deny-by-default imports and egress.
- Semantic routing: deterministic intent match → embedding route → complexity escalation; ambiguous/sensitive requests go to the safer path.

**Exit criteria**
- Replacing the MCP/A2A adapter requires no worker or policy changes.
- Code-mode tool cannot reach host filesystem, Docker socket, network or secrets.
- Routing red-team: sensitive request never routed to the cheap tier; ambiguous request escalates.

## Explicit non-goals (whole project)

- Local GPU inference / self-hosted LLM.
- Multi-tenant SaaS control plane or billing.
- Reversible DLP token vault in v0.1.
- Trusting OmniRoute semantic cache, 5-second idempotency or admin MCP/A2A as security controls.
- Building against A2A as a hard dependency.
- Reusing the earlier Temporal POC or any code from superseded projects.
