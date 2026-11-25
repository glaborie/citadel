# AGENTS.md — Citadel Implementation Handover

You are implementing Citadel from an approved design. Read the whole document set before writing code. The design tree is closed; do not re-litigate settled decisions. If a fact is marked as an implementation-time verification item, verify it and record the result in an ADR amendment or a short implementation note — do not silently choose a different architecture.

## Ground rules

1. **Docs-first, then code.** All design docs in this repository are the source of truth. If code and docs disagree, stop and report the conflict.
2. **No code reuse** from prior projects. Lessons only.
3. **No local LLM/GPU tier.** Hosted inference through OmniRoute only; Presidio is the sole local model workload.
4. **Fail closed** on missing tenant, policy failure, DLP failure, expired approval or unknown tool.
5. **Skills are documentation, never authority.** Never let a SKILL.md file grant tools, scopes or policy exceptions.
6. **Never mount the Docker socket into a model-influenced component.** Use the hardened tool runner; gVisor is the isolation upgrade.
7. **No plaintext secrets** in repo, traces, audit, eval fixtures, approval UI or sandbox. Use `.env.example` placeholders; migrate to SOPS+age at v0.2.
8. **Test the security boundary**, not just happy paths. Every control has an allow test, a deny test and a red-team test.
9. **Pin everything**: dependencies with hashes, images by digest, model aliases and prompt packs by version.
10. **Do not expose OmniRoute admin MCP/A2A** or treat its cache/idempotency as Citadel controls.

## Read in this order

1. `README.md` — pitch, capability map, non-goals.
2. `docs/architecture.md` — components, lifecycle, threat model, open verification items.
3. `docs/milestones.md` — scope and exit criteria.
4. `docs/security/tool-tiers.md` — tool classification and approval flow.
5. `docs/evals/trajectory-schema.md` — event schema and graders.
6. `docs/adr/ADR-Index.md` and all ADRs — reasons and constraints.

## Implementation order for v0.1

1. Repository hygiene: Python packaging, `uv` lock with hashes, ruff + mypy strict, pytest, `.gitignore`, `.env.example`, clean-clone test.
2. Compose skeleton: `postgres`, `keycloak`, `temporal`, `temporal-ui`, `openfga`, `omniroute`, `mlflow`, `presidio`, `api`, approval UI, one worker per specialist, sandboxed tool runner. Pin images by digest.
3. Identity path: Keycloak realm/roles/tenant claim; run-token issuance and validation; tenant middleware; RLS setup. Verify the exact delegated-token mechanism and record the finding.
4. Policy path: OpenFGA model loaded from versioned files; single `authorize()` chokepoint; deny-by-default tests.
5. Temporal path: orchestrator + Docker + GitHub child workflows; approval wait/resume; retries and idempotency keys.
6. Tools: T0 read set first; then `restart_service` and `open_remediation_pr` as T1; sandbox runner integration; audit events.
7. DLP: Presidio + custom CH/EU recognizers; fail-closed wrapper; redaction on all surfaces.
8. Approval console: five views, Keycloak SSO, server-side authorisation, CSRF, TTL auto-deny, reason capture, audit-before-resume.
9. Observability and eval: OTel to MLflow OTLP endpoint, audit-ID propagation, one golden trajectory, CI eval invocation.
10. Red-team suite and milestone exit review against `docs/milestones.md`.

## Definition of done (v0.1)

- `docker compose up` on Ubuntu starts only the services listed for v0.1 and all health checks pass.
- Clean clone with no hidden files installs and passes all tests.
- Red-team tests prove: cross-tenant block, unauthorized tool block, DLP-failure block, expired-approval block, idempotent replay, injection label propagation.
- One end-to-end run produces a recorded trace whose policy, DLP, approval and tool spans carry matching audit IDs.
- No secret, token or credential appears in logs, traces, eval fixtures or the approval UI.

## Open verification items

1. Canonical OmniRoute repository and exact image commit; many forks and a GitHub redirect were observed.
2. MLflow image version (resolved: 3.18.0, digest pinned in Compose) and the Keycloak OAuth2 proxy for the human path (open only if the UI is published; the internal OTLP write path is resolved).
3. gVisor `runsc` availability on the target Ubuntu host; if absent, document the fallback explicitly.
4. Keycloak delegated-token mechanism preserving user identity (RFC 8693 V2 caveats).
5. Whether the chosen hosted reranker/embedding endpoints are acceptable for the redacted data leaving the box.

## Style

Python 3.12+, FastAPI for API/UI, Temporal Python SDK, qdrant-client, OpenFGA SDK, Presidio, MLflow SDK, pytest, httpx for gateway calls. No LiteLLM. No LangChain agent abstractions. Keep components thin and replaceable behind interfaces. Write an ADR before any change that alters a settled decision.
