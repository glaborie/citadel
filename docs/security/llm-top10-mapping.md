# OWASP Top 10 for LLM Applications 2025: Citadel coverage

A mapping of the OWASP LLM Top 10 (2025) onto the controls this repository
actually implements, produced with the `semgrep/skills@llm-security` rule set as
the checklist. The point is not to claim coverage but to name the control, the
file that enforces it, and where it stops.

Verdicts: **Covered** (a control exists and a test proves it), **Partial** (a
control exists but a known case is unhandled), **Accepted** (risk deliberately
carried, recorded in an ADR).

| # | Category | Citadel control | Evidence | Verdict |
|---|---|---|---|---|
| LLM01 | Prompt injection | Untrusted labelling before content reaches a model, lexical `prompt_injection` detector, DLP on tool output, skills carry no authority, HITL on T1 | `src/citadel/research/labels.py`, `src/citadel/model/types.py`, `src/citadel/policy/authorize.py:104-107`, RT-INJ-01..06 | **Covered** |
| LLM02 | Sensitive information disclosure | Fail-closed DLP on `input`, `output`, `record`; a credential *refuses* rather than redacts; no secrets in container env; SOPS custody | `src/citadel/dlp.py`, `docs/security/secrets.md` surfaces table, `tests/test_dlp.py` | **Covered**, with the ADR-025 residual below |
| LLM03 | Supply chain | Images pinned by digest, `uv.lock` hashes, `gh` verified against a published checksum, Syft SBOM plus weekly Grype, Renovate, Scorecard | `Dockerfile`, `.github/workflows/security.yml`, `compose.yaml` | **Covered**; two build-hygiene gaps filed from the trivy/hadolint run |
| LLM04 | Data and model poisoning | No training or fine-tuning anywhere, so the model itself cannot be poisoned. Retrieval content is hashed and ACL-tagged at ingest | `docs/architecture.md` §6, `src/citadel/retrieval/` | **Partial** — a hash proves integrity, not trustworthiness; a poisoned runbook that is committed is ingested faithfully |
| LLM05 | Improper output handling | Tool execution is an argv list with `shell=False` and metacharacter rejection; outputs are DLP-gated and stored digest-addressed before serving | ADR-023 items 3-4, `src/citadel/tools/allowlist.py`, `src/citadel/tools/bounds.py`, `src/citadel/tool_outputs.py` | **Covered** |
| LLM06 | Excessive agency | Three tiers with deny-by-default, one `authorize()` chokepoint, T2 denied outright, T1 needs a human, no model-influenced component holds the Docker socket | `docs/security/tool-tiers.md`, `src/citadel/policy/authorize.py:87`, `compose.yaml` `tool-runner` | **Covered** |
| LLM07 | System prompt leakage | The system prompt is assembled from versioned skill-pack text and digested; no secret is placed in a prompt, and authority lives in OpenFGA, so leaking the prompt grants nothing | `src/citadel/prompts.py` (`assemble`, `_digest`), `src/citadel/skills.py` | **Partial** — no output filter stops a verbatim echo; the impact is disclosure of documentation, not of capability |
| LLM08 | Vector and embedding weaknesses | Per-tenant collections, ACL filter applied inside the query before reranking, filter-set digest in the audit event, tenant-partitioned cache, reranker in-stack | `src/citadel/retrieval/activities.py`, `docs/architecture.md` §6, ADR-016 | **Covered** |
| LLM09 | Misinformation | Citations carry `(source_uri, revision, chunk_id, line_range)`; the orchestrator must say when evidence is insufficient; eval graders score citation grounding | `docs/architecture.md` §6, `docs/evals/`, `run.end.citation_ids` | **Partial** — citation presence is graded, citation *sufficiency* is not |
| LLM10 | Unbounded consumption | `max_steps` 6, `max_tokens` 32000, `max_cost_usd` 0.01, workflow activity timeouts, approval TTL with auto-deny, and a per-credential ingress budget on `POST /runs` (429 with `Retry-After`) | `src/citadel/ratelimit.py`, `src/citadel/api/app.py` (`budgeted_principal`), `src/citadel/model/types.py:68-69`, `tests/test_run_budget.py` | **Covered** — the caps bound one run, the budget bounds a client that starts many (#256) |

## Where the mapping found something worth fixing

1. **LLM10 needed an ingress budget, and #256 added one.** Before it,
   `grep -rniE 'rate.?limit|quota|throttl' src/` returned nothing: the step and
   token caps bound one run, not a client that starts many. `RunBudget` charges
   one run per `(tenant, user)` before the request reaches the database and
   refuses with 429 plus `Retry-After`, so the control is the API's own rather
   than OmniRoute's quota.
2. **LLM04's trust boundary is ingest, not the model.** Poisoning arrives as a
   committed runbook or an ingested repository, and the content hash records
   what arrived rather than whether it should have. The review gate is the PR
   that changes `knowledge/`; worth saying so in `docs/architecture.md` §6.
3. **LLM07 and LLM09 are honest Partials, not gaps to paper over.** A prompt
   echo and an under-evidenced answer are both visible in the trace, which is
   the mitigation the design chose.

## Not applicable

- **Fine-tuning and training-data poisoning** as categories: this deployment
  calls a hosted model and trains nothing.
- **Model theft** via weight extraction: no weights are served locally; the
  reranker model is a public cross-encoder baked into an image at a pinned
  revision.
