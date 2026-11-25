# Definition of Production-Ready (Agent)

Ten gates. An agent that misses one does not ship, and a gap is only allowed as
a written, time-boxed exception with a named owner and a review date. This is
the document that answers "what does the practice actually enforce", which is a
different question from "what does the platform support".

Each gate names the evidence a reviewer can inspect. If the evidence cannot be
produced in under five minutes during a review, the gate is not met.

| # | Gate | Evidence | Signed by |
|---|---|---|---|
| 1 | **Identity and tenancy** — every run carries a user identity, a tenant claim and a short-lived delegated token; data access is filtered by that tenant, not by prompt instruction | Trace shows token claims; one cross-tenant query in the red-team pack returns zero results | Platform |
| 2 | **Tool authority** — every tool call is decided at one chokepoint against a catalog entry and a policy relation; unknown tools are denied and alerted | Policy decision per call with rule ID; `RT-AUTHZ-02`, `RT-AUTHZ-03` green | Platform |
| 3 | **Side-effect safety** — write tools are idempotent under retry, bounded in scope, and cannot execute outside the sandbox | One `tool.call` span per effect on retry; `RT-DUR-01`, `RT-DUR-02` green | Engineering |
| 4 | **Data protection** — DLP runs on prompt, retrieval, tool arguments and output, fails closed, and redacts before any egress | DLP events in the trace; `RT-DLP-01..05` green | Security |
| 5 | **Human in the loop** — the approval binds the exact arguments, expires into denial, and the approver is never the requester | `approval.decision` with args hash and TTL; `RT-HITL-01..05` green | Product owner |
| 6 | **Evaluation** — a versioned golden set with hard assertions at 100%, a calibrated judge for the soft dimensions, and a regression gate in CI | Eval report with pass rate per assertion, judge–human agreement, and the diff against the last accepted run | Engineering |
| 7 | **Grounding** — retrieval results are ACL-filtered, citations resolve to a source revision, and an answer without evidence is allowed to say so | Citation checker at 100%; refusal path demonstrated on an empty corpus | Product owner |
| 8 | **Observability and audit** — full trajectory in the trace store, hash-chained audit rows for every decision, correlation IDs across model, tool and approval events | A single run replayed end to end from trace plus ledger, with no missing link | Platform |
| 9 | **Economics** — measured cost per run, p95 latency and tokens per step, with a budget that aborts the run rather than overspending | Cost and latency table from the last accepted eval run; `RT-COST-01` green | Practice lead |
| 10 | **Operations** — runbook for the top three failure modes, a rollback that does not require a redeploy, an owner, and a model-change procedure | Runbook reviewed; one model swap rehearsed and rolled back | Practice lead |

## Rules that make the gates real

1. **A gate without a failing example is theatre.** Every gate names at least one
   red-team case or eval assertion that turns red when the control is removed.
   Remove the control, watch the test fail, put it back — that is the acceptance
   test for the gate itself.
2. **Safety gates are never judge-scored.** Deterministic assertions decide
   gates 1–5. A judge may refine quality dimensions only.
3. **Model changes are changes.** Swapping a model alias, a prompt pack or a
   retrieval configuration requires a full eval run and a diff against the last
   accepted baseline. No baseline, no merge.
4. **Exceptions are written, dated and owned.** A gap lives in a GitHub issue with an
   owner and a review date; it does not live in a conversation.
5. **The definition is versioned.** Changing it is an ADR, not an edit — the
   standard is what the next engineer inherits, so it needs a decision record.

## How this maps to a client conversation

| Client question | Gate that answers it |
|---|---|
| "Can the agent touch production?" | 3, 5 |
| "Where does our data go?" | 1, 4 |
| "How do you know it works?" | 6, 7 |
| "What happens when it is wrong?" | 5, 8, 10 |
| "What does it cost per query?" | 9 |
| "Can we audit what it did?" | 8 |

A first conversation that can answer those six in order is the difference
between a pilot and a programme.
