# Judge Calibration

An LLM judge is an instrument with unknown error. Until that error is measured,
its scores are opinions with a decimal point. This protocol makes the judge
defensible in a client review and usable as a merge gate for the dimensions
where it has earned it.

Safety assertions never depend on the judge. Deterministic checks decide
everything in `docs/standards/production-ready.md` gates 1–5. The judge scores
the soft dimensions: plan coherence, justification of tool choice, recovery
narrative, groundedness of the answer, and whether escalation was raised when
evidence was thin.

## Protocol

1. **Sample 30 trajectories** from the last accepted eval run, stratified: 10
   clean successes, 10 partials, 10 failures or near-misses. A judge calibrated
   only on successes looks excellent and gates nothing.
2. **Two human raters** score independently on the rubric below, without seeing
   judge scores. Disagreements are recorded, not reconciled before measurement —
   reconcile afterwards, in the rubric.
3. **Compute kappa** between human and judge, per dimension, with
   `python scripts/cohens_kappa.py labels.json`. Also compute human-vs-human as
   the ceiling: if two humans agree at 0.55, a judge at 0.6 is already at the
   limit of the task, and the rubric is the problem, not the model.
4. **Act on the band:**

| Kappa | Band | Consequence |
|---|---|---|
| < 0.41 | fair or worse | Rubric broken. Rewrite the scale anchors; do not touch the judge yet. |
| 0.41 – 0.60 | moderate | Judge may report, may not gate. Add few-shot anchors per level. |
| 0.61 – 0.80 | substantial | Judge may gate non-safety dimensions with a human spot-check of 10%. |
| > 0.80 | almost perfect | Judge may gate, human spot-check 5%. Re-measure on every model change. |

5. **Re-calibrate on triggers**, not on a calendar: model alias change, prompt
   pack version change, rubric change, or a drift alert from online sampling.
6. **Record the result** with the run: judge model and alias, prompt-pack
   version, rubric version, rater initials, n, kappa per dimension.

## Rubric shape

Four levels per dimension, anchored on observable trajectory evidence, not on
prose quality. Each level needs one sentence a second rater can apply without
asking a question.

| Level | Plan coherence (example) |
|---|---|
| 4 | Steps follow from the symptom; every tool call has a stated purpose; stops when evidence is sufficient |
| 3 | Sound plan with one redundant or missing step that does not change the outcome |
| 2 | Plan reaches the answer by trial; at least one step unjustified or out of order |
| 1 | Plan contradicts the evidence, or repeats a failing step without changing approach |

If two raters cannot apply a level consistently, the level is written badly.
That is a documentation bug and it is cheaper to fix than a judge.

## Reporting

Per eval run, one block in the report:

```
judge            qwen3-32b @ v3 prompt pack, rubric v2
n                30 (10/10/10 stratified)
kappa            plan 0.71 · grounding 0.66 · recovery 0.48 · escalation 0.79
human ceiling    0.74 (plan) · 0.70 (grounding)
gating           plan, grounding, escalation: yes · recovery: report only
note             recovery stays report-only until rubric v3 anchors are tested
```

The `note` line matters more than the numbers: it is the written record that
someone decided what the instrument is allowed to decide. That is the job
description of a practice lead, not of a framework.

## Anti-patterns

- **Judge scores averaged into a single "quality" number.** It hides which
  dimension moved, and it makes regression untraceable.
- **Calibrating on the same 30 items forever.** Once they are in the prompt as
  anchors, the judge memorises them; hold out a rotating set.
- **Letting a judge gate safety.** A confident judge is not a control.
- **Reporting kappa without the human ceiling.** It looks rigorous and says
  nothing about whether the task is well-posed.

## Implementation

The instrument exists; the calibration run does not. That split is deliberate and
it is visible in the code, because a judge that gates before anyone measured it
is the thing this document argues against.

| Piece | Where |
|---|---|
| Rubric catalogue: four dimensions, four anchored levels each | `evals/golden/rubrics.json` |
| Loading and validation (a gap in the levels is a dataset error) | `citadel/evals/rubric.py` |
| Band table and `may_gate` decision, straight from step 4 | `rubric.band` |
| Judge as a model call, JSON-only answer | `rubric.OmniJudge` |
| Evidence rendering, bounded to 8 KB with a digest | `rubric.render_evidence` |
| Kappa per dimension | `scripts/cohens_kappa.py` |

Run it against the gateway:

```bash
uv run python -m citadel.evals --judge auto/best-fast
```

Two failure modes are handled as failures rather than as scores, because both
would otherwise read as a pass:

- **the verdict cannot be read** - no JSON object, a quoted score, an
  out-of-scale level - is a `JudgeMisread` and the grade fails;
- **the judge cannot be reached** is a `JudgeUnavailable` and the grade fails.

The evidence the judge sees is the trajectory: task, each tool call and its
outcome, policy and DLP decisions, the recorded answer. It is capped at 8 KB of
head and tail with the digest of the whole stream, so a 100 KB log cannot push
the rubric out of the context window or out of the record.

**Every dimension ships report-only.** `gates: false` in the catalogue for all
four, including `plan` and `grounding`, because no kappa has been measured yet.
A dimension earns the right to fail a run in the PR that records its calibration:

```json
{ "dimension": "plan", "gates": true, "gating_requires": "kappa 0.71, n=30, 2026-12-01" }
```

The mechanism is tested in both directions: a failing report-only dimension
leaves the exit code alone (`NOTE` in the output), and a failing gating dimension
returns 1.

### Still open

The sample described in step 1 - 30 trajectories, stratified 10/10/10, two
independent raters - has not been drawn. Until it is, the judge produces a number
with a decimal point and no known error, and the documented consequence applies:
it may report, it may not gate.
