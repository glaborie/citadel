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
