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

## Sample v1: what it is, and what it is not

Step 1 above says *sample 30 trajectories from the last accepted eval run, 10/10/10*. The
accepted run has no such spread: the golden dataset is 14 cases that all pass, and exactly
one of them carried a judge block. Rather than wait for a run that does not exist, sample
v1 is **authored** and says so:

- ten **clean** items are the golden trajectories with a written final answer;
- ten **partial** and ten **near-miss** items are the same trajectories treated worse - a
  dropped citation, a restart before any diagnosis, a step repeated without a new idea, an
  answer that claims more than the events contain - each with the flaw named in the file
  and in `evals/calibration/sample-v1.json` under `provenance`.

What that buys: 30 trajectories with a known spread, on which a human and the judge can be
compared. What it costs: a kappa measured here describes agreement on these trajectories,
not the distribution of live runs. Both sentences belong next to the numbers.

```bash
make calibration-sample     # rebuild the sample from the goldens (deterministic)
make calibration-sheet      # the blind labelling sheet for the human rater
make calibration-check      # sample, sheet and key agree with what is committed
```

The sheet renumbers items by a hash of the sample id, and the band and mutation live in
`evals/calibration/label-key.json` so that a kappa cannot be computed against a rater who
already knew which items were meant to be bad.

## What is still missing

The judge run itself. Kappa needs `human` and `judge` scores for the same items; the sheet
produces the first, `python -m citadel.evals --judge ALIAS` on the sample produces the
second, and `scripts/cohens_kappa.py` turns each dimension into a number. Until those
exist, a dimension keeps `gates: false` - which is where all four are today.

## Result: sample v1, measured 2026-11-26

```
judge            auto/best-reasoning @ rubrics v1, deterministic suite offline
n                27 per dimension (30 sampled; 3 unjudged - see below)
kappa            plan 0.31 · grounding 0.05 · recovery 0.14 · escalation 0.06
human ceiling    not measured: one human rater, so "weak judge" and "ambiguous anchors"
                 cannot yet be told apart
gating           none. All four dimensions stay report-only.
note             kappa is below 0.41 on every dimension, which the band table calls a
                 broken rubric: rewrite the anchors before touching the judge.
```

Observed agreement runs 0.22 to 0.59, and the confusion matrices say why: on grounding,
**eleven** items are human 4 / judge 2, and on recovery **twelve** are human 4 / judge 1.
The judge is not noisy, it is systematically harsher - two raters reading the same anchor
and placing the same trajectory four levels apart are reading different questions. That is
what "rewrite the anchors" means here: the 4 level for grounding ("every claim traces to a
tool result or citation") and the 2 level ("asserts at least one fact the record does not
contain") do not share a boundary a reader can apply, because an answer can be both.

## The three items the judge never saw

`item-04`, `item-13` and `item-24` are the trajectories whose evidence quotes a credential
(the DLP drill and the two samples derived from it). The judge client runs the same DLP gate
on its own prompt as everything else, and that gate cannot tell a planted fixture from a live
token - so those items came back `dlp_blocked`, on all four dimensions, and the kappa is
computed over the 27 items both raters saw.

That is the correct failure: an item the judge could not read is not a low score, and filling
the gap with a default would have produced a kappa about the default. It is also a real
limitation of judging DLP fixtures at all, and worth stating where the numbers are: **the
judge cannot grade a trajectory whose evidence contains what DLP blocks.**

## What this result changes

Nothing in the rubric catalogue: all four dimensions keep `gates: false`, now because a
number says so rather than because nobody measured. A test (`tests/test_judge_calibration.py`)
keeps them that way - it reads the kappa from this block and fails if a dimension gates
without clearing 0.61.

Next, in order:

1. rewrite the four anchor sets so that a second reader can apply a level without asking a
   question, starting with the grounding 4/2 boundary and the recovery 4/1 boundary;
2. have a second human label the same 30 items, so the next run has a ceiling to compare
   against - without it, a low kappa cannot distinguish a harsh judge from an ambiguous task;
3. re-run `scripts/judge-sample.py` and `scripts/label-merge.py`, and only then consider a
   `gates: true`.

## Rubric v2: the two boundaries the v1 measurement condemned

The kappa above is about **rubrics v1**. Two of the four boundaries were the reason for it,
and both were rewritten rather than the threshold lowered. Everything below is v2; the
numbers stay attached to v1 until a run under v2 replaces them.

### Grounding: an inference is not an assertion of fact

v1 level 4 said "nothing is inferred beyond it", and level 2 said "asserts a fact the record
does not contain". Every diagnosis is an inference, so a rater reading level 4 saw a
well-sourced inference and marked it 4, while the judge reading level 2 saw a claim the
record did not contain and marked it 2 - eleven times out of 27.

v2 states the rule the two levels were fighting over: **a claim is an inference when its
evidence is named beside it, and an assertion when it is not.** Level 4 now admits an
inference that points at what it rests on; level 2 now requires that the claim be one the
recommendation depends on, and that no evidence be named.

### Recovery: nothing failed is a 4, not a missing measurement

v1 level 1 was "repeats the failing step, or ignores the failure and reports success", and
the scale had no entry for a run in which nothing failed. Twelve of 27 items were human 4 /
judge 1: the human read a clean single attempt as a 4, the judge read the absence of a
recovery narrative as a 1.

v2 says it outright: a run with no failure scores 4 when it does not imply one. Scoring it
low because there was no incident turns the dimension into a measure of incident rate, and
punishes the trajectories that behaved. Retrying once before changing approach is now a 2,
and repeating unchanged is a 1 at three attempts - a counted rule rather than a judgement.

### What did not change

`gates` stays false on all four dimensions, `threshold` stays 3, and plan and escalation are
untouched at v1. The measurement above is the reason for the rewrite, and no dimension earns
a gate from it.

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
