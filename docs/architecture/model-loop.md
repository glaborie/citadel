# The model in the loop

One client, one bounded loop, and a rule about cost. Everything else in Citadel
assumed a model that answers; this is the piece that makes the assumption
testable.

```
prompt ──▶ DLP (input) ──▶ OmniRoute ──▶ reply
                                        │
                              ┌─────────┴─────────┐
                        no tool call          tool call
                              │                   │
                           answer          authorize() ──▶ deny / approval / allow
                                                              │
                                                          execute()
                                                              │
                                                     DLP (output) ──▶ context
```

## Why no SDK

The gateway speaks OpenAI-shaped JSON over HTTP. A client library for it would
add a dependency, a version floor and a supply-chain surface to a component
whose entire job is `POST` and parse. `urllib` with an explicit timeout and an
injectable opener is smaller, and the injectable opener is what makes "the
prompt never left the process" an assertion rather than a claim.

The same reasoning that rejected LiteLLM applies here: a transport is not worth
a dependency when the protocol is one request.

## Cost is reported or unknown, never zero

OmniRoute returns `usage.cost` with `usage_evidence` naming where each token
count came from. That number is the cost; arithmetic on it is not.

* `Usage.cost_source` is `reported` or `unreported`.
* A gateway that returns no `cost` yields `cost_usd=None`, and `Usage.add`
  propagates that: a total containing one unreported call is `unreported`, not a
  partial sum that looks complete.
* A budget with `max_cost_usd` cannot be checked against an unreported cost, and
  does not pretend otherwise — the token ceiling still applies.

The report prints `unreported` in that case. A run that cannot state its cost is
a finding, not a zero.

## The loop is where an injection stops being an opinion

A model that obeys a malicious instruction still cannot act:

1. every requested tool goes through `authorize()` — the chokepoint, not a copy
   of it, so the four identity rules and the tier rules apply unchanged;
2. `requires_approval` is a refusal here: no approval token is minted, nothing
   executes;
3. tool output is gated on the `output` surface before it becomes context, so an
   instruction inside a log line or a PR body never reaches a second turn.

Step 3 is why the injection cases are executable without a live model: the
interesting question is what the runtime does with a compliant model, not what a
particular provider chooses to say. `tests/redteam/harness.py` scripts the
compliance and asserts the outcome.

## Budget

`Budget(max_steps, max_tokens, max_cost_usd)`. The loop checks after every model
call and aborts with `run.end` and a `budget.exceeded` step carrying the running
totals. Steps are counted, tokens and cost are measured — the difference matters
because a model that never answers is a cost problem even when every individual
call is cheap.

## What is deliberately not here

* **No retries.** A retry hides a failure behind spend, and the caller (a
  Temporal activity) already owns retry semantics.
* **No prompt caching.** The gateway reports `cached_tokens`; exploiting it is a
  v0.3 problem, and measuring it first is the honest order.
* **No judge.** Evaluation quality is `docs/evals/judge-calibration.md`; putting
  a second model inside the loop would make the loop the thing under test.

## Smoke test

`scripts/model_smoke.py` is the only code path that spends money. It runs inside
the compose network where both OmniRoute and Presidio are reachable, and prints
the trajectory summary plus the answer:

```bash
docker compose run --rm --no-deps \
  -v ~/projects/citadel:/repo:ro -e PYTHONPATH=/repo/src \
  api python /repo/scripts/model_smoke.py
```

It caught two things the unit tests could not: the stack's `OMNIROUTE_URL`
pointed at another gateway's port, and the API image carries a stale install, so
the smoke needs the worktree on `PYTHONPATH` until the image is rebuilt.
