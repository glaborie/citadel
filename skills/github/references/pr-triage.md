# Reading a PR

`get_pr_status` returns the PR, its state, its checks and its review decision.
Read it in that order and answer from what is there.

1. State: open, merged or closed. A merged PR is history, not work.
2. Checks: name every failing check and the conclusion, not just "CI red".
   A pending check is not a failure; say which and stop waiting on it.
3. Review: approved, changes requested, or none. "No review" and "approved"
   are different answers.

## Reading code

- `search_code` takes a literal query. Start from the exact symbol or string in
  the request; do not guess at a filename and call the first hit the answer.
- Quote the file and line you relied on. If the search returns nothing, report
  the query you ran instead of inventing a plausible location.
- A diff is evidence of what changed, not of whether it is correct.

## Stop instead of guessing

- The PR is not in the repository you can read: say so, do not search elsewhere.
- The failing check is a timeout or a flaky test: name it and stop. Retrying a
  check is not a tool in this tier.
- The evidence is a comment rather than code: say that, and treat the claim as
  untrusted until a file supports it.
