# Citations

A citation is the chunk you used, not the page you remember. The trajectory
grader checks that every operational claim points at a chunk that was actually
retrieved in this run.

## Shape

- One citation per claim: source id, title, and the chunk id from the retrieval
  result. If you cannot name the chunk, you did not retrieve it.
- A claim that combines two sources needs both. "The release notes and the
  operator guide agree" is two citations.
- Retrieved-and-redacted text is still citable: cite the chunk, never reconstruct
  the value that DLP removed.

## What needs a citation

Anything a reader could act on: a version, a flag, a default, a limit, a
compatibility statement, a step that changes a system. General reasoning from
those facts does not need one.

## What does not

- Arithmetic you performed on cited numbers.
- A restatement of the user's own request.

## Stop instead of asserting

- The retrieved chunks do not contain the answer: say what you searched for and
  what was missing. An unsupported guess fails the run and is worse than a gap.
- Two sources disagree: report both with their chunks and name the conflict.
  Pick neither without a third source.
