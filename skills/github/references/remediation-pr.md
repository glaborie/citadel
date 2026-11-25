# Opening a remediation PR

`open_remediation_pr` is a T1 write. The approval names the exact title and
body, so both must say what a reviewer needs without your transcript.

## The arguments are matched literally

- Title and body are a single line each. A newline is rejected by the
  allowlist matcher, not by the model.
- `..` is rejected anywhere in the text, because the matcher refuses the token.
- Keep the title under 72 characters: it is a commit-style subject, not a
  summary of the run.

## What the PR must contain

- The symptom, with the evidence: the failing check, the log line, the file and
  line you read.
- The change, in one sentence. If it needs a paragraph, the change is too large
  for one PR from this tier.
- A draft, always. A human decides when it is ready for review.

## Stop instead of opening

- The fix touches a secret, a credential, a workflow file or an infrastructure
  manifest outside the repository's own source: that is not a remediation PR.
- The change is more than one file, or the request asks for several changes:
  propose one PR per change and let a human sequence them.
- The evidence is a hunch. A draft PR that a reviewer must debug is worse than
  a written finding.

## Never

- Name a person, a token or an internal host in the title or body if a
  description of the component is enough. The body is published.
- Reopen or force-update an existing PR. This tier creates; it does not amend.
