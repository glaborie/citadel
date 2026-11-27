# Static analysis: the one suppression

`.github/workflows/security.yml` runs Bandit, Semgrep (`p/python` + `p/security-audit`,
with `--error`), CodeQL (`security-extended`), Gitleaks, pip-audit, zizmor and a SBOM/grype
pair. Findings land in code scanning under one alert per tool, so an exception has to be
visible there.

There is exactly one suppression in `src/`:

```python
# src/citadel/research/fetch.py
# nosemgrep: python.lang.security.audit.httpsconnection-detected.httpsconnection-detected
connection: http.client.HTTPConnection = http.client.HTTPSConnection(
```

## Why it is there

The rule warns that `HTTPSConnection` may not verify TLS, because the API changed across
Python releases and older versions did not verify by default. Both halves of that premise
are false here:

- the context is `ssl.create_default_context()`, so certificate and hostname verification
  are on (`verify_mode == CERT_REQUIRED`, `check_hostname is True`);
- the protocol floor is explicit, `ssl.TLSVersion.TLSv1_2`;
- the socket is dialled at an address `urlguard.check()` already approved, and the verified
  hostname is passed separately as `server_hostname`.

That last point is why the connection is hand-rolled rather than `urllib.request.urlopen`:
`urlopen` resolves the name again at connect time, so a short-TTL answer could swap in an
internal address between the guard's check and the connect. Pinning the socket to the
checked address is the SSRF defence; the linter sees the cost of that decision, not the
reason for it.

`tests/test_static_analysis_suppressions.py` holds the reasoning in executable form: the
context really does verify, the suppression names its rule, and no other bare `# nosemgrep`
enters `src/`.

## Verifying it, and re-verifying after an upgrade

```bash
uv run --with semgrep semgrep scan \
  --config=p/python --config=p/security-audit \
  src/citadel/research/fetch.py
```

Expect `0 findings`. A scan that reports nothing proves nothing on its own, so check that
the scanner is awake: copy the file, delete the `nosemgrep` line, and confirm the rule
fires on the copy.

```bash
sed 's/# nosemgrep.*//' src/citadel/research/fetch.py > /tmp/fetch-unsuppressed.py
uv run --with semgrep semgrep scan --config=p/python --config=p/security-audit \
  /tmp/fetch-unsuppressed.py   # expect: 1 finding, httpsconnection-detected
```

If the rule stops firing on the unsuppressed copy, the rule was renamed or removed and the
suppression is dead weight: delete it rather than leaving a comment that means nothing.

## Rules for a new suppression

1. Name the rule id. A bare `# nosemgrep` also hides any other rule matching that line, so
   the next finding arrives silently.
2. Write the reason next to it, and add a line here.
3. If the reason is a test's behaviour rather than the code's, say so.

The suppression count is asserted, so a second one shows up in review as a change to a test
rather than as a quiet comment.
