"""Drop the results Semgrep suppressed in source before the SARIF is uploaded.

`semgrep scan` honours `# nosemgrep`: with a justified exception in place it reported
`Ran 211 rules on 207 files: 0 findings`. It still wrote that result into the SARIF with
`suppressions: [{"kind": "inSource"}]`, and code scanning does not read the field - so the
suppressed finding arrived as an open alert (#42) that no amount of code could close.

The upload should carry what the scan stands behind. Run it between the scan and
`upload-sarif`:

    python3 scripts/strip-suppressed-sarif.py semgrep.sarif
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


def strip(document: dict[str, Any]) -> int:
    """Remove every result carrying a `suppressions` entry, in place. Returns the count."""
    dropped = 0
    for run in document.get("runs", []):
        results = run.get("results", [])
        kept = [result for result in results if not result.get("suppressions")]
        dropped += len(results) - len(kept)
        run["results"] = kept
    return dropped


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: strip-suppressed-sarif.py <sarif file>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.exists():
        # The scan step failed before writing anything. Say so and leave the exit code
        # alone: this script is not the reason the job is red.
        print(f"no {path} to clean; nothing was uploaded from it")
        return 0
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    dropped = strip(document)
    path.write_text(json.dumps(document), encoding="utf-8")
    print(f"suppressed results dropped: {dropped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
