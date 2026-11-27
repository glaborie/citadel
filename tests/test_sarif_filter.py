"""Upload what the scan stands for, not what it decided to suppress.

`semgrep scan` reported `0 findings` for the fetcher and still wrote the suppressed result
into the SARIF, flagged `suppressions: [{"kind": "inSource"}]`. Code scanning does not read
that field, so a justified exception arrived as an open alert (#42).
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "strip-suppressed-sarif.py"
RULE = "python.lang.security.audit.httpsconnection-detected.httpsconnection-detected"


def _result(line: int, **extra: Any) -> dict[str, Any]:
    return {
        "ruleId": RULE,
        "message": {"text": "HTTPSConnection detected"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "src/citadel/research/fetch.py"},
                    "region": {"startLine": line},
                }
            }
        ],
        **extra,
    }


def _sarif(*results: dict[str, Any]) -> dict[str, Any]:
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "Semgrep OSS", "rules": [{"id": RULE}]}},
                "results": list(results),
            }
        ],
    }


def _run(tmp_path: Path, document: dict[str, Any]) -> tuple[subprocess.CompletedProcess[str], Path]:
    path = tmp_path / "semgrep.sarif"
    path.write_text(json.dumps(document), encoding="utf-8")
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, check=False
    )
    return done, path


def _lines(path: Path) -> list[int]:
    document = json.loads(path.read_text(encoding="utf-8"))
    return [
        result["locations"][0]["physicalLocation"]["region"]["startLine"]
        for result in document["runs"][0]["results"]
    ]


def test_a_result_suppressed_in_source_is_not_uploaded(tmp_path: Path) -> None:
    done, path = _run(tmp_path, _sarif(_result(88, suppressions=[{"kind": "inSource"}])))

    assert done.returncode == 0
    assert _lines(path) == []
    assert "dropped: 1" in done.stdout


def test_an_ordinary_result_survives(tmp_path: Path) -> None:
    """The filter must not become a way to lose findings: only suppressed ones go."""
    done, path = _run(
        tmp_path, _sarif(_result(88, suppressions=[{"kind": "inSource"}]), _result(12))
    )

    assert done.returncode == 0
    assert _lines(path) == [12]


def test_the_rest_of_the_document_is_untouched(tmp_path: Path) -> None:
    """Code scanning needs the schema and the rule metadata to place an alert."""
    original = _sarif(_result(88, suppressions=[{"kind": "inSource"}]))
    done, path = _run(tmp_path, original)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["version"] == "2.1.0"
    assert document["$schema"] == original["$schema"]
    assert document["runs"][0]["tool"] == original["runs"][0]["tool"]


def test_a_missing_file_is_not_a_second_failure(tmp_path: Path) -> None:
    """When the scan itself failed there is nothing to clean, and this step stays quiet."""
    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(tmp_path / "absent.sarif")],
        capture_output=True,
        text=True,
        check=False,
    )

    assert done.returncode == 0
    assert "nothing was uploaded" in done.stdout


def test_unreadable_json_fails_loudly(tmp_path: Path) -> None:
    """A SARIF we cannot read is a broken upload; silence would hide it."""
    path = tmp_path / "broken.sarif"
    path.write_text("{not json", encoding="utf-8")

    done = subprocess.run(
        [sys.executable, str(SCRIPT), str(path)], capture_output=True, text=True, check=False
    )

    assert done.returncode != 0
