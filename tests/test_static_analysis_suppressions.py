"""One static-analysis exception in this repository, and what keeps it honest.

Alert #44 (`python.lang.security.audit.httpsconnection-detected`) is suppressed in
`research/fetch.py`, and it should be: the rule warns that `HTTPSConnection` may not verify
TLS, and this one does - `create_default_context()`, an explicit TLS 1.2 floor, and
hostname verification, because the whole point of the module is to dial the address the
guard already checked (a plain `urlopen` would resolve the name a second time).

The suppression is the risky part, not the connection. These tests keep it attributable
and keep the properties that justify it.
"""

from __future__ import annotations

import re
import socket
import ssl
from pathlib import Path
from typing import Any

import pytest

from citadel.research import fetch

ROOT = Path(__file__).resolve().parents[1]
SOURCES = sorted([*(ROOT / "src").rglob("*.py"), *(ROOT / "scripts").rglob("*.py")])
DYNAMIC_URL = "python.lang.security.audit.dynamic-urllib-use-detected.dynamic-urllib-use-detected"
READER = ROOT / "scripts" / "read-eval-samples.py"
RULE = "python.lang.security.audit.httpsconnection-detected.httpsconnection-detected"


class _Dialled(Exception):
    """Raised to stop `_connect` before it opens a socket."""


def test_every_suppression_names_the_rule_it_suppresses() -> None:
    """A bare `# nosemgrep` hides whatever else matches that line, including a new rule."""
    bare = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in SOURCES
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"#\s*nosemgrep\s*$", line)
    ]
    assert not bare, f"name the rule id in the suppression: {bare}"


def test_the_fetcher_suppresses_exactly_one_rule() -> None:
    """One exception, named. Adding a second should be a decision, not a side effect."""
    text = fetch.__file__ and Path(fetch.__file__).read_text(encoding="utf-8")
    assert text is not None
    assert text.count("# nosemgrep") == 1
    assert f"# nosemgrep: {RULE}" in text


def test_the_connection_verifies_the_certificate_it_is_given(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The rule's premise is an unverified context. Assert the context this code builds.

    The spy returns the real `create_default_context()` and the dial is what fails, so the
    assertions describe the context the module would actually have used.
    """
    captured: dict[str, ssl.SSLContext] = {}
    real = ssl.create_default_context

    def spy(*args: Any, **kwargs: Any) -> ssl.SSLContext:
        context = real(*args, **kwargs)
        captured["context"] = context
        return context

    def refuse_to_dial(*args: Any, **kwargs: Any) -> Any:
        raise _Dialled

    monkeypatch.setattr(ssl, "create_default_context", spy)
    monkeypatch.setattr(socket, "create_connection", refuse_to_dial)

    with pytest.raises(_Dialled):
        fetch._connect("https", "example.com", "93.184.216.34", 443, 1.0)

    context = captured["context"]
    assert context.verify_mode == ssl.CERT_REQUIRED, "certificates must be checked"
    assert context.check_hostname is True, "the name in the URL must match the certificate"
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2, (
        "no protocol floor would be a regression"
    )


def test_the_exception_is_documented() -> None:
    """A suppression with no written reason is indistinguishable from a silencing."""
    guide = (ROOT / "docs" / "security" / "static-analysis.md").read_text(encoding="utf-8")
    assert RULE in guide
    assert "fetch.py" in guide


def test_the_reader_suppresses_exactly_one_rule_and_names_it() -> None:
    """scripts/ is code too: a bare suppression there would silence a whole line."""
    text = READER.read_text(encoding="utf-8")
    assert text.count("# nosemgrep") == 1
    assert f"# nosemgrep: {DYNAMIC_URL}" in text


def test_the_reader_cannot_be_pointed_at_the_filesystem() -> None:
    """What justifies the suppression above: the URL is not actor-controlled.

    `urllib` honours `file://`, which is the rule's premise. The base is the operator's
    tracking URI and must be http(s); the dataset id comes from the ledger and is escaped
    into the path.
    """
    module = _script(READER)
    for bad in ("file:///etc/passwd", "ftp://mlflow:5000", "mlflow:5000"):
        with pytest.raises(ValueError, match="must be http"):
            module.base_url(bad)
    assert module.base_url("http://mlflow:5000/../admin") == "http://mlflow:5000"


def _script(path: Path) -> Any:
    import importlib.util

    spec = importlib.util.spec_from_file_location("script_under_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_every_bandit_suppression_names_its_check() -> None:
    """A bare `# nosec` silences every bandit check on that line, not the one you meant."""
    bare = [
        f"{path.relative_to(ROOT)}:{number}"
        for path in SOURCES
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
        if re.search(r"#\s*nosec\s*$", line)
    ]
    assert not bare, f"name the bandit check id: {bare}"
