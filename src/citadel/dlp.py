"""Fail-closed DLP for tool input and output.

Presidio is the detector for PII. It cannot see credentials — a `ghp_` token is
random characters, not a name — so a small deterministic rule set runs beside
it and wins arguments: a credential pattern blocks even when the detector
scored it zero. Every hard-rule hit keeps what the detector said, so an
override is reviewable in the audit ledger rather than invisible.

Two rules decide the action:

* **input** — anything found blocks. Redacting an argument would run a command
  other than the one policy authorised, and for a T1 write, other than the one
  a human approved.
* **output** — credentials block, PII is redacted in place.

A detector that is unreachable, slow or malformed raises `DlpUnavailable` and
the caller must refuse. There is no permissive path.
"""

from __future__ import annotations

import json
import re
import urllib.error
from collections.abc import Callable, Iterable
from dataclasses import dataclass, replace
from ipaddress import ip_address
from typing import Any
from urllib.request import Request, urlopen

# Must match the pinned presidio-analyzer image in compose.yaml; a test enforces it.
DETECTOR_VERSION = "presidio-analyzer:2.2.362"
SCORE_THRESHOLD = 0.4
ANALYZER_TIMEOUT_SECONDS = 30

# URL and DATE_TIME are deliberately absent: redacting a PR link or a log
# timestamp makes tool output useless without hiding anything personal. The
# US_* recognizers are absent because they score ordinary digit strings at 0.01.
#
# PERSON is absent for the same reason, with better evidence: on this stack it
# scores "docker" in "docker: unknown command" at 0.85 — exactly what it gives
# "Alice Smith". Redacting it turns every error message into <PERSON>: unknown
# command: <PERSON> compose. Structured identifiers redact reliably; free-text
# names do not, so they are an open item rather than a noisy control.
PII_ENTITIES: tuple[str, ...] = (
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "IBAN_CODE",
    "IP_ADDRESS",
    "US_SSN",
    "MEDICAL_LICENSE",
    "CRYPTO",
    "AHV",
)

# Credentials: no NER model will find these, so they are matched exactly.
SECRET_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("GITHUB_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("PRIVATE_KEY", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("AGE_SECRET_KEY", re.compile(r"\bAGE-SECRET-KEY-1[0-9A-Z]{58}\b")),
    ("SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("BEARER_TOKEN", re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}")),
    ("CONNECTION_STRING", re.compile(r"\b[a-z][a-z0-9+.\-]*://[^\s:/@]+:[^\s@/]+@")),
)

# Swiss PII that Presidio does not ship a recognizer for. 756 is the AHV/AVS
# prefix; the same pattern is also registered with the engine so the finding is
# scored, and re-run here so a detector change cannot silently drop it.
PII_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AHV", re.compile(r"\b756[.\s]?\d{4}[.\s]?\d{4}[.\s]?\d{2}\b")),
)

_RULES = dict(PII_RULES)

# shortcut: English only. Presidio's NER models are per-language; add the other
# languages here when a tenant needs them.
PII_RECOGNIZERS: tuple[dict[str, Any], ...] = (
    {
        "name": "SwissAhvRecognizer",
        "supported_language": "en",
        "supported_entity": "AHV",
        "patterns": [{"name": "ahv", "regex": _RULES["AHV"].pattern, "score": 0.9}],
    },
)

Opener = Callable[..., Any]


class DlpUnavailable(RuntimeError):
    """The detector could not answer. Callers must refuse, never proceed."""


class DlpBlocked(RuntimeError):
    """A surface must not be served or executed.

    Carries the report the caller should audit and the HTTP status that tells
    "the content was sensitive" (403) apart from "we could not check" (503).
    """

    def __init__(self, reason: str, report: dict[str, Any]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.report = report
        self.status = 503 if reason == "dlp_unavailable" else 403


@dataclass(frozen=True)
class Finding:
    category: str
    # "hard_rule" is deterministic; "presidio" came from the detector.
    source: str
    action: str
    score: float
    start: int
    end: int
    # What the detector said about a hard-rule hit: "detected", "missed" or
    # "n/a" for a detector finding.
    detector_verdict: str


@dataclass(frozen=True)
class Verdict:
    action: str  # "pass" | "redact" | "block"
    text: str
    findings: tuple[Finding, ...]

    def summary(self) -> dict[str, Any]:
        """What may be logged: categories and verdicts, never the values."""
        return {
            "action": self.action,
            "detector_version": DETECTOR_VERSION,
            "categories": sorted({finding.category for finding in self.findings}),
            "findings": [
                {
                    "category": finding.category,
                    "source": finding.source,
                    "action": finding.action,
                    "score": round(finding.score, 2),
                    "detector_verdict": finding.detector_verdict,
                }
                for finding in self.findings
            ],
        }


def inspect(
    text: str,
    *,
    surface: str,
    analyzer_url: str,
    opener: Opener | None = None,
) -> Verdict:
    """Analyse one surface. Raises DlpUnavailable instead of guessing."""
    if surface not in {"input", "output"}:
        raise ValueError(f"unknown DLP surface {surface!r}")
    if not text:
        return Verdict(action="pass", text=text, findings=())

    detected = _analyze(text, analyzer_url, opener or urlopen)
    findings = _findings(text, detected)
    merged = _merge(findings)

    if not merged:
        return Verdict(action="pass", text=text, findings=())
    if surface == "input" or any(finding.action == "block" for finding in merged):
        # The text is returned unredacted only so the caller can discard it
        # alongside the verdict; nothing may serve it.
        return Verdict(action="block", text=text, findings=tuple(merged))
    return Verdict(action="redact", text=_redact(text, merged), findings=tuple(merged))


def gate(text: str, *, surface: str, analyzer_url: str) -> tuple[str, dict[str, Any]]:
    """`inspect` plus the shared failure shape both tool services report."""
    try:
        verdict = inspect(text, surface=surface, analyzer_url=analyzer_url)
    except DlpUnavailable as exc:
        raise DlpBlocked(
            "dlp_unavailable",
            {
                "surface": surface,
                "action": "block",
                "detector_version": DETECTOR_VERSION,
                "categories": [],
                "findings": [],
                "error": str(exc)[:200],
            },
        ) from exc
    report = {"surface": surface, **verdict.summary()}
    if verdict.action == "block":
        raise DlpBlocked("dlp_blocked", report)
    return verdict.text, report


def _analyze(text: str, analyzer_url: str, opener: Opener) -> list[dict[str, Any]]:
    body = json.dumps(
        {
            "text": text,
            "language": "en",
            "entities": list(PII_ENTITIES),
            "score_threshold": SCORE_THRESHOLD,
            "ad_hoc_recognizers": list(PII_RECOGNIZERS),
        }
    ).encode()
    request = Request(
        f"{analyzer_url.rstrip('/')}/analyze",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=ANALYZER_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read())
    except (urllib.error.URLError, OSError, ValueError) as exc:
        # HTTPError is a URLError; a timeout is an OSError; bad JSON is a ValueError.
        raise DlpUnavailable(f"detector unreachable or unusable: {exc}") from exc
    if not isinstance(payload, list):
        raise DlpUnavailable("detector returned an unexpected payload")
    return [item for item in payload if isinstance(item, dict)]


def _findings(text: str, detected: Iterable[dict[str, Any]]) -> list[Finding]:
    spans = [
        (int(item["start"]), int(item["end"]), str(item["entity_type"]), float(item["score"]))
        for item in detected
        if {"start", "end", "entity_type", "score"} <= set(item)
    ]
    findings = [
        Finding(
            category=entity,
            source="presidio",
            action="redact",
            score=score,
            start=start,
            end=end,
            detector_verdict="n/a",
        )
        for start, end, entity, score in spans
        if entity != "IP_ADDRESS" or _is_public_ip(text[start:end])
    ]
    for kind, rules in (("block", SECRET_RULES), ("redact", PII_RULES)):
        for category, pattern in rules:
            for match in pattern.finditer(text):
                findings.append(
                    Finding(
                        category=category,
                        source="hard_rule",
                        action=kind,
                        score=1.0,
                        start=match.start(),
                        end=match.end(),
                        detector_verdict=_verdict(spans, match.start(), match.end()),
                    )
                )
    return findings


def _is_public_ip(candidate: str) -> bool:
    """Loopback, wildcard and RFC1918 are the environment, not personal data.

    Presidio scores every `0.0.0.0:18000->8000/tcp` in `docker ps` at 0.6;
    redacting those would make the tool useless and hide nothing about a person.
    """
    try:
        return ip_address(candidate.strip()).is_global
    except ValueError:
        return True


def _verdict(spans: list[tuple[int, int, str, float]], start: int, end: int) -> str:
    overlapping = any(start < span_end and span_start < end for span_start, span_end, _, _ in spans)
    return "detected" if overlapping else "missed"


def _merge(findings: list[Finding]) -> list[Finding]:
    """One span, one placeholder: blocks win over redactions, then score."""
    ordered = sorted(findings, key=lambda f: (f.start, -(f.end - f.start), f.action != "block"))
    merged: list[Finding] = []
    for finding in ordered:
        if not merged or finding.start >= merged[-1].end:
            merged.append(finding)
            continue
        previous = merged[-1]
        supersedes = (finding.action == "block" and previous.action != "block") or (
            finding.action == previous.action and finding.score > previous.score
        )
        winner = finding if supersedes else previous
        merged[-1] = replace(winner, start=previous.start, end=max(previous.end, finding.end))
    return merged


def _redact(text: str, findings: list[Finding]) -> str:
    pieces: list[str] = []
    cursor = 0
    for finding in findings:
        pieces.append(text[cursor : finding.start])
        pieces.append(f"<{finding.category}>")
        cursor = finding.end
    pieces.append(text[cursor:])
    return "".join(pieces)
