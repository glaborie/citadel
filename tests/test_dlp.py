"""DLP: what is redacted, what blocks, and what happens when the detector dies.

The detector is stubbed. The interesting behaviour is ours: the hard rules that
no NER model will find, and the choice to refuse rather than to guess.
"""

from __future__ import annotations

import json
import pathlib
import urllib.error
from typing import Any

import pytest

from citadel import dlp

URL = "http://presidio:3000"


class Response:
    def __init__(self, payload: Any) -> None:
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Response:
        return self

    def __exit__(self, *_: Any) -> None:
        return None


def detector(payload: Any) -> Any:
    def opener(_request: Any, timeout: Any = None) -> Response:
        return Response(payload)

    return opener


def failing(exc: Exception) -> Any:
    def opener(_request: Any, timeout: Any = None) -> Response:
        raise exc

    return opener


def token() -> str:
    return "ghp_" + "a" * 36


def test_swiss_ahv_is_redacted() -> None:
    text = "AHV 756.1234.5678.97 ok"
    verdict = dlp.inspect(
        text,
        surface="output",
        analyzer_url=URL,
        opener=detector([{"entity_type": "AHV", "start": 4, "end": 20, "score": 0.9}]),
    )
    assert verdict.action == "redact"
    assert verdict.text == "AHV <AHV> ok"


def test_custom_recognizer_is_sent_with_every_request() -> None:
    """The AHV pattern lives here, so the engine has to be told about it."""
    seen: list[dict[str, Any]] = []

    def opener(request: Any, timeout: Any = None) -> Response:
        seen.append(json.loads(request.data))
        return Response([])

    dlp.inspect("756.1234.5678.97", surface="output", analyzer_url=URL, opener=opener)
    assert seen[0]["ad_hoc_recognizers"][0]["supported_entity"] == "AHV"
    assert "URL" not in seen[0]["entities"], "redacting links makes output useless"


def test_a_credential_the_detector_misses_blocks() -> None:
    """Red team: Presidio scored it zero, so only the hard rule can stop it."""
    text = f"token {token()}"
    verdict = dlp.inspect(text, surface="output", analyzer_url=URL, opener=detector([]))

    assert verdict.action == "block"
    (finding,) = verdict.findings
    assert finding.category == "GITHUB_TOKEN"
    assert finding.source == "hard_rule"
    assert finding.detector_verdict == "missed"


def test_the_override_records_that_the_detector_saw_it_too() -> None:
    text = f"token {token()}"
    verdict = dlp.inspect(
        text,
        surface="output",
        analyzer_url=URL,
        opener=detector(
            [{"entity_type": "CRYPTO", "start": 6, "end": 6 + len(token()), "score": 1}]
        ),
    )
    (finding,) = [f for f in verdict.findings if f.source == "hard_rule"]
    assert finding.detector_verdict == "detected"


def test_the_audit_summary_never_carries_the_value() -> None:
    secret = token()
    verdict = dlp.inspect(
        f"token {secret}", surface="output", analyzer_url=URL, opener=detector([])
    )
    summary = json.dumps(verdict.summary())
    assert secret not in summary
    assert "GITHUB_TOKEN" in summary


def test_input_is_blocked_instead_of_rewritten() -> None:
    """Rewriting an argument would run a command policy did not authorise."""
    text = json.dumps({"repo": "a/b", "title": "ping anna@example.ch"})
    verdict = dlp.inspect(
        text,
        surface="input",
        analyzer_url=URL,
        opener=detector([{"entity_type": "EMAIL_ADDRESS", "start": 31, "end": 46, "score": 1}]),
    )
    assert verdict.action == "block"
    assert verdict.text == text, "blocked input is never silently altered"


def test_clean_text_passes_through_unchanged() -> None:
    verdict = dlp.inspect(
        "checkout-api restarted", surface="output", analyzer_url=URL, opener=detector([])
    )
    assert verdict.action == "pass"
    assert verdict.text == "checkout-api restarted"
    assert verdict.findings == ()


def test_person_names_are_not_asked_for() -> None:
    """Calibration: PERSON scored "docker" at 0.85 here, so it is not requested."""
    seen: list[dict[str, Any]] = []

    def opener(request: Any, timeout: Any = None) -> Response:
        seen.append(json.loads(request.data))
        return Response([])

    dlp.inspect("docker: unknown command", surface="output", analyzer_url=URL, opener=opener)
    assert "PERSON" not in seen[0]["entities"]


def test_overlapping_hits_are_redacted_once() -> None:
    text = "contact a@example.ch now"
    verdict = dlp.inspect(
        text,
        surface="output",
        analyzer_url=URL,
        opener=detector(
            [
                {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 20, "score": 1},
                {"entity_type": "PERSON", "start": 8, "end": 20, "score": 1},
            ]
        ),
    )
    assert verdict.text == "contact <EMAIL_ADDRESS> now"


def test_detector_failure_is_fail_closed() -> None:
    with pytest.raises(dlp.DlpUnavailable):
        dlp.inspect(
            "anything",
            surface="output",
            analyzer_url=URL,
            opener=failing(urllib.error.URLError("name resolution")),
        )


def test_malformed_detector_response_is_fail_closed() -> None:
    with pytest.raises(dlp.DlpUnavailable):
        dlp.inspect("anything", surface="output", analyzer_url=URL, opener=detector({"oops": 1}))


def test_gate_reports_an_unavailable_detector_as_503(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dlp, "urlopen", failing(TimeoutError("slow")))
    with pytest.raises(dlp.DlpBlocked) as caught:
        dlp.gate("x", surface="output", analyzer_url=URL)
    assert caught.value.reason == "dlp_unavailable"
    assert caught.value.status == 503


def test_detector_version_matches_the_pinned_image() -> None:
    compose = (pathlib.Path(__file__).resolve().parents[1] / "compose.yaml").read_text()
    tag = dlp.DETECTOR_VERSION.split(":", 1)[1]
    assert f"presidio-analyzer:{tag}@" in compose


def test_bind_addresses_in_ports_are_not_personal_data() -> None:
    """`docker ps` prints 0.0.0.0:18000->8000/tcp; redacting it breaks the tool."""
    text = "api   0.0.0.0:18000->8000/tcp, 172.18.0.5"
    verdict = dlp.inspect(
        text,
        surface="output",
        analyzer_url=URL,
        opener=detector(
            [
                {"entity_type": "IP_ADDRESS", "start": 6, "end": 13, "score": 0.6},
                {"entity_type": "IP_ADDRESS", "start": 31, "end": 41, "score": 0.6},
            ]
        ),
    )
    assert verdict.action == "pass"
    assert verdict.text == text


def test_a_public_address_is_still_redacted() -> None:
    verdict = dlp.inspect(
        "from 8.8.8.8",
        surface="output",
        analyzer_url=URL,
        opener=detector([{"entity_type": "IP_ADDRESS", "start": 5, "end": 12, "score": 0.6}]),
    )
    assert verdict.text == "from <IP_ADDRESS>"
