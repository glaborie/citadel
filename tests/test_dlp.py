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


def person(text: str, *names: str) -> list[dict[str, Any]]:
    """The detector's answer for names, with offsets taken from the text."""
    spans: list[dict[str, Any]] = []
    cursor = 0
    for name in names:
        start = text.index(name, cursor)
        spans.append(
            {"entity_type": "PERSON", "start": start, "end": start + len(name), "score": 0.85}
        )
        cursor = start + len(name)
    return spans


def test_person_is_requested_from_the_detector() -> None:
    seen: list[dict[str, Any]] = []

    def opener(request: Any, timeout: Any = None) -> Response:
        seen.append(json.loads(request.data))
        return Response([])

    dlp.inspect("docker: unknown command", surface="output", analyzer_url=URL, opener=opener)
    assert "PERSON" in seen[0]["entities"]


@pytest.mark.parametrize(
    "name", ["Alice Smith", "Alice", "alice", "Hans Müller", "Jean-Pierre Dupont"]
)
def test_names_are_redacted(name: str) -> None:
    text = f"restarted for {name}"
    verdict = dlp.inspect(
        text, surface="output", analyzer_url=URL, opener=detector(person(text, name))
    )
    assert verdict.action == "redact"
    assert verdict.text == "restarted for <PERSON>"


@pytest.mark.parametrize(
    "text,name",
    [
        ("docker: unknown command: docker compose", "docker"),
        ("Docker Compose is not installed", "Docker Compose"),
        ("Docker daemon is not running", "Docker"),
        ("Keycloak realm citadel is down", "Keycloak"),
        ("Temporal workflow failed on Postgres", "Temporal"),
    ],
)
def test_technical_nouns_are_not_redacted(text: str, name: str) -> None:
    """Calibration: these score 0.85, the same as a name, and must survive."""
    verdict = dlp.inspect(
        text, surface="output", analyzer_url=URL, opener=detector(person(text, name))
    )
    assert verdict.action == "pass"
    assert verdict.text == text


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


TEXT = "contact alice@example.com now"


@pytest.mark.parametrize(
    "item",
    [
        pytest.param(("EMAIL_ADDRESS", 8, 20, 0.9), id="tuple-not-span"),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 20}, id="score-missing"
        ),
        pytest.param(
            {"type": "EMAIL_ADDRESS", "start": 8, "end": 20, "score": 0.9}, id="field-renamed"
        ),
        pytest.param(
            {"entityType": "EMAIL_ADDRESS", "start": 8, "end": 20, "score": 0.9},
            id="camelcase",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": None, "end": 20, "score": 0.9},
            id="start-null",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": "8", "end": 20, "score": 0.9},
            id="start-string",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": True, "end": 20, "score": 0.9},
            id="start-bool",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 20, "score": "high"},
            id="score-string",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 20, "score": True},
            id="score-bool",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": 8, "end": 999, "score": 0.9},
            id="span-past-the-end",
        ),
        pytest.param(
            {"entity_type": "EMAIL_ADDRESS", "start": 20, "end": 8, "score": 0.9},
            id="end-before-start",
        ),
        pytest.param(
            {"entity_type": "", "start": 8, "end": 20, "score": 0.9}, id="no-entity-type"
        ),
    ],
)
def test_a_span_the_reader_cannot_parse_is_a_refusal(item: Any) -> None:
    """Dropping what the reader cannot parse is how redaction stops silently.

    Every case here used to produce an empty finding list, which `inspect` reads as
    `pass` and the caller serves unchanged: a detector that answers differently
    disables the only content control on tool output. The last two used to escape
    as TypeError and ValueError, i.e. a 500 rather than a deliberate refusal.
    """
    with pytest.raises(dlp.DlpUnavailable):
        dlp.inspect(TEXT, surface="output", analyzer_url=URL, opener=detector([item]))


def test_a_span_in_an_unexpected_payload_shape_is_refused() -> None:
    with pytest.raises(dlp.DlpUnavailable):
        dlp.inspect(TEXT, surface="output", analyzer_url=URL, opener=detector({"results": []}))


def test_a_detector_that_found_nothing_still_passes() -> None:
    """Refusing unreadable answers must not turn a clean answer into a block."""
    verdict = dlp.inspect(TEXT, surface="output", analyzer_url=URL, opener=detector([]))

    assert verdict.action == "pass"
    assert verdict.text == TEXT


def test_gate_refuses_an_unreadable_span_and_serves_no_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The refusal must reach the caller as DlpBlocked, with no content attached."""
    malformed = [{"entity_type": "EMAIL_ADDRESS", "start": 8, "score": 0.9}]
    monkeypatch.setattr(dlp, "urlopen", detector(malformed))

    with pytest.raises(dlp.DlpBlocked) as caught:
        dlp.gate(TEXT, surface="output", analyzer_url=URL)

    assert caught.value.reason == "dlp_unavailable"
    assert caught.value.status == 503
    assert "alice@example.com" not in json.dumps(caught.value.report)


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


def test_a_record_surface_redacts_pii_like_an_output() -> None:
    """A reason is rendered and exported, so PII in it is redacted in place."""
    text = "card 4111 1111 1111 1111 on file"
    verdict = dlp.inspect(
        text,
        surface="record",
        analyzer_url=URL,
        opener=detector([{"entity_type": "CREDIT_CARD", "start": 5, "end": 24, "score": 0.95}]),
    )
    assert verdict.action == "redact"
    assert verdict.text == "card <CREDIT_CARD> on file"


def test_a_record_surface_still_blocks_a_credential() -> None:
    """Redaction is for text that can be scrubbed; a token blocks on every surface."""
    text = f"rotating {token()} because it leaked"
    verdict = dlp.inspect(text, surface="record", analyzer_url=URL, opener=detector([]))
    assert verdict.action == "block"
    assert [finding.category for finding in verdict.findings] == ["GITHUB_TOKEN"]


def test_an_unknown_surface_is_a_programming_error() -> None:
    with pytest.raises(ValueError, match="unknown DLP surface"):
        dlp.inspect("x", surface="stdout", analyzer_url=URL, opener=detector([]))
