"""The model step as an activity: gates, provenance, and cost that stays honest."""

from __future__ import annotations

from typing import Any

import pytest

from citadel.audit import AuditLedger
from citadel.model import ModelUnavailable, Reply, RequestedTool, ScriptedClient, Usage
from citadel.model.client import parse_reply
from citadel.workflows.model_step import ModelActivities, ModelStepRequest


class FakeAudit(AuditLedger):
    """Records events instead of writing a chain."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def append(self, **kwargs: Any) -> Any:  # noqa: ANN401 - test double
        self.events.append(kwargs)
        from types import SimpleNamespace

        return SimpleNamespace(audit_id=f"audit-{len(self.events)}")


class Detector:
    """Stub Presidio: findings keyed by the text it is asked about."""

    def __init__(self, findings: dict[str, list[dict[str, Any]]] | None = None) -> None:
        self.findings = findings or {}

    def __call__(self, request: Any, timeout: Any = None) -> Detector:
        import json

        payload = json.loads(request.data)
        text = payload["text"]
        self.last_text = text
        # The analyzer answers with a bare list of entities, not an envelope.
        self._body = json.dumps(self.findings.get(text, [])).encode()
        return self

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> Detector:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def request(**overrides: Any) -> ModelStepRequest:
    base: dict[str, Any] = {
        "run_id": "11111111-1111-1111-1111-111111111111",
        "tenant_id": "lab-a",
        "user_id": "user-alice",
        "agent_id": "docker",
        "task": "why is checkout-api restarting?",
    }
    base.update(overrides)
    return ModelStepRequest(**base)


def build(
    replies: list[Reply], *, detector: Detector | None = None
) -> tuple[ModelActivities, FakeAudit]:
    audit = FakeAudit()
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=lambda alias: ScriptedClient(replies),
        analyzer=detector or Detector(),
    )
    return activities, audit


def answered(text: str = "it restarted twice", cost: float | None = 0.001) -> Reply:
    return Reply(
        content=text,
        tools=(),
        usage=Usage(
            prompt_tokens=100,
            completion_tokens=20,
            cost_usd=cost,
            cost_source="reported" if cost is not None else "unreported",
        ),
        model="auto/best-fast",
        latency_ms=12,
    )


def wants(tool: str, arguments: dict[str, Any]) -> Reply:
    return Reply(
        content="checking the container",
        tools=(RequestedTool(name=tool, arguments=arguments),),
        usage=Usage(
            prompt_tokens=120, completion_tokens=30, cost_usd=0.002, cost_source="reported"
        ),
        model="auto/best-fast",
        latency_ms=15,
    )


def test_an_answer_is_returned_with_its_provenance() -> None:
    activities, audit = build([answered()])

    result = activities.next_step(request())

    assert (result.status, result.rule_id) == ("answered", "model.answered")
    assert result.content == "it restarted twice"
    assert result.prompt_pack.startswith("docker")
    assert len(result.prompt_digest) == 64
    event = audit.events[-1]
    assert event["event_type"] == "model.call"
    assert event["payload"]["prompt_digest"] == result.prompt_digest
    assert event["payload"]["cost_usd"] == pytest.approx(0.001)
    assert event["payload"]["cost_source"] == "reported"


def test_a_tool_request_is_reported_not_executed_here() -> None:
    """The activity asks; policy and the specialist decide. That separation is the control."""
    activities, audit = build([wants("read_logs", {"service": "checkout-api"})])

    result = activities.next_step(request())

    assert (result.status, result.tool) == ("tool_requested", "read_logs")
    assert result.arguments == {"service": "checkout-api"}
    assert audit.events[-1]["payload"]["requested_tool"] == "read_logs"


def test_a_credential_in_the_task_never_reaches_the_gateway() -> None:
    calls: list[Any] = []

    class NeverCalled(ScriptedClient):
        def complete(self, **kwargs: Any) -> Reply:  # noqa: ANN401
            calls.append(kwargs)
            return answered()

    detector = Detector()
    audit = FakeAudit()
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=lambda alias: NeverCalled([answered()]),
        analyzer=detector,
    )

    result = activities.next_step(request(task="use token ghp_" + "A" * 36))

    assert result.status == "dlp_blocked"
    assert calls == [], "the prompt left the process"
    assert audit.events[-1]["payload"]["surface"] == "input"


def test_a_poisoned_reply_never_enters_context() -> None:
    """The reply surface is gated too: an answer is context for the next step."""
    activities, audit = build([answered("here it is: ghp_" + "A" * 36)])

    result = activities.next_step(request())

    assert result.status == "dlp_blocked"
    assert result.content == "", "a blocked reply must not travel further"
    assert audit.events[-1]["payload"]["surface"] == "output"


def test_tool_call_markup_in_content_is_not_an_answer() -> None:
    """#168: an untranslated tool request in prose must not complete the run."""
    bar = "\uff5c"
    payload = {
        "model": "auto/best-fast",
        "choices": [
            {
                "message": {
                    "content": (
                        "I'll verify the state before proposing anything. Starting with "
                        "the container inventory.\n\n"
                        f"<{bar}DSML{bar}calls>\n"
                        f'<{bar}DSML{bar}invoke name="inspect_containers">\n'
                        f"</{bar}DSML{bar}invoke>\n"
                        f"</{bar}DSML{bar}calls>"
                    )
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 20, "cost": 0.001},
    }
    activities, audit = build([parse_reply(payload, latency_ms=1)])

    result = activities.next_step(request(task="restart the reranker"))

    assert (result.status, result.rule_id) == ("refused", "model.tool_markup")
    assert result.content == "", "markup must never surface as the answer"
    assert audit.events[-1]["payload"]["status"] == "refused"
    assert audit.events[-1]["payload"]["rule_id"] == "model.tool_markup"


def test_an_unreported_cost_stays_unreported() -> None:
    activities, audit = build([answered(cost=None)])

    result = activities.next_step(request())

    assert result.cost_usd is None
    assert result.cost_source == "unreported"
    assert audit.events[-1]["payload"]["cost_source"] == "unreported"


def test_a_pack_version_that_disagrees_with_disk_is_refused() -> None:
    """A run names the pack it was approved against; using another is a provenance lie."""
    activities, audit = build([answered()])

    result = activities.next_step(request(pack_version="docker-1.0.0@9.9.9"))

    assert (result.status, result.rule_id) == ("refused", "pack.version_mismatch")
    assert audit.events[-1]["event_type"] == "model.call"


def test_an_unknown_agent_is_refused_rather_than_prompted() -> None:
    activities, _ = build([answered()])

    result = activities.next_step(request(agent_id="nobody"))

    assert result.status == "refused"
    assert result.rule_id.startswith("pack.")


def test_a_gateway_outage_is_a_failed_step_not_an_exception() -> None:
    audit = FakeAudit()

    class Down:
        def complete(self, **kwargs: Any) -> Reply:  # noqa: ANN401
            raise ModelUnavailable("gateway unreachable")

    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=lambda alias: Down(),
        analyzer=Detector(),
    )

    result = activities.next_step(request())

    assert (result.status, result.rule_id) == ("unavailable", "model.unavailable")
    assert "unreachable" in result.detail


def test_history_is_appended_after_the_task() -> None:
    """Step two must see what step one said; the task stays where it was."""
    from citadel.workflows.model_step import _messages

    history = [
        {"role": "assistant", "content": "checking"},
        {"role": "user", "content": "[tool result] ok"},
    ]
    turns = _messages(request(history=history), "system text")

    assert [turn["role"] for turn in turns] == ["system", "user", "assistant", "user"]
    assert turns[1]["content"] == "why is checkout-api restarting?"
