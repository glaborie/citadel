"""The model step as an activity: gates, provenance, and cost that stays honest."""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import pytest

from citadel import dlp
from citadel.audit import AuditLedger
from citadel.cache import AnswerCache, InMemoryCacheStore
from citadel.model import ModelUnavailable, Reply, RequestedTool, ScriptedClient, Usage
from citadel.model.client import parse_reply
from citadel.prompts import assemble
from citadel.skills import load_pack
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


def as_chat_agent(monkeypatch: pytest.MonkeyPatch) -> None:
    """The same pack text without the acting flag: a pack that may answer directly."""
    monkeypatch.setattr(
        "citadel.workflows.model_step.assemble",
        lambda agent, task: assemble(
            agent, task, pack=replace(load_pack(agent), requires_tool=False)
        ),
    )


def build(
    replies: list[Reply], *, detector: Detector | None = None, cache: AnswerCache | None = None
) -> tuple[ModelActivities, FakeAudit]:
    audit = FakeAudit()
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=lambda alias: ScriptedClient(replies),
        analyzer=detector or Detector(),
        cache=cache,
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
    # Step two: an observation is behind the answer, so an acting pack may report it.
    history = [{"role": "user", "content": "[tool result] up 2 restarts"}]

    result = activities.next_step(request(history=history))

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


def test_a_dlp_refusal_on_the_conversation_is_a_denied_step() -> None:
    """The input gate runs inside `complete`; its refusal must not kill the activity."""

    class Blocked:
        def complete(self, **kwargs: Any) -> Reply:  # noqa: ANN401
            raise dlp.DlpBlocked(
                "dlp_blocked", {"surface": "input", "action": "block", "categories": []}
            )

    audit = FakeAudit()
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=lambda alias: Blocked(),
        analyzer=Detector(),
    )

    result = activities.next_step(request())

    assert (result.status, result.rule_id) == ("dlp_blocked", "dlp.blocked")
    assert audit.events[-1]["payload"]["status"] == "dlp_blocked"
    assert audit.events[-1]["payload"]["rule_id"] == "dlp.blocked"
    assert audit.events[-1]["payload"]["surface"] == "input"


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


def test_a_zero_tool_answer_from_an_acting_pack_is_refused() -> None:
    """#209: `tr-84819553` narrated a plan and the ledger recorded `completed`."""
    announcement = (
        "I'll start with the read-only checks - daemon health and the container list - "
        "since they don't depend on each other."
    )
    activities, audit = build([answered(announcement)])

    result = activities.next_step(request(task="check the docker daemon and list containers"))

    assert (result.status, result.rule_id) == ("refused", "model.no_tool_call")
    assert result.content == "", "a plan must not surface as the run's answer"
    assert audit.events[-1]["payload"]["status"] == "refused"
    assert audit.events[-1]["payload"]["rule_id"] == "model.no_tool_call"


def test_the_gate_does_not_fire_once_a_tool_has_been_observed() -> None:
    """The rule is "no observation", not "never answer": a result may be reported."""
    activities, _ = build([answered("the daemon reports two restarts")])
    history = [
        {"role": "assistant", "content": "checking the daemon"},
        {"role": "user", "content": "[tool result] up 2 restarts"},
    ]

    result = activities.next_step(request(history=history))

    assert (result.status, result.rule_id) == ("answered", "model.answered")


def test_a_pack_without_the_flag_may_answer_directly(monkeypatch: pytest.MonkeyPatch) -> None:
    """A chat agent answers from context; acting is the pack's declaration, not a guess."""
    as_chat_agent(monkeypatch)
    activities, _ = build([answered()])

    result = activities.next_step(request())

    assert (result.status, result.rule_id) == ("answered", "model.answered")


def test_an_acting_pack_never_reads_the_answer_cache() -> None:
    """Only a first-step answer is cacheable, and an acting pack's first step must act."""
    activities, audit, store, calls = cached_build([answered(), answered()])

    first = activities.next_step(request())
    second = activities.next_step(request())

    assert (first.status, second.status) == ("refused", "refused")
    assert not store.entries, "a plan must not be stored for a later run to replay"
    assert not [event for event in audit.events if event["event_type"] == "cache.lookup"]
    assert len(calls) == 2


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


def cached_build(
    replies: list[Reply], *, detector: Detector | None = None
) -> tuple[ModelActivities, FakeAudit, InMemoryCacheStore, list[int]]:
    """A model step with a cache, counting how often the gateway is asked."""
    calls: list[int] = []
    audit = FakeAudit()
    remaining = iter(replies)

    def factory(alias: str) -> ScriptedClient:
        calls.append(1)
        return ScriptedClient([next(remaining)])

    store = InMemoryCacheStore()
    activities = ModelActivities(
        dsn="postgres://unused",
        audit=audit,
        client_factory=factory,
        analyzer=detector or Detector(),
        cache=AnswerCache(backend=store),
    )
    return activities, audit, store, calls


def test_a_cached_answer_skips_the_second_model_call(monkeypatch: pytest.MonkeyPatch) -> None:
    as_chat_agent(monkeypatch)
    activities, audit, _, calls = cached_build([answered(), answered()])

    first = activities.next_step(request())
    second = activities.next_step(request())

    assert (first.status, first.rule_id) == ("answered", "model.answered")
    assert (second.status, second.rule_id) == ("answered", "cache.hit")
    assert second.content == first.content
    assert (second.cost_usd, second.cost_source) == (0.0, "reported")
    assert len(calls) == 1, "a hit must not spend a model call"
    decisions = [
        event["payload"]["decision"]
        for event in audit.events
        if event["event_type"] == "cache.lookup"
    ]
    assert decisions == ["miss", "exact"]


def test_a_tool_request_is_never_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    """Only a plain answer is cacheable, so no tool result can be replayed."""
    as_chat_agent(monkeypatch)
    activities, audit, _, calls = cached_build(
        [wants("read_logs", {"service": "checkout-api"}), answered()]
    )

    first = activities.next_step(request())
    second = activities.next_step(request())

    assert first.rule_id == "model.tool_requested"
    assert second.rule_id == "model.answered"
    assert len(calls) == 2
    decisions = [
        event["payload"]["decision"]
        for event in audit.events
        if event["event_type"] == "cache.lookup"
    ]
    assert decisions == ["miss", "miss"]


def test_an_output_blocked_answer_is_not_stored(monkeypatch: pytest.MonkeyPatch) -> None:
    as_chat_agent(monkeypatch)
    secret = "here it is: ghp_" + "A" * 36
    activities, _, store, _ = cached_build([answered(secret), answered("clean")])

    blocked = activities.next_step(request())
    assert blocked.status == "dlp_blocked"
    assert not store.entries, "a refused answer must not be cached"

    again = activities.next_step(request())
    assert again.rule_id == "model.answered"


def test_a_later_step_does_not_read_the_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    """A conversation with tool output cannot be answered by a first-step entry."""
    as_chat_agent(monkeypatch)
    activities, _, _, calls = cached_build([answered(), answered()])

    activities.next_step(request())
    later = activities.next_step(request(history=[{"role": "user", "content": "[tool result] ok"}]))

    assert later.rule_id == "model.answered"
    assert len(calls) == 2
