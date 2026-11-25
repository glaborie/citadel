"""The model in the loop: cost provenance, prompt gating, budget enforcement.

What is tested here is the part a real model cannot make deterministic — what
the loop does with a reply, not what a provider decides to say.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

import pytest

from citadel import dlp
from citadel.model import Budget, Reply, RequestedTool, ScriptedClient, Usage, run_agent
from citadel.model.client import ModelUnavailable, OmniRouteClient, parse_reply, parse_usage
from citadel.policy import AuthorizationRequest, authorize

ANALYZER = "http://presidio.test"
CREDENTIAL = "dsn: postgres://citadel:testpassw0rd@checkout-db:5432/checkout"


class _Response:
    def __init__(self, payload: Any) -> None:
        self._body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_: object) -> None:
        return None


def transport(payload: Any, seen: list[str]) -> Any:
    """Answer the detector with no findings, and the gateway with the payload."""

    def opener(request: Any, timeout: Any = None) -> _Response:
        url = str(request.full_url)
        seen.append(url)
        return _Response([] if "/analyze" in url else payload)

    return opener


def detector(payload: Any) -> Any:
    def opener(request: Any, timeout: Any = None) -> _Response:
        assert "/analyze" in str(request.full_url)
        return _Response(payload)

    return opener


def reply(*, tools: tuple[RequestedTool, ...] = (), text: str = "", tokens: int = 100) -> Reply:
    return Reply(
        content=text,
        tools=tools,
        usage=Usage(
            prompt_tokens=tokens - 20,
            completion_tokens=20,
            cost_usd=1e-5,
            cost_source="reported",
        ),
        model="scripted",
        latency_ms=3,
    )


class _Checker:
    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed

    def can_call(self, *, user: str, obj: str) -> bool:
        return self.allowed


class _Runs:
    def exists(self, *, tenant_id: str, run_id: str) -> bool:
        return True


def decision_for(tool: str, *, allowed: bool = True) -> Any:
    return authorize(
        AuthorizationRequest(
            user_id="alice", tenant_id="lab-a", run_id="run-1", agent_id="docker", tool=tool
        ),
        _Checker(allowed),
        _Runs(),
    )


def gate(text: str, surface: str) -> str:
    verdict = dlp.inspect(text, surface=surface, analyzer_url=ANALYZER, opener=detector([]))
    if verdict.action == "block":
        raise dlp.DlpBlocked("dlp_blocked", {"surface": surface, **verdict.summary()})
    return verdict.text


# ------------------------------------------------------------- cost


def test_usage_carries_the_gateway_cost() -> None:
    usage = parse_usage(
        {
            "prompt_tokens": 31,
            "completion_tokens": 7,
            "cost": 2.27e-05,
            "prompt_tokens_details": {"cached_tokens": 4},
        }
    )
    assert usage.cost_source == "reported"
    assert usage.cost_usd == pytest.approx(2.27e-05)
    assert usage.cached_tokens == 4
    assert usage.total == 38


def test_missing_cost_is_unknown_rather_than_zero() -> None:
    unreported = parse_usage({"prompt_tokens": 10, "completion_tokens": 5})
    assert unreported.cost_usd is None
    assert unreported.cost_source == "unreported"

    reported = Usage(cost_usd=1e-5, cost_source="reported")
    mixed = reported.add(unreported)
    assert mixed.cost_usd is None
    assert mixed.cost_source == "unreported"
    assert mixed.total == 15


def test_a_budget_without_a_cost_ceiling_cannot_be_checked_against_one() -> None:
    usage = Usage(prompt_tokens=10, completion_tokens=5)
    assert Budget(max_steps=1, max_tokens=100, max_cost_usd=0.0).exceeded(usage, 1) is None


# ----------------------------------------------------------- client


def test_a_credential_in_the_prompt_never_reaches_the_gateway() -> None:
    egress: list[str] = []

    def opener(request: Any, timeout: Any = None) -> _Response:
        url = str(request.full_url)
        if "/analyze" in url:
            return _Response([])
        egress.append(url)
        raise AssertionError(f"prompt left the process: {url}")

    client = OmniRouteClient(
        base_url="http://omniroute.test", api_key="k", analyzer_url=ANALYZER, opener=opener
    )
    with pytest.raises(dlp.DlpBlocked) as blocked:
        client.complete(messages=[{"role": "user", "content": f"deploy failed. {CREDENTIAL}"}])
    assert blocked.value.reason == "dlp_blocked"
    assert egress == []


def test_a_completion_parses_tool_calls_and_cost() -> None:
    seen: list[str] = []
    payload = {
        "model": "auto/best-fast",
        "choices": [
            {
                "message": {
                    "content": "checking",
                    "tool_calls": [
                        {
                            "id": "call-1",
                            "function": {
                                "name": "inspect_containers",
                                "arguments": "{\"all\": true}",
                            },
                        }
                    ],
                },
                "finish_reason": "tool_calls",
            }
        ],
        "usage": {"prompt_tokens": 272, "completion_tokens": 33, "cost": 2.27e-05},
    }
    client = OmniRouteClient(
        base_url="http://omniroute.test",
        api_key="k",
        analyzer_url=ANALYZER,
        opener=transport(payload, seen),
    )
    parsed = client.complete(
        messages=[{"role": "user", "content": "list containers"}], run_id="run-1"
    )

    assert parsed.tools[0].name == "inspect_containers"
    assert parsed.tools[0].arguments == {"all": True}
    assert parsed.usage.cost_usd == pytest.approx(2.27e-05)
    assert parsed.model == "auto/best-fast"
    assert parsed.latency_ms >= 0
    assert seen[-1].endswith("/v1/chat/completions")


def test_a_gateway_error_is_an_unavailable_model_not_an_empty_answer() -> None:
    seen: list[str] = []
    client = OmniRouteClient(
        base_url="http://omniroute.test",
        api_key="k",
        analyzer_url=ANALYZER,
        opener=transport({"error": {"code": "provider_not_configured"}}, seen),
    )
    with pytest.raises(ModelUnavailable):
        client.complete(messages=[{"role": "user", "content": "hi"}])


def test_a_malformed_completion_is_refused() -> None:
    with pytest.raises(ModelUnavailable):
        parse_reply({"choices": []}, latency_ms=1)


# ------------------------------------------------------------- loop


def test_an_allowed_tool_runs_once_and_the_run_completes() -> None:
    executed: list[str] = []

    def execute(name: str, arguments: Mapping[str, Any]) -> str:
        executed.append(name)
        return "3 containers"

    model = ScriptedClient(
        [
            reply(tools=(RequestedTool("inspect_containers", {}, "call-1"),)),
            reply(text="three containers are healthy"),
        ]
    )
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "how are the containers?"}],
        authorize=lambda tool: decision_for(tool),
        execute=execute,
        gate=gate,
    )
    assert trajectory.outcome == "completed"
    assert executed == ["inspect_containers"]
    assert trajectory.tools_executed() == ("inspect_containers",)
    assert trajectory.usage.cost_usd == pytest.approx(2e-05)


def test_a_t1_tool_without_approval_is_refused_and_never_executes() -> None:
    executed: list[str] = []

    def execute(name: str, arguments: Mapping[str, Any]) -> str:
        executed.append(name)
        return "ok"

    model = ScriptedClient(
        [reply(tools=(RequestedTool("restart_service", {"service": "checkout-api"}, "c1"),))]
    )
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "restart checkout"}],
        authorize=lambda tool: decision_for(tool),
        execute=execute,
        gate=gate,
    )
    assert trajectory.outcome == "refused"
    assert executed == []
    rules = [step.rule_id for step in trajectory.steps if step.kind == "policy.decision"]
    assert rules == ["policy.tier_requires_approval"]


def test_a_denied_tool_is_reported_as_a_policy_denial() -> None:
    model = ScriptedClient([reply(tools=(RequestedTool("inspect_containers", {}, "c1"),))])
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "list"}],
        authorize=lambda tool: decision_for(tool, allowed=False),
        execute=lambda name, arguments: "should not run",
        gate=gate,
    )
    assert trajectory.outcome == "policy_denied"
    assert trajectory.tools_executed() == ()


def test_poisoned_tool_output_is_blocked_before_it_becomes_context() -> None:
    executed: list[str] = []

    def execute(name: str, arguments: Mapping[str, Any]) -> str:
        executed.append(name)
        return f"log line {CREDENTIAL}"

    model = ScriptedClient(
        [reply(tools=(RequestedTool("read_logs", {"service": "checkout"}, "c1"),))]
    )
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "check the logs"}],
        authorize=lambda tool: decision_for(tool),
        execute=execute,
        gate=gate,
    )
    assert trajectory.outcome == "dlp_blocked"
    assert executed == ["read_logs"]
    assert model.calls == 1, "a blocked output must not be fed back to the model"


def test_the_token_budget_stops_a_model_that_keeps_calling_tools() -> None:
    model = ScriptedClient(
        [
            reply(
                tools=(RequestedTool("read_logs", {"service": "checkout"}, f"c{index}"),),
                tokens=2500,
            )
            for index in range(4)
        ]
    )
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "keep checking"}],
        authorize=lambda tool: decision_for(tool),
        execute=lambda name, arguments: "unchanged",
        gate=gate,
        budget=Budget(max_steps=4, max_tokens=5000, max_cost_usd=1.0),
    )
    assert trajectory.outcome == "budget_exceeded"
    assert trajectory.usage.total > 5000
    assert trajectory.usage.cost_usd is not None
    assert "budget.exceeded" in trajectory.events()
    assert model.calls == 3, "the third call crosses the ceiling and the fourth never happens"


def test_the_step_ceiling_stops_a_model_that_never_answers() -> None:
    model = ScriptedClient(
        [
            reply(tools=(RequestedTool("read_logs", {"service": "checkout"}, f"c{index}"),))
            for index in range(5)
        ]
    )
    trajectory = run_agent(
        complete=model.complete,
        messages=[{"role": "user", "content": "go"}],
        authorize=lambda tool: decision_for(tool),
        execute=lambda name, arguments: "unchanged",
        gate=gate,
        budget=Budget(max_steps=2, max_tokens=100000, max_cost_usd=None),
    )
    assert trajectory.outcome == "budget_exceeded"
    assert "steps=2" in trajectory.steps[-2].detail
