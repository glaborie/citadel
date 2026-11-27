"""The ingress run budget: one credential cannot loop provider spend (#256).

These run without a database on purpose. A 429 has to be decided before the
request reaches one, and a 400 from the skill-pack lookup is the proof that a
request which stays inside the budget got past the limiter and into the handler.
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from httpx import Response

from citadel.api.app import create_app
from citadel.identity import KeycloakVerifier
from citadel.ratelimit import RunBudget
from tests.conftest import AUDIENCE, ISSUER, StaticKeys, user_token

# Valid per RunRequest, and then refused by the pack lookup rather than the
# limiter: the agent name is well formed and simply has no pack on disk.
RUN = {
    "agent_id": "no-such-agent",
    "prompt_pack_version": "unused-1.0.0",
    "model_alias": "auto/best-fast",
}


def _api(rsa_key: rsa.RSAPrivateKey, *, per_minute: int) -> TestClient:
    verifier = KeycloakVerifier(ISSUER, AUDIENCE, StaticKeys(rsa_key.public_key()))
    return TestClient(create_app(verifier=verifier, budget=RunBudget(per_minute)))


def _post(api: TestClient, token: str) -> Response:
    response: Response = api.post("/runs", json=RUN, headers={"Authorization": f"Bearer {token}"})
    return response


def test_the_allowance_is_spent_then_refused_with_retry_after(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    api = _api(rsa_key, per_minute=2)
    token = user_token(rsa_key)

    assert _post(api, token).status_code == 400, "inside the budget the handler answers"
    assert _post(api, token).status_code == 400

    refused = _post(api, token)
    assert refused.status_code == 429
    assert int(refused.headers["Retry-After"]) >= 1, "a client has to be told when to retry"


def test_one_tenant_exhausting_its_budget_does_not_block_another(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    api = _api(rsa_key, per_minute=1)
    tenant_a = user_token(rsa_key, tenant="lab-a")
    tenant_b = user_token(rsa_key, tenant="lab-b")

    assert _post(api, tenant_a).status_code == 400
    assert _post(api, tenant_a).status_code == 429

    assert _post(api, tenant_b).status_code == 400, "a second tenant must not inherit the refusal"


def test_an_unauthenticated_request_does_not_consume_a_budget(
    rsa_key: rsa.RSAPrivateKey,
) -> None:
    """Otherwise anyone could drain a victim's allowance without a token."""
    api = _api(rsa_key, per_minute=1)
    token = user_token(rsa_key)

    for _ in range(3):
        assert api.post("/runs", json=RUN).status_code == 401

    assert _post(api, token).status_code == 400


def test_the_budget_refills_over_time() -> None:
    now = [0.0]
    budget = RunBudget(1, clock=lambda: now[0])

    assert budget.take("lab-a", "user-alice") is None
    assert budget.take("lab-a", "user-alice") == pytest.approx(60.0)

    now[0] += 61.0
    assert budget.take("lab-a", "user-alice") is None, "a bucket that refilled is a bucket again"
