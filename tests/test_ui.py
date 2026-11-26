"""Console views: session gating, CSRF, and who may decide what.

The Keycloak redirect itself is not exercised here; the session cookie is
signed directly so the tests drive the same routes a logged-in browser would.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import jwt
import pytest
from fastapi.testclient import TestClient

from citadel import net
from citadel.ui import app as ui_app

KEY = "test-session-key-0123456789abcdef"
RUN = "11111111-1111-1111-1111-111111111111"
REQUEST = "22222222-2222-2222-2222-222222222222"


class Cursor:
    def __init__(self, rows: list[Any]) -> None:
        self._rows = rows

    def fetchall(self) -> list[Any]:
        return self._rows

    def fetchone(self) -> Any:
        return self._rows[0] if self._rows else None


class FakeDB:
    def __init__(self) -> None:
        self.tenants: list[str] = []
        self.statements: list[tuple[str, tuple[Any, ...]]] = []
        self.runs = [(RUN, "user-alice", "docker", "T1", "created", "2026-01-01")]
        self.pending = [(REQUEST, RUN, "restart_service", "docker", "T1", "user-alice", "now")]
        self.request: list[Any] = [
            (
                REQUEST,
                RUN,
                "restart_service",
                "docker",
                {"service": "checkout-api"},
                "T1",
                "policy.tier_requires_approval",
                "user-alice",
                "pending",
                "2026-01-01",
            )
        ]
        self.events = [
            (1, "policy.decision", "agent", "docker", {"decision": "requires_approval"}, "now")
        ]
        self.calls = [("restart_service", "executed", "now")]

    @contextmanager
    def connect(self, _dsn: str, tenant: str) -> Iterator[FakeConn]:
        self.tenants.append(tenant)
        yield FakeConn(self)


class FakeConn:
    def __init__(self, db: FakeDB) -> None:
        self._db = db

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> Cursor:
        statement = " ".join(sql.split())
        self._db.statements.append((statement, params))
        if statement.startswith("SELECT id, user_id, agent_id"):
            return Cursor(self._db.runs)
        if statement.startswith("SELECT id, run_id, tool, agent_id, arguments"):
            return Cursor(self._db.request)
        if statement.startswith("SELECT id, run_id, tool, agent_id, tier"):
            return Cursor(self._db.pending)
        if statement.startswith("SELECT seq, event_type"):
            return Cursor(self._db.events)
        if statement.startswith("SELECT tool, status, created_at"):
            return Cursor(self._db.calls)
        if statement.startswith("UPDATE approval_requests SET status = 'expired'"):
            return Cursor([])
        raise AssertionError(f"unexpected SQL: {statement}")


def session(**overrides: Any) -> str:
    claims: dict[str, Any] = {
        "access_token": "user-access-token",
        "sub": "user-carol",
        "tenant": "lab-a",
        "roles": ["approver"],
        "csrf": "csrf-value",
        "exp": int(time.time()) + 60,
    }
    claims.update(overrides)
    return jwt.encode(claims, KEY, algorithm="HS256")


@pytest.fixture
def env(monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, FakeDB]:
    db = FakeDB()
    monkeypatch.setattr(ui_app, "tenant_connection", db.connect)
    app = ui_app.create_app(dsn="postgres://fake", api_url="http://api.test", session_key=KEY)
    return TestClient(app), db


def _login(client: TestClient, **overrides: Any) -> None:
    client.cookies.set(ui_app.COOKIE, session(**overrides))


def test_no_session_redirects_to_login(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    response = client.get("/runs", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_expired_session_redirects_to_login(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client, exp=int(time.time()) - 1)
    assert client.get("/runs", follow_redirects=False).status_code == 303


def test_unknown_role_is_refused(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client, roles=["nobody"])
    assert client.get("/runs").status_code == 403


def test_runs_list_is_tenant_scoped(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["operator"])
    response = client.get("/runs")
    assert response.status_code == 200
    assert "11111111" in response.text
    assert db.tenants and set(db.tenants) == {"lab-a"}


def test_argument_preview_is_escaped(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    db.request[0] = (*db.request[0][:4], {"note": "<script>alert(1)</script>"}, *db.request[0][5:])
    _login(client)
    response = client.get(f"/approvals/{REQUEST}")
    assert response.status_code == 200
    assert "<script>alert(1)</script>" not in response.text
    assert "&lt;script&gt;" in response.text


FRAMING = {
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "cache-control": "no-store",
}


def _assert_refuses_framing(response: Any) -> None:
    for header, expected in FRAMING.items():
        assert response.headers[header] == expected, header
    csp = response.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in csp
    assert "form-action 'self'" in csp


@pytest.mark.parametrize(
    "path",
    ["/", "/runs", "/approvals", f"/approvals/{REQUEST}", "/audit"],
)
def test_every_console_view_refuses_framing(
    env: tuple[TestClient, FakeDB], path: str
) -> None:
    """A framed approval page is a T1 write decided by a decoy click."""
    client, _ = env
    _login(client)

    response = client.get(path)

    assert response.status_code == 200, path
    _assert_refuses_framing(response)


def test_the_login_redirect_refuses_framing(env: tuple[TestClient, FakeDB]) -> None:
    """A redirect is also a response a framing page can follow."""
    client, _ = env

    response = client.get("/runs", follow_redirects=False)

    assert response.status_code == 303
    _assert_refuses_framing(response)


def test_a_decision_post_refuses_framing(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client)

    response = client.post(
        f"/approvals/{REQUEST}/decide",
        data={"decision": "approve", "reason": "ok"},
        follow_redirects=False,
    )

    _assert_refuses_framing(response)


def test_a_refusal_refuses_framing(env: tuple[TestClient, FakeDB]) -> None:
    """The 403 a wrong role gets is still a page: it must not be framable either."""
    client, _ = env
    _login(client, roles=["nobody"])

    response = client.get("/runs")

    assert response.status_code == 403
    _assert_refuses_framing(response)


def test_decide_requires_csrf(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client)
    response = client.post(
        f"/approvals/{REQUEST}/decide", data={"decision": "approve", "reason": "ok"}
    )
    assert response.status_code == 403


def test_decide_requires_the_approver_role(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client, roles=["operator"])
    response = client.post(
        f"/approvals/{REQUEST}/decide",
        data={"csrf": "csrf-value", "decision": "approve", "reason": "ok"},
    )
    assert response.status_code == 403


def test_decide_requires_a_reason(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    _login(client)
    response = client.post(
        f"/approvals/{REQUEST}/decide",
        data={"csrf": "csrf-value", "decision": "approve", "reason": " "},
    )
    assert response.status_code == 400


def test_nobody_approves_their_own_request(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    db.request[0] = (*db.request[0][:7], "user-carol", *db.request[0][8:])
    _login(client, sub="user-carol")
    response = client.post(
        f"/approvals/{REQUEST}/decide",
        data={"csrf": "csrf-value", "decision": "approve", "reason": "ok"},
    )
    assert response.status_code == 403


def test_decide_forwarded_to_the_api_with_the_user_token(
    env: tuple[TestClient, FakeDB], monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _ = env
    _login(client)
    seen: dict[str, Any] = {}

    class Reply:
        status = 200

        def read(self) -> bytes:
            return b'{"approved": true}'

        def __enter__(self) -> Reply:
            return self

        def __exit__(self, *_: Any) -> None:
            return None

    def fake(request: Any, timeout: Any = None) -> Reply:
        seen["url"] = request.full_url
        seen["headers"] = dict(request.header_items())
        seen["body"] = request.data
        return Reply()

    monkeypatch.setattr(net, "urlopen", fake)
    response = client.post(
        f"/approvals/{REQUEST}/decide",
        data={"csrf": "csrf-value", "decision": "approve", "reason": "looks fine"},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert seen["url"] == "http://api.test/approvals"
    assert seen["headers"]["Authorization"] == "Bearer user-access-token"
    assert b'"approved": true' in seen["body"]


def test_audit_search_passes_the_filters_through(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["viewer"])
    response = client.get("/audit", params={"event_type": "policy.decision", "q": "requires"})
    assert response.status_code == 200
    _, params = db.statements[-1]
    assert params == ("policy.decision", "policy.decision", "", "%%", "requires", "%requires%")


def test_runs_sort_uses_only_whitelisted_columns(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["operator"])
    assert client.get("/runs", params={"sort": "user", "dir": "asc"}).status_code == 200
    sql, _ = db.statements[-1]
    assert sql.endswith("ORDER BY user_id ASC LIMIT 100")


def test_unknown_sort_falls_back_and_never_reaches_sql(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["operator"])
    client.get("/runs", params={"sort": "id; DROP TABLE runs", "dir": "asc"})
    sql, _ = db.statements[-1]
    assert sql.endswith("ORDER BY created_at ASC LIMIT 100")
    assert "DROP" not in sql


def test_runs_filters_reach_the_query(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["operator"])
    client.get("/runs", params={"user": "alice", "status": "created"})
    sql, params = db.statements[-1]
    assert "user_id ILIKE" in sql and "status ILIKE" in sql
    assert "%alice%" in params and "%created%" in params


def test_audit_filters_and_sort(env: tuple[TestClient, FakeDB]) -> None:
    client, db = env
    _login(client, roles=["viewer"])
    client.get("/audit", params={"actor": "carol", "sort": "event", "dir": "asc"})
    sql, params = db.statements[-1]
    assert sql.endswith("ORDER BY event_type ASC LIMIT 100")
    assert "%carol%" in params


def test_login_redirects_with_pkce(env: tuple[TestClient, FakeDB]) -> None:
    client, _ = env
    response = client.get("/login", follow_redirects=False)
    assert response.status_code == 303
    location = response.headers["location"]
    assert "client_id=citadel-console" in location
    assert "code_challenge_method=S256" in location
    assert ui_app.LOGIN_COOKIE in response.cookies
