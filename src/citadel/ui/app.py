"""Approval console: five server-rendered views behind Keycloak SSO.

The console reads the ledger and the pending-approval rows; it never writes a
decision itself. A decision POST forwards to the API with the approver's own
access token, so server-side authorisation, the DLP check and the audit-before-
resume ordering all stay in one place.

The session cookie carries a Keycloak refresh token, so a review that sits past
the 300 s access-token lifespan can still submit; the refresh grant dies with the
SSO session, so revocation still ends the console session.

    KEYCLOAK_ISSUER           public issuer, used for the browser redirect
    KEYCLOAK_INTERNAL_ISSUER  issuer reachable from the container, for tokens
    KEYCLOAK_JWKS_URL         signing keys
    CITADEL_CONSOLE_CLIENT_ID public Keycloak client with PKCE
    CITADEL_CONSOLE_REDIRECT_URI
    CITADEL_CONSOLE_SESSION_KEY  HS256 key for the session cookie
    CITADEL_API_URL
    CITADEL_DB_DSN
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Any

import jwt
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from starlette.middleware.base import RequestResponseEndpoint

from citadel import __version__
from citadel.db import tenant_connection
from citadel.env import secret
from citadel.identity import IdentityError, KeycloakVerifier, Principal
from citadel.net import open_url
from citadel.workflows.types import APPROVAL_TTL

COOKIE = "citadel_console"
LOGIN_COOKIE = "citadel_login"
# The refresh token dies with the Keycloak SSO session (realm ssoSessionIdleTimeout),
# so the console session may outlive the 300 s access token but not revocation.
SESSION_TTL = 1800
REFRESH_SKEW = 60  # refresh this long before the access token expires
READ_ROLES = {"operator", "approver", "viewer", "admin", "auditor"}
RUN_COLUMNS = {
    "id": "id",
    "user": "user_id",
    "agent": "agent_id",
    "tier": "risk_tier",
    "status": "status",
    "created": "created_at",
}
AUDIT_COLUMNS = {"seq": "seq", "event": "event_type", "actor": "actor_id", "at": "created_at"}

STYLE = """
body{font:14px/1.5 system-ui,sans-serif;margin:2rem;color:#111}
nav{display:flex;gap:1rem;margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%}
th,td{border-bottom:1px solid #ddd;padding:.35rem .5rem;text-align:left;vertical-align:top}
pre{background:#f6f6f6;padding:.75rem;overflow:auto}
.error{color:#a00}
form.decide{display:grid;gap:.5rem;max-width:32rem;margin-top:1rem}
textarea{min-height:5rem}
th a{color:#06c;text-decoration:none;white-space:nowrap}
tr.filters th{padding-top:0}
tr.filters input{width:100%;box-sizing:border-box}
"""


class LoginRequired(Exception):
    """No usable session; the handler sends the browser to /login."""


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _page(
    title: str, body: str, principal: Principal | None = None, status_code: int = 200
) -> HTMLResponse:
    nav = ""
    who = ""
    if principal is not None:
        nav = (
            '<nav><a href="/runs">runs</a><a href="/approvals">approvals</a>'
            '<a href="/audit">audit</a><a href="/logout">logout</a></nav>'
        )
        who = f"{_esc(principal.user_id)} · {_esc(principal.tenant_id)}"
    return HTMLResponse(
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f"<title>{_esc(title)} · Citadel</title><style>{STYLE}</style></head>"
        f"<body>{nav}{body}<footer><hr><small>{who}</small></footer></body></html>",
        status_code=status_code,
    )


def _tbody(rows: list[list[str]]) -> str:
    return "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)


def _table(headers: tuple[str, ...], rows: list[list[str]]) -> str:
    head = "".join(f"<th>{_esc(item)}</th>" for item in headers)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{_tbody(rows)}</tbody></table>"


def _order(columns: dict[str, str], sort: str, direction: str, default: str) -> str:
    """Only a whitelisted column reaches SQL; an unknown sort falls back."""
    column = columns.get(sort, columns[default])
    return f"{column} {'DESC' if direction == 'desc' else 'ASC'}"


def _sort_header(label: str, key: str, sort: str, direction: str, filters: dict[str, str]) -> str:
    marker = ""
    if key == sort:
        marker = " ▲" if direction == "asc" else " ▼"
    next_direction = "desc" if key == sort and direction == "asc" else "asc"
    query = urllib.parse.urlencode({**filters, "sort": key, "dir": next_direction})
    return f'<th><a href="?{query}">{_esc(label)}{marker}</a></th>'


def _filter(name: str, value: str, placeholder: str = "") -> str:
    return (
        f'<th><input name="{_esc(name)}" value="{_esc(value)}"'
        f' placeholder="{_esc(placeholder)}"></th>'
    )


def _challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def _sign(payload: dict[str, Any], key: str) -> str:
    return jwt.encode(payload, key, algorithm="HS256")


def _decode(token: str, key: str) -> dict[str, Any] | None:
    try:
        claims = jwt.decode(token, key, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None
    return claims if isinstance(claims, dict) else None


def _is_uuid(value: str) -> bool:
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def create_app(
    *,
    verifier: KeycloakVerifier | None = None,
    dsn: str | None = None,
    api_url: str | None = None,
    issuer: str | None = None,
    internal_issuer: str | None = None,
    jwks_url: str | None = None,
    audience: str | None = None,
    client_id: str | None = None,
    redirect_uri: str | None = None,
    session_key: str | None = None,
) -> FastAPI:
    app = FastAPI(title="Citadel Approval Console", version=__version__)

    @app.middleware("http")
    async def _refuse_to_be_framed(
        request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        """No console page may be framed, and none may be cached.

        The decision form carries its own CSRF token, so framing
        `/approvals/<id>` in a decoy page turns a genuine approval into a click on
        something the approver never read. `SameSite=Lax` does not cover it: Lax
        separates sites, not ports, and the stack publishes the console beside
        Keycloak, Temporal and MLflow, so a page on any of them is same-site and
        gets the cookie. The cookie stays Lax regardless - the OIDC callback is a
        cross-site navigation, and Strict would drop the session on the way back.

        `Cache-Control: no-store` is part of the same control: a cached approval
        page is a stale CSRF token and a readable copy of the arguments.
        """
        response = await call_next(request)
        refreshed = getattr(request.state, "session_cookie", None)
        if refreshed is not None:
            response.set_cookie(
                COOKIE, _sign(refreshed, _key()), max_age=SESSION_TTL, httponly=True, samesite="lax"
            )
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = (
            "frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.exception_handler(LoginRequired)
    def _to_login(_: Request, __: LoginRequired) -> RedirectResponse:
        return RedirectResponse("/login", status_code=303)

    def _dsn() -> str:
        return dsn if dsn is not None else secret("CITADEL_DB_DSN")

    def _key() -> str:
        if session_key is not None:
            return session_key
        try:
            return secret("CITADEL_CONSOLE_SESSION_KEY")
        except KeyError as exc:
            # Unconfigured sessions are a denial, never an unsigned cookie.
            raise HTTPException(
                status_code=503, detail="CITADEL_CONSOLE_SESSION_KEY is not set"
            ) from exc

    def _verifier() -> KeycloakVerifier:
        if verifier is not None:
            return verifier
        public = issuer or os.environ.get(
            "KEYCLOAK_ISSUER", "http://localhost:18081/realms/citadel"
        )
        keys = jwt.PyJWKClient(
            jwks_url
            or os.environ.get(
                "KEYCLOAK_JWKS_URL",
                "http://keycloak:8080/realms/citadel/protocol/openid-connect/certs",
            ),
            cache_keys=True,
        )
        return KeycloakVerifier(public, audience or "citadel-agent", keys)

    def _issuer() -> str:
        return issuer or os.environ.get("KEYCLOAK_ISSUER", "http://localhost:18081/realms/citadel")

    def _internal() -> str:
        return internal_issuer or os.environ.get(
            "KEYCLOAK_INTERNAL_ISSUER", "http://keycloak:8080/realms/citadel"
        )

    def _client_id() -> str:
        return client_id or os.environ.get("CITADEL_CONSOLE_CLIENT_ID", "citadel-console")

    def _redirect() -> str:
        return redirect_uri or os.environ.get(
            "CITADEL_CONSOLE_REDIRECT_URI", "http://localhost:18001/callback"
        )

    def _api() -> str:
        return api_url or os.environ.get("CITADEL_API_URL", "http://api:8000")

    def _session(request: Request) -> tuple[dict[str, Any], Principal] | None:
        claims = _decode(request.cookies.get(COOKIE, ""), _key())
        if claims is None or int(claims.get("exp", 0)) < int(time.time()):
            return None
        if int(claims.get("access_exp", 0)) - int(time.time()) <= REFRESH_SKEW:
            refreshed = _refresh(claims)
            if refreshed is None:
                return None
            claims = refreshed
            request.state.session_cookie = refreshed
        principal = Principal(
            str(claims.get("sub", "")),
            str(claims.get("tenant", "")),
            frozenset(str(role) for role in claims.get("roles", [])),
        )
        if not principal.user_id or not principal.tenant_id:
            return None
        if not READ_ROLES & principal.roles:
            raise HTTPException(status_code=403, detail="no console role")
        return claims, principal

    def _require(request: Request) -> tuple[dict[str, Any], Principal]:
        session = _session(request)
        if session is None:
            raise LoginRequired
        return session

    async def _form(request: Request) -> dict[str, str]:
        raw = (await request.body()).decode()
        return {key: values[0] for key, values in urllib.parse.parse_qs(raw).items()}

    def _token_request(form: dict[str, str]) -> dict[str, Any]:
        request = urllib.request.Request(
            f"{_internal()}/protocol/openid-connect/token",
            data=urllib.parse.urlencode(form).encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        try:
            with open_url(request, timeout=10) as response:
                payload = json.loads(response.read())
        except urllib.error.HTTPError as exc:
            raise HTTPException(
                status_code=502, detail=f"token endpoint refused: {exc.code}"
            ) from exc
        except (urllib.error.URLError, OSError, ValueError) as exc:
            raise HTTPException(status_code=502, detail=f"token exchange failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=502, detail="token endpoint returned no payload")
        return payload

    def _exchange(code: str, verifier_value: str) -> dict[str, Any]:
        payload = _token_request(
            {
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": _redirect(),
                "client_id": _client_id(),
                "code_verifier": verifier_value,
            }
        )
        if not isinstance(payload.get("access_token"), str):
            raise HTTPException(status_code=502, detail="token endpoint returned no access token")
        return payload

    def _refresh(session: dict[str, Any]) -> dict[str, Any] | None:
        """Trade the refresh token for a new access token, before expiry.

        A refused grant means the SSO session is gone (revoked or idle past the
        realm timeout), so the console session ends with it: refresh is never a
        way to outlive revocation. The fresh token is re-verified, and the
        identity must not change under a rotation.
        """
        refresh_token = session.get("refresh_token")
        if not isinstance(refresh_token, str) or not refresh_token:
            return None
        try:
            payload = _token_request(
                {
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": _client_id(),
                }
            )
        except HTTPException:
            return None
        token = payload.get("access_token")
        if not isinstance(token, str):
            return None
        try:
            principal = _verifier().verify(token)
        except IdentityError:
            return None
        if principal.user_id != session.get("sub") or principal.tenant_id != session.get("tenant"):
            return None
        now = int(time.time())
        return {
            **session,
            "access_token": token,
            "refresh_token": payload.get("refresh_token") or refresh_token,
            "roles": sorted(principal.roles),
            "access_exp": now + int(payload.get("expires_in", 300)),
            "exp": now + SESSION_TTL,
        }

    def _decide_api(token: str, payload: dict[str, Any]) -> tuple[int, str]:
        request = urllib.request.Request(
            f"{_api()}/approvals",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"},
            method="POST",
        )
        try:
            with open_url(request, timeout=10) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def _pending_row(request_id: str, tenant: str) -> tuple[Any, ...] | None:
        if not _is_uuid(request_id):
            return None
        with tenant_connection(_dsn(), tenant) as conn:
            return conn.execute(
                "SELECT id, run_id, tool, agent_id, arguments, tier, rule_id,"
                " requested_by, status, created_at"
                " FROM approval_requests WHERE id = %s::uuid",
                (request_id,),
            ).fetchone()

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/")
    def index() -> Response:
        return RedirectResponse("/runs", status_code=303)

    @app.get("/login")
    def login() -> Response:
        state = secrets.token_urlsafe(24)
        verifier_value = secrets.token_urlsafe(48)
        cookie = _sign(
            {"state": state, "verifier": verifier_value, "exp": int(time.time()) + 300}, _key()
        )
        query = urllib.parse.urlencode(
            {
                "client_id": _client_id(),
                "redirect_uri": _redirect(),
                "response_type": "code",
                "scope": "openid",
                "state": state,
                "code_challenge": _challenge(verifier_value),
                "code_challenge_method": "S256",
            }
        )
        response = RedirectResponse(
            f"{_issuer()}/protocol/openid-connect/auth?{query}", status_code=303
        )
        response.set_cookie(LOGIN_COOKIE, cookie, max_age=300, httponly=True, samesite="lax")
        return response

    @app.get("/callback")
    def callback(request: Request, code: str = "", state: str = "") -> Response:
        pending = _decode(request.cookies.get(LOGIN_COOKIE, ""), _key())
        if not pending or not hmac.compare_digest(str(pending.get("state", "")), state):
            raise HTTPException(status_code=400, detail="login state did not match")
        if not code:
            raise HTTPException(status_code=400, detail="missing authorization code")
        payload = _exchange(code, str(pending.get("verifier", "")))
        token = str(payload["access_token"])
        try:
            principal = _verifier().verify(token)
        except IdentityError as exc:
            raise HTTPException(status_code=401, detail=f"token rejected: {exc}") from exc
        now = int(time.time())
        session = {
            "access_token": token,
            "refresh_token": payload.get("refresh_token"),
            "sub": principal.user_id,
            "tenant": principal.tenant_id,
            "roles": sorted(principal.roles),
            "csrf": secrets.token_urlsafe(24),
            "access_exp": now + int(payload.get("expires_in", 300)),
            "exp": now + SESSION_TTL,
        }
        response = RedirectResponse("/runs", status_code=303)
        response.set_cookie(
            COOKIE, _sign(session, _key()), max_age=SESSION_TTL, httponly=True, samesite="lax"
        )
        response.delete_cookie(LOGIN_COOKIE)
        return response

    @app.get("/logout")
    def logout() -> Response:
        response = RedirectResponse("/login", status_code=303)
        response.delete_cookie(COOKIE)
        return response

    @app.get("/runs")
    def runs(  # noqa: PLR0913 - one query parameter per column
        request: Request,
        sort: str = "created",
        dir: str = "desc",
        run: str = "",
        user: str = "",
        agent: str = "",
        tier: str = "",
        status: str = "",
    ) -> Response:
        _, principal = _require(request)
        filters = {"run": run, "user": user, "agent": agent, "tier": tier, "status": status}
        clauses = (
            "(%s = '' OR id::text ILIKE %s)",
            "(%s = '' OR user_id ILIKE %s)",
            "(%s = '' OR agent_id ILIKE %s)",
            "(%s = '' OR risk_tier ILIKE %s)",
            "(%s = '' OR status ILIKE %s)",
        )
        params: list[Any] = []
        for value in filters.values():
            params.extend([value, f"%{value}%"])
        order = _order(RUN_COLUMNS, sort, dir, "created")
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            rows = conn.execute(
                # `order` comes from the RUN_COLUMNS whitelist; every value is a
                # bound parameter.
                "SELECT id, user_id, agent_id, risk_tier, status, created_at"  # nosec B608
                " FROM runs WHERE " + " AND ".join(clauses) + f" ORDER BY {order} LIMIT 100",
                tuple(params),
            ).fetchall()
        headers = "".join(
            _sort_header(label, key, sort, dir, filters)
            for label, key in (
                ("Run", "id"),
                ("User", "user"),
                ("Agent", "agent"),
                ("Tier", "tier"),
                ("Status", "status"),
                ("Created", "created"),
            )
        )
        inputs = (
            _filter("run", run, "id")
            + _filter("user", user)
            + _filter("agent", agent)
            + _filter("tier", tier)
            + _filter("status", status)
            + "<th><button>Filter</button></th>"
        )
        body = (
            "<h1>Runs</h1>"
            '<form method="get" action="/runs">'
            f'<input type="hidden" name="sort" value="{_esc(sort)}">'
            f'<input type="hidden" name="dir" value="{_esc(dir)}">'
            f'<table><thead><tr>{headers}</tr><tr class="filters">{inputs}</tr></thead>'
            "<tbody>"
            + _tbody(
                [
                    [
                        f'<a href="/runs/{_esc(row[0])}">{_esc(str(row[0])[:8])}</a>',
                        _esc(row[1]),
                        _esc(row[2]),
                        _esc(row[3]),
                        _esc(row[4]),
                        _esc(row[5]),
                    ]
                    for row in rows
                ]
            )
            + "</tbody></table></form>"
        )
        return _page("Runs", body, principal)

    @app.get("/runs/{run_id}")
    def timeline(request: Request, run_id: str) -> Response:
        _, principal = _require(request)
        if not _is_uuid(run_id):
            raise HTTPException(status_code=404, detail="run not found")
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            events = conn.execute(
                "SELECT seq, event_type, actor_type, actor_id, payload, created_at"
                " FROM audit_events WHERE payload->>'run_id' = %s ORDER BY seq",
                (run_id,),
            ).fetchall()
            calls = conn.execute(
                "SELECT tool, status, created_at FROM tool_calls"
                " WHERE run_id = %s::uuid ORDER BY created_at",
                (run_id,),
            ).fetchall()
        body = f"<h1>Run {_esc(run_id[:8])}</h1><h2>Events</h2>" + _table(
            ("Seq", "Event", "Actor", "Payload", "At"),
            [
                [
                    _esc(row[0]),
                    _esc(row[1]),
                    _esc(f"{row[2]}:{row[3]}"),
                    f"<code>{_esc(json.dumps(row[4], sort_keys=True)[:300])}</code>",
                    _esc(row[5]),
                ]
                for row in events
            ],
        )
        body += "<h2>Tool calls</h2>" + _table(
            ("Tool", "Status", "At"),
            [[_esc(row[0]), _esc(row[1]), _esc(row[2])] for row in calls],
        )
        return _page(f"Run {run_id[:8]}", body, principal)

    @app.get("/approvals")
    def approvals(request: Request) -> Response:
        _, principal = _require(request)
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            # A pending row the workflow has already timed out is expired, not
            # pending: the workflow is the enforcer, this is display truth.
            conn.execute(
                "UPDATE approval_requests SET status = 'expired'"
                " WHERE status = 'pending' AND created_at < now() - (%s * interval '1 second')",
                (APPROVAL_TTL,),
            )
            rows = conn.execute(
                "SELECT id, run_id, tool, agent_id, tier, requested_by, created_at"
                " FROM approval_requests WHERE status = 'pending' ORDER BY created_at"
            ).fetchall()
        body = "<h1>Pending approvals</h1>" + _table(
            ("Request", "Run", "Tool", "Agent", "Tier", "Requested by", "Created"),
            [
                [
                    f'<a href="/approvals/{_esc(row[0])}">{_esc(str(row[0])[:8])}</a>',
                    _esc(str(row[1])[:8]),
                    _esc(row[2]),
                    _esc(row[3]),
                    _esc(row[4]),
                    _esc(row[5]),
                    _esc(row[6]),
                ]
                for row in rows
            ],
        )
        return _page("Approvals", body, principal)

    @app.get("/approvals/{request_id}")
    def approval_detail(request: Request, request_id: str) -> Response:
        session, principal = _require(request)
        row = _pending_row(request_id, principal.tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail="approval not found")
        (
            _id,
            run_id,
            tool,
            agent_id,
            arguments,
            tier,
            rule_id,
            requested_by,
            status,
            created,
        ) = row
        can_decide = (
            status == "pending"
            and "approver" in principal.roles
            and str(requested_by) != principal.user_id
        )
        body = (
            f"<h1>Approval {_esc(str(request_id)[:8])}</h1>"
            + _table(
                ("Field", "Value"),
                [
                    ["Tool", _esc(tool)],
                    ["Run", f'<a href="/runs/{_esc(run_id)}">{_esc(str(run_id)[:8])}</a>'],
                    ["Agent", _esc(agent_id)],
                    ["Tier", _esc(tier)],
                    ["Policy rule", _esc(rule_id)],
                    ["Requested by", _esc(requested_by)],
                    ["Status", _esc(status)],
                    ["Created", _esc(created)],
                    ["Expires", _esc(f"{APPROVAL_TTL // 60} minutes after creation")],
                ],
            )
            + "<h2>Arguments</h2>"
            + f"<pre>{_esc(json.dumps(arguments, indent=2, sort_keys=True))}</pre>"
        )
        if can_decide:
            csrf = _esc(session.get("csrf", ""))
            body += (
                f'<form class="decide" method="post" action="/approvals/{_esc(request_id)}/decide">'
                f'<input type="hidden" name="csrf" value="{csrf}">'
                '<label>Reason (required)<textarea name="reason" required></textarea></label>'
                '<button name="decision" value="approve">Approve</button>'
                '<button name="decision" value="deny">Deny</button>'
                "</form>"
            )
        elif str(requested_by) == principal.user_id:
            body += '<p class="error">You cannot approve your own request.</p>'
        return _page(f"Approval {str(request_id)[:8]}", body, principal)

    @app.post("/approvals/{request_id}/decide")
    async def decide(request: Request, request_id: str) -> Response:
        session, principal = _require(request)
        form = await _form(request)
        if not hmac.compare_digest(form.get("csrf", ""), str(session.get("csrf", ""))):
            raise HTTPException(status_code=403, detail="CSRF token did not match")
        if "approver" not in principal.roles:
            raise HTTPException(status_code=403, detail="approver role required")
        decision = form.get("decision", "")
        if decision not in {"approve", "deny"}:
            raise HTTPException(status_code=400, detail="decision must be approve or deny")
        reason = form.get("reason", "").strip()
        if not reason:
            raise HTTPException(status_code=400, detail="a reason is required")
        row = _pending_row(request_id, principal.tenant_id)
        if row is None:
            raise HTTPException(status_code=404, detail="approval not found")
        if str(row[7]) == principal.user_id:
            raise HTTPException(status_code=403, detail="cannot approve your own run")
        if str(row[8]) != "pending":
            raise HTTPException(status_code=409, detail=f"approval is already {row[8]}")
        status, detail = _decide_api(
            str(session.get("access_token", "")),
            {
                "run_id": str(row[1]),
                "tool": str(row[2]),
                "agent_id": str(row[3]),
                "arguments": row[4],
                "approved": decision == "approve",
                "reason": reason,
            },
        )
        if status != 200:
            body = (
                f'<h1>Decision refused</h1><p class="error">API returned {_esc(status)}</p>'
                f"<pre>{_esc(detail[:500])}</pre>"
            )
            return _page("Decision refused", body, principal, status_code=502)
        return RedirectResponse("/approvals", status_code=303)

    @app.get("/audit")
    def audit(
        request: Request,
        sort: str = "seq",
        dir: str = "desc",
        event_type: str = "",
        actor: str = "",
        q: str = "",
    ) -> Response:
        _, principal = _require(request)
        event_type = event_type.strip()
        actor = actor.strip()
        q = q.strip()
        filters = {"event_type": event_type, "actor": actor, "q": q}
        order = _order(AUDIT_COLUMNS, sort, dir, "seq")
        with tenant_connection(_dsn(), principal.tenant_id) as conn:
            rows = conn.execute(
                # `order` comes from the AUDIT_COLUMNS whitelist; every value is a
                # bound parameter.
                "SELECT seq, event_type, actor_type, actor_id, payload, created_at"  # nosec B608
                " FROM audit_events"
                " WHERE (%s = '' OR event_type = %s)"
                " AND (%s = '' OR actor_id ILIKE %s)"
                " AND (%s = '' OR payload::text ILIKE %s)"
                f" ORDER BY {order} LIMIT 100",
                (event_type, event_type, actor, f"%{actor}%", q, f"%{q}%"),
            ).fetchall()
        headers = (
            _sort_header("Seq", "seq", sort, dir, filters)
            + _sort_header("Event", "event", sort, dir, filters)
            + _sort_header("Actor", "actor", sort, dir, filters)
            + "<th>Payload</th>"
            + _sort_header("At", "at", sort, dir, filters)
        )
        inputs = (
            _filter("event_type", event_type)
            + _filter("actor", actor)
            + _filter("q", q, "payload contains")
            + "<th></th><th><button>Filter</button></th>"
        )
        body = (
            "<h1>Audit</h1>"
            '<form method="get" action="/audit">'
            f'<input type="hidden" name="sort" value="{_esc(sort)}">'
            f'<input type="hidden" name="dir" value="{_esc(dir)}">'
            f'<table><thead><tr>{headers}</tr><tr class="filters">{inputs}</tr></thead>'
            "<tbody>"
            + _tbody(
                [
                    [
                        _esc(row[0]),
                        _esc(row[1]),
                        _esc(f"{row[2]}:{row[3]}"),
                        f"<code>{_esc(json.dumps(row[4], sort_keys=True)[:300])}</code>",
                        _esc(row[5]),
                    ]
                    for row in rows
                ]
            )
            + "</tbody></table></form>"
        )
        return _page("Audit", body, principal)

    return app


app = create_app()
