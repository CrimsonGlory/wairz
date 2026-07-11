"""Tests for the MCP Streamable HTTP transport + per-session state (Phase 5).

Covers:
  * 5b — each MCP session gets its own ProjectState (no cross-session bleed),
    while the stdio shared-state path keeps one instance.
  * 5c — the HTTP endpoint requires a valid bearer token when auth is enabled,
    and is open (no 401) when auth is disabled.

The per-session tests use the SDK's in-memory client/server transport so a real
ServerSession is created per connection — no network, no database (the tools we
call resolve against empty state).
"""

import types

import pytest
from starlette.testclient import TestClient

from app.auth import oidc
from app.auth.oidc import AuthError
from app.mcp_server import (
    ProjectState,
    build_http_app,
    build_mcp_server,
    _make_session_factory,
)


def _server(shared_state=None):
    # host_storage_root=None → no path translation; session_factory is never hit
    # by the no-project tools we exercise here.
    return build_mcp_server(
        _make_session_factory(), None, shared_state=shared_state
    )


# --- 5b: per-session state isolation ----------------------------------------


async def _call_get_project_info(client):
    result = await client.call_tool("get_project_info", {})
    return result.content[0].text


async def test_http_mode_isolates_state_per_session():
    """Two concurrent sessions on one server get distinct ProjectState objects."""
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    server = _server(shared_state=None)  # HTTP-style: per-session state

    async with connect(server) as client_a, connect(server) as client_b:
        # Touch a tool on each session so its ProjectState is materialized.
        text_a = await _call_get_project_info(client_a)
        text_b = await _call_get_project_info(client_b)
        assert "No project is active" in text_a
        assert "No project is active" in text_b

        # While both sessions are live, each holds its own ProjectState.
        states = list(server._wairz_session_states.values())
        assert len(states) == 2, f"expected 2 per-session states, got {len(states)}"
        assert states[0] is not states[1]
        assert all(isinstance(s, ProjectState) for s in states)

    # After both sessions close, the WeakKeyDictionary drops their entries —
    # no per-session leak across a long-lived server.
    import gc

    gc.collect()
    assert len(server._wairz_session_states) == 0


async def test_stdio_mode_shares_one_state():
    """stdio/shared_state mode never populates the per-session map."""
    from mcp.shared.memory import create_connected_server_and_client_session as connect

    shared = ProjectState()
    server = _server(shared_state=shared)

    async with connect(server) as client:
        assert "No project is active" in await _call_get_project_info(client)

    # Shared mode short-circuits before the per-session map is ever touched.
    assert len(server._wairz_session_states) == 0


# --- 5c: bearer-token auth on the HTTP endpoint -----------------------------


def _good_verifier():
    return types.SimpleNamespace(
        issuer="https://issuer.example.com",
        verify=lambda t: {"sub": "u"} if t == "good"
        else (_ for _ in ()).throw(AuthError("bad")),
    )


def test_http_rejects_missing_token(monkeypatch):
    monkeypatch.setattr(oidc, "get_verifier", _good_verifier)
    with TestClient(build_http_app()) as client:
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert r.status_code == 401
        assert "bearer" in r.json()["detail"].lower()


def test_http_rejects_invalid_token(monkeypatch):
    monkeypatch.setattr(oidc, "get_verifier", _good_verifier)
    with TestClient(build_http_app()) as client:
        r = client.post(
            "/mcp",
            headers={"Authorization": "Bearer bad"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert r.status_code == 401


def test_http_valid_token_passes_auth_gate(monkeypatch):
    # A valid token gets past the auth gate into the MCP transport. The bare
    # request then fails transport validation (no session/Accept negotiation),
    # but crucially NOT with 401 — proving the gate opened.
    monkeypatch.setattr(oidc, "get_verifier", _good_verifier)
    with TestClient(build_http_app()) as client:
        r = client.post(
            "/mcp",
            headers={"Authorization": "Bearer good"},
            json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
        )
        assert r.status_code != 401


def test_http_open_when_auth_disabled(monkeypatch):
    # auth disabled → verifier None → no 401 (transport may still 4xx the bare
    # request, but never on auth grounds).
    monkeypatch.setattr(oidc, "get_verifier", lambda: None)
    with TestClient(build_http_app()) as client:
        r = client.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
        assert r.status_code != 401


def test_health_endpoint_unauthenticated(monkeypatch):
    # The ALB target-group health check must get a 200 even with auth enabled —
    # /healthz is outside the auth gate.
    monkeypatch.setattr(oidc, "get_verifier", _good_verifier)
    with TestClient(build_http_app()) as client:
        r = client.get("/healthz")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"
