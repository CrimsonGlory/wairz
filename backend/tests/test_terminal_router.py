"""WebSocket auth tests for ``app.routers.terminal``.

Phase 1 of audit-test-coverage-routers-services-2026-05-04 — the
terminal router (477 LOC) was previously untested at the WebSocket
layer.  The most load-bearing invariant is the **Rule #34b
``appendApiKey`` regression contract**: browser-issued WebSocket
connections cannot send ``X-API-Key`` headers (kernel-controlled
``Sec-WebSocket-*`` slots only), so the auth middleware MUST also
honour the ``?api_key=<key>`` query parameter.  If the middleware
were ever simplified to "header-only", every browser terminal /
TCP-proxy session would break with a 4401 close — and the front-end
``appendApiKey`` discipline (frontend/src/api/client.ts:27,
terminal.ts:6, emulation.ts:93/215/314, hardwareFirmware.ts:240)
would silently lose its anchor.

Three layers of coverage:

1. **APIKeyASGIMiddleware unit tests** — direct ASGI-scope assertions
   on the auth middleware so the contract is locked in independently
   of any router. Tests both ``http`` and ``websocket`` scope; covers
   header-path, query-string-path, missing-key, wrong-key, and the
   ``settings.api_key`` falsy → pass-through ergonomic.

2. **WebSocket-endpoint smoke** — uses ``starlette.testclient`` (the
   only async-app WebSocket transport that ships with FastAPI/Starlette)
   to drive ``/api/v1/projects/{pid}/terminal/ws`` and confirms the
   auth gate fires (4401) when the key is missing AND the project /
   firmware lookup fires (4004 with the right error message) when the
   key passes.

3. **Rule #35b live-canary** — wraps the full path against a real
   SQLite session: seeds Project + Firmware rows, opens a WebSocket
   with the right ``?api_key=...``, sees the handler look up the
   firmware, and verifies the close-frame message carries the
   "Extracted firmware directory not found on disk" error
   (proving the DB row was actually read end-to-end, not mocked).
"""
from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest
from sqlalchemy import select
from starlette.testclient import TestClient

from app.main import app
from app.middleware.asgi_auth import APIKeyASGIMiddleware
from app.models.firmware import Firmware
from app.models.project import Project

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Layer 1: APIKeyASGIMiddleware ASGI-scope unit tests
# ---------------------------------------------------------------------------

VALID_KEY = "rule-34b-canary-key"


@pytest.fixture
def auth_settings(monkeypatch):
    """Force ``settings.api_key`` to a known value for the test scope.

    The middleware imports ``get_settings`` at module scope from
    ``app.config``, so we patch the symbol the middleware actually
    resolves at call time.
    """
    fake_settings = MagicMock()
    fake_settings.api_key = VALID_KEY
    from app.middleware import asgi_auth as _auth_mod
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)
    return fake_settings


async def _drive_middleware(scope, valid_key=VALID_KEY):
    """Run the middleware against a synthesized scope and capture sent
    messages. Returns ``(passed_through: bool, sent: list[dict])``."""
    sent: list[dict] = []
    passed_through = []

    async def downstream(s, r, snd):
        passed_through.append(True)

    async def send(message):
        sent.append(message)

    async def receive():
        return {"type": "lifespan.startup"}

    middleware = APIKeyASGIMiddleware(downstream)
    await middleware(scope, receive, send)
    return bool(passed_through), sent


@pytest.mark.asyncio
async def test_websocket_query_string_api_key_passes_through(auth_settings):
    """Rule #34b core: ``?api_key=<key>`` query param MUST authenticate.

    This is the only path that works for browser-issued WebSockets.
    Removing it would break every WebSocket terminal/TCP-proxy session
    even though the front-end is correctly using ``appendApiKey``.
    """
    scope = {
        "type": "websocket",
        "path": "/api/v1/projects/x/terminal/ws",
        "query_string": f"api_key={VALID_KEY}".encode("latin-1"),
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert passed, (
        "Rule #34b regression: ?api_key=<correct> in WebSocket query string "
        "did not authenticate — APIKeyASGIMiddleware._check_key "
        "(asgi_auth.py:103-110) must read the api_key query param for "
        "WebSocket scope."
    )
    assert sent == [], "no close frame should be sent on the success path"


@pytest.mark.asyncio
async def test_websocket_missing_api_key_closes_4401(auth_settings):
    """No api_key in query string AND no X-API-Key header → 4401 close.

    The middleware accepts the handshake first then sends close
    (asgi_auth.py:128-140) so the browser surfaces ``CloseEvent.code=4401``
    on ``onclose`` rather than collapsing to HTTP 403 with code=1006.
    """
    scope = {
        "type": "websocket",
        "path": "/api/v1/projects/x/terminal/ws",
        "query_string": b"",
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert not passed, "missing-key WebSocket must NOT pass through"
    assert len(sent) == 2
    assert sent[0]["type"] == "websocket.accept"
    assert sent[1]["type"] == "websocket.close"
    assert sent[1]["code"] == 4401
    assert sent[1]["reason"] == "unauthenticated"


@pytest.mark.asyncio
async def test_websocket_wrong_api_key_closes_4401(auth_settings):
    """Constant-time compare must reject anything other than the configured key."""
    scope = {
        "type": "websocket",
        "path": "/api/v1/projects/x/terminal/ws",
        "query_string": b"api_key=not-the-real-key",
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert not passed
    assert sent[1]["code"] == 4401


@pytest.mark.asyncio
async def test_websocket_x_api_key_header_passes_through(auth_settings):
    """``X-API-Key`` header is the second-class path (used by tests + CLI,
    not by browsers — but it MUST still authenticate so backend-to-backend
    callers don't regress)."""
    scope = {
        "type": "websocket",
        "path": "/api/v1/projects/x/terminal/ws",
        "query_string": b"",
        "headers": [(b"x-api-key", VALID_KEY.encode("latin-1"))],
    }
    passed, sent = await _drive_middleware(scope)
    assert passed
    assert sent == []


@pytest.mark.asyncio
async def test_settings_api_key_empty_disables_middleware(monkeypatch):
    """``settings.api_key=""`` → middleware passes everything through.

    Preserves the historical "API_KEY unset → open backend" dev
    ergonomic (asgi_auth.py:56-61). Without this, every fresh
    checkout would 401 on every request.
    """
    fake_settings = MagicMock()
    fake_settings.api_key = ""
    from app.middleware import asgi_auth as _auth_mod
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)

    scope = {
        "type": "websocket",
        "path": "/api/v1/projects/x/terminal/ws",
        "query_string": b"",  # NO key but auth disabled
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert passed
    assert sent == []


@pytest.mark.asyncio
async def test_http_query_string_api_key_passes_through(auth_settings):
    """HTTP scope also accepts ``?api_key=`` — kept symmetric with WebSocket
    so the same middleware code path covers both transports."""
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/projects/x/firmware",
        "query_string": f"api_key={VALID_KEY}".encode("latin-1"),
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert passed
    assert sent == []


@pytest.mark.asyncio
async def test_http_options_passes_without_key(auth_settings):
    """CORS preflight (OPTIONS) bypasses the gate; browsers never send
    custom headers on preflight, so gating it would break every
    cross-origin call (asgi_auth.py:67-71)."""
    scope = {
        "type": "http",
        "method": "OPTIONS",
        "path": "/api/v1/projects/x/firmware",
        "query_string": b"",
        "headers": [],
    }
    passed, sent = await _drive_middleware(scope)
    assert passed


# ---------------------------------------------------------------------------
# Layer 2: WebSocket-endpoint smoke via starlette TestClient
# ---------------------------------------------------------------------------

@pytest.fixture
def auth_set_app(monkeypatch):
    """Configure the live ``app`` so the auth middleware enforces VALID_KEY."""
    fake_settings = MagicMock()
    fake_settings.api_key = VALID_KEY
    from app.middleware import asgi_auth as _auth_mod
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)
    yield


def test_websocket_terminal_rejects_missing_key(auth_set_app):
    """End-to-end: WebSocket /ws without ``?api_key=`` → close code 4401.

    Uses Starlette's TestClient — the only WebSocket-capable transport
    that ships with FastAPI/Starlette and works against an async app.

    NB: ``TestClient(app)`` without the ``with`` context skips the FastAPI
    lifespan. The lifespan in ``main.py:30-143`` does production-DB
    writes (orphan-row reaping) that race against an in-test session
    fixture; for an auth-only test the lifespan adds no signal and would
    just inject "another operation is in progress" failures from
    concurrent asyncpg calls on the production pool.
    """
    pid = uuid.uuid4()
    client = TestClient(app)  # no `with` → no lifespan
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
            f"/api/v1/projects/{pid}/terminal/ws"
        ) as ws:
            ws.receive_json()
    assert exc_info.value.code == 4401, (
        f"expected close code 4401 for missing api_key, "
        f"got {exc_info.value.code}"
    )


def test_websocket_terminal_accepts_query_param_key(auth_set_app):
    """End-to-end Rule #34b: ``?api_key=<correct>`` → handshake succeeds.

    The handler then closes 4004 because no firmware is uploaded for
    the test project_id — that close code is the success signal here:
    we got past the 4401 auth gate and into the project-not-found
    branch (terminal.py:101-103).
    """
    pid = uuid.uuid4()
    client = TestClient(app)  # no `with` → no lifespan (see comment above)
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect(
            f"/api/v1/projects/{pid}/terminal/ws?api_key={VALID_KEY}"
        ) as ws:
            # Server sends {"type": "error", "data": "Project not found"}
            msg = ws.receive_json()
            assert msg.get("type") == "error"
            assert "Project not found" in msg.get("data", "")
            ws.receive_json()  # triggers the close frame

    # 4004 = the handler's project-not-found code; NOT 4401 (auth).
    assert exc_info.value.code == 4004, (
        f"Rule #34b regression: ?api_key=<correct> did not pass the "
        f"auth gate — got close code {exc_info.value.code}, expected "
        f"4004 (handler-level project-not-found)."
    )


# ---------------------------------------------------------------------------
# Layer 3: Rule #35b LIVE-CANARY — real ORM round-trip + SELECT
# ---------------------------------------------------------------------------

class TestTerminalReadsFirmwareFromDbLiveCanary:
    """Rule #35b: the WebSocket handler's project + firmware lookup must
    actually consult the DB, not a mocked dependency. We seed real rows in
    a SQLite session, override ``async_session_factory`` to point at it,
    open the WebSocket, and observe the handler's "Extracted firmware
    directory not found on disk" branch fire — proving the row WAS read.
    """

    @pytest.mark.asyncio
    async def test_terminal_reads_firmware_row_via_live_session(
        self, auth_set_app,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="rule-34b-canary", status="ready")
            db.add(project)
            await db.flush()

            # Use a path that will NOT exist on disk so the handler
            # reaches its "Extracted firmware directory not found on disk"
            # close branch — that branch only fires when the SELECT
            # actually returned a firmware row, so it doubles as a
            # proof-of-real-DB-access.
            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="e" * 64,
                extracted_path="/tmp/this-path-deliberately-does-not-exist-rule-35b",
            )
            db.add(firmware)
            await db.flush()
            await db.commit()  # commit so the handler's session sees it

            # The terminal router uses ``async_session_factory()`` directly
            # (terminal.py:97), not Depends(get_db) — so we replace the
            # factory with one that yields our live SQLite session.
            from contextlib import asynccontextmanager
            from app.routers import terminal as terminal_mod

            @asynccontextmanager
            async def _fake_factory():
                yield db

            original_factory = terminal_mod.async_session_factory
            terminal_mod.async_session_factory = lambda: _fake_factory()
            try:
                client = TestClient(app)  # no lifespan; see test above
                from starlette.websockets import WebSocketDisconnect
                with pytest.raises(WebSocketDisconnect) as exc_info:
                    with client.websocket_connect(
                        f"/api/v1/projects/{pid}/terminal/ws?api_key={VALID_KEY}"
                    ) as ws:
                        msg = ws.receive_json()
                        # The handler sends an error JSON before
                        # closing (terminal.py:119-121).
                        assert msg.get("type") == "error"
                        assert "Extracted firmware" in msg.get("data", "")
                        ws.receive_json()  # close

                # 4004 = handler-defined "resource not found" close.
                assert exc_info.value.code == 4004
            finally:
                terminal_mod.async_session_factory = original_factory

            # Real SELECT — confirm the seeded row is still in the DB
            # (the handler is read-only; this just verifies the round-trip
            # contract and proves the live canary is exercising the same
            # row the handler saw).
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.project_id == pid)
                )
            ).scalar_one()
            assert row.extracted_path.endswith(
                "this-path-deliberately-does-not-exist-rule-35b"
            )
