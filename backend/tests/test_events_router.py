"""HTTP-layer tests for ``app.routers.events``.

Phase 2 Wave 4 file 5 of 5 — backfills router-level tests for
backend/app/routers/events.py (144 LOC, 1 SSE endpoint) per intake
audit-test-coverage-routers-services-2026-05-04.

Single SSE endpoint that streams real-time project events from Redis
pub/sub. Tests focus on the value-flow contract for channel selection
(``types`` query parameter → Redis channel list) — the F-A-06-shape
risk here is a regression that allows arbitrary types through (cross-
project subscription leak) or silently drops valid types.

Coverage targets:

* ``VALID_EVENT_TYPES`` constant pin — the security-relevant set:
  unpacking, emulation, fuzzing, device, assessment, vulhunt.
* ``channel_name`` shape — canonical ``wairz:{project_id}:{event_type}``.
* SSE response shape — text/event-stream Content-Type + nginx-disable
  header + cache-control.
* Channel selection — verifies the SUBSCRIBE call hits exactly the
  right channels for each ``types`` query parameter combination.
* Bogus types in query → falls back to ALL valid types (defense in depth).

Per Rule #30: ``event_service`` is module-imported at top of events.py
(line 18). Tests patch it at the consumer-module path.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.rate_limit import limiter
from app.routers.events import (
    KEEPALIVE_INTERVAL,
    VALID_EVENT_TYPES,
)
from app.services.event_service import EventService


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    from app.middleware import asgi_auth as _auth_mod
    fake = MagicMock()
    fake.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake)


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    prior = limiter.enabled
    limiter.enabled = False
    limiter.reset()
    try:
        yield
    finally:
        limiter.enabled = prior


@pytest.fixture(autouse=True)
def _cleanup_overrides():
    yield
    app.dependency_overrides.clear()


@pytest.fixture
async def client():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test",
    ) as c:
        yield c


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


# ===========================================================================
# Constants pin
# ===========================================================================


class TestValidEventTypes:
    """Pin the VALID_EVENT_TYPES set so a regression that adds an
    arbitrary type (which would let the SSE endpoint subscribe to a
    Redis channel we didn't intend) is caught at CI time."""

    def test_set_contents_match_canonical(self):
        assert VALID_EVENT_TYPES == {
            "unpacking", "emulation", "fuzzing",
            "device", "assessment", "vulhunt",
        }

    def test_keepalive_interval_is_15s(self):
        # 15 s matches nginx's `proxy_read_timeout` default to keep
        # long-lived SSE connections from being torn down by reverse proxies.
        assert KEEPALIVE_INTERVAL == 15


# ===========================================================================
# channel_name shape
# ===========================================================================


class TestChannelName:
    def test_canonical_format_is_wairz_project_type(self):
        ch = EventService.channel_name("abc-123", "unpacking")
        assert ch == "wairz:abc-123:unpacking"


# ===========================================================================
# SSE endpoint — channel selection + response shape
# ===========================================================================


class _FakePubsub:
    """Minimal async pubsub mock that records subscribe/unsubscribe calls
    and yields one message then disconnects."""

    def __init__(self):
        self.subscribed_channels: tuple[str, ...] | None = None
        self.unsubscribed = False
        self.closed = False
        self._messages_yielded = 0

    async def subscribe(self, *channels):
        self.subscribed_channels = channels

    async def unsubscribe(self, *_channels):
        self.unsubscribed = True

    async def aclose(self):
        self.closed = True

    async def get_message(self, ignore_subscribe_messages=True, timeout=None):
        # Yield exactly one real message then signal disconnect via timeout
        # (None) — the router treats None as "send keepalive and continue".
        if self._messages_yielded == 0:
            self._messages_yielded += 1
            return {
                "type": "message",
                "channel": b"wairz:test:unpacking",
                "data": json.dumps({
                    "type": "unpacking",
                    "status": "complete",
                    "progress": 1.0,
                }),
            }
        # Subsequent calls return None — the router's keepalive path.
        return None


class _FakeEventService:
    def __init__(self):
        self.redis = MagicMock()
        self._pubsub = _FakePubsub()
        self.redis.pubsub = MagicMock(return_value=self._pubsub)

    @staticmethod
    def channel_name(project_id: str, event_type: str) -> str:
        return f"wairz:{project_id}:{event_type}"


class TestStreamEvents:
    @pytest.mark.asyncio
    async def test_invalid_types_fall_back_to_all_valid(
        self, client, project_id, monkeypatch,
    ):
        """Query says ``types=bogus``; intersection with VALID_EVENT_TYPES
        is empty → router falls back to ALL valid types. The SUBSCRIBE
        call must hit one channel per valid type."""
        fake_svc = _FakeEventService()

        # Disconnect immediately after the first message yields so the
        # generator returns and the request completes (otherwise the
        # endpoint streams forever).
        async def fake_disconnect():
            return True
        monkeypatch.setattr(
            "starlette.requests.Request.is_disconnected", fake_disconnect,
        )

        with patch("app.routers.events.event_service", fake_svc):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/events",
                params={"types": "bogus,bogus2"},
            )

        # All 6 valid types subscribed (sorted order — events.py:68).
        assert fake_svc._pubsub.subscribed_channels is not None
        subscribed = set(fake_svc._pubsub.subscribed_channels)
        assert len(subscribed) == 6
        for et in VALID_EVENT_TYPES:
            assert f"wairz:{project_id}:{et}" in subscribed

    @pytest.mark.asyncio
    async def test_valid_types_subset_subscribes_only_those(
        self, client, project_id, monkeypatch,
    ):
        """Query ``types=unpacking,fuzzing`` → only those two channels."""
        fake_svc = _FakeEventService()

        async def fake_disconnect():
            return True
        monkeypatch.setattr(
            "starlette.requests.Request.is_disconnected", fake_disconnect,
        )

        with patch("app.routers.events.event_service", fake_svc):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/events",
                params={"types": "unpacking,fuzzing"},
            )

        subscribed = set(fake_svc._pubsub.subscribed_channels or ())
        assert subscribed == {
            f"wairz:{project_id}:unpacking",
            f"wairz:{project_id}:fuzzing",
        }, (
            "Rule #35b shape: only the requested-AND-valid types must "
            "be subscribed — never bleed extras through"
        )

    @pytest.mark.asyncio
    async def test_response_has_sse_headers(
        self, client, project_id, monkeypatch,
    ):
        fake_svc = _FakeEventService()

        async def fake_disconnect():
            return True
        monkeypatch.setattr(
            "starlette.requests.Request.is_disconnected", fake_disconnect,
        )

        with patch("app.routers.events.event_service", fake_svc):
            resp = await client.get(
                f"/api/v1/projects/{project_id}/events",
            )

        assert resp.status_code == 200
        # Content-Type is text/event-stream (with charset).
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers.get("cache-control") == "no-cache"
        # Nginx buffering disabled — load-balancer-friendly SSE.
        assert resp.headers.get("x-accel-buffering") == "no"

    @pytest.mark.asyncio
    async def test_pubsub_unsubscribes_and_closes_on_disconnect(
        self, client, project_id, monkeypatch,
    ):
        """Resource cleanup contract: pubsub.unsubscribe + aclose must
        run when the generator exits, even via early disconnect."""
        fake_svc = _FakeEventService()

        async def fake_disconnect():
            return True
        monkeypatch.setattr(
            "starlette.requests.Request.is_disconnected", fake_disconnect,
        )

        with patch("app.routers.events.event_service", fake_svc):
            await client.get(
                f"/api/v1/projects/{project_id}/events",
            )

        assert fake_svc._pubsub.unsubscribed is True, (
            "router must unsubscribe from Redis channels on client disconnect"
        )
        assert fake_svc._pubsub.closed is True, (
            "router must close the pubsub connection on client disconnect"
        )
