"""HTTP-layer tests for ``app.routers.health``.

Phase 2 Wave 5 file 2 of 6 — backfills router-level tests for
backend/app/routers/health.py (119 LOC, 3 probes) per intake
audit-test-coverage-routers-services-2026-05-04.

Three probes: shallow ``/health`` (process-up only, no deps),
deep ``/health/deep`` (DB + Redis + Docker + storage), and
``/ready`` (k8s-canonical alias for /health/deep). All are
auth-exempt via app.middleware.asgi_auth._EXEMPT_HTTP_PATHS.

Coverage targets:

* ``GET /health``     — shallow returns 200 with status='ok'.
* ``GET /health/deep`` — 200 when all 4 checks pass; 503 with
  per-component status when ANY fails.
* ``GET /ready``      — same checks as deep, same response shape.
* Both deep probes share ``_run_deep_checks`` — verify the body
  carries each check's ok/error fields (the F-A-06-shape contract:
  a regression that drops one check key from the response would
  silently break orchestrator probes).

Per Rule #30: ``async_session_factory``, ``event_service``,
``get_docker_client`` are all module-imported at top of health.py
(lines 30-32). Tests patch them at the consumer-module path.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.rate_limit import limiter


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


# ===========================================================================
# Shallow /health — no deps
# ===========================================================================


class TestShallowHealth:
    @pytest.mark.asyncio
    async def test_returns_200_with_status_ok(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "ok"
        assert "version" in body
        assert "storage_root_exists" in body


# ===========================================================================
# Deep /health/deep — all dependencies must pass for 200
# ===========================================================================


def _build_async_session_factory_mock():
    """Async-context-manager mock that yields a session with .execute()."""
    db = AsyncMock()
    db.execute = AsyncMock(return_value=MagicMock())

    class _SessionFactory:
        def __call__(self):
            return self

        async def __aenter__(self):
            return db

        async def __aexit__(self, *_a):
            return False

    return _SessionFactory(), db


class TestDeepHealthAllPassing:
    @pytest.mark.asyncio
    async def test_all_checks_passing_returns_200(self, client):
        factory, _ = _build_async_session_factory_mock()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = MagicMock()
        fake_event_svc._redis.ping = AsyncMock()

        fake_docker = MagicMock()
        fake_docker.containers.list = MagicMock(return_value=[])

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            return_value=fake_docker,
        ), patch(
            "os.path.isdir", return_value=True,
        ):
            resp = await client.get("/health/deep")

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["status"] == "ok"
        assert body["checks"]["db"]["ok"] is True
        assert body["checks"]["redis"]["ok"] is True
        assert body["checks"]["docker"]["ok"] is True
        assert body["checks"]["storage"]["ok"] is True


class TestDeepHealthDegradedStates:
    @pytest.mark.asyncio
    async def test_db_failure_yields_503(self, client):
        # Async-context-manager that raises on db.execute().
        db = AsyncMock()
        db.execute = AsyncMock(side_effect=Exception("connection refused"))

        class _SessionFactory:
            def __call__(self):
                return self

            async def __aenter__(self):
                return db

            async def __aexit__(self, *_a):
                return False

        factory = _SessionFactory()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = MagicMock()
        fake_event_svc._redis.ping = AsyncMock()
        fake_docker = MagicMock()
        fake_docker.containers.list = MagicMock(return_value=[])

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            return_value=fake_docker,
        ), patch(
            "os.path.isdir", return_value=True,
        ):
            resp = await client.get("/health/deep")

        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "degraded"
        assert body["checks"]["db"]["ok"] is False
        assert "connection refused" in body["checks"]["db"]["error"]
        # Other checks still report ok.
        assert body["checks"]["redis"]["ok"] is True
        assert body["checks"]["docker"]["ok"] is True

    @pytest.mark.asyncio
    async def test_redis_not_connected_yields_503(self, client):
        factory, _ = _build_async_session_factory_mock()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = None  # connect not called yet
        fake_docker = MagicMock()
        fake_docker.containers.list = MagicMock(return_value=[])

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            return_value=fake_docker,
        ), patch(
            "os.path.isdir", return_value=True,
        ):
            resp = await client.get("/health/deep")

        assert resp.status_code == 503
        body = resp.json()
        assert body["checks"]["redis"]["ok"] is False
        assert body["checks"]["redis"]["error"] == "not connected"

    @pytest.mark.asyncio
    async def test_docker_unreachable_yields_503(self, client):
        factory, _ = _build_async_session_factory_mock()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = MagicMock()
        fake_event_svc._redis.ping = AsyncMock()

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            side_effect=Exception("socket not found"),
        ), patch(
            "os.path.isdir", return_value=True,
        ):
            resp = await client.get("/health/deep")

        assert resp.status_code == 503
        body = resp.json()
        assert body["checks"]["docker"]["ok"] is False

    @pytest.mark.asyncio
    async def test_missing_storage_root_yields_503(self, client):
        factory, _ = _build_async_session_factory_mock()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = MagicMock()
        fake_event_svc._redis.ping = AsyncMock()
        fake_docker = MagicMock()
        fake_docker.containers.list = MagicMock(return_value=[])

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            return_value=fake_docker,
        ), patch(
            "os.path.isdir", return_value=False,
        ):
            resp = await client.get("/health/deep")

        assert resp.status_code == 503
        body = resp.json()
        assert body["checks"]["storage"]["ok"] is False
        assert "path" in body["checks"]["storage"]


# ===========================================================================
# /ready alias parity
# ===========================================================================


class TestReadyAlias:
    @pytest.mark.asyncio
    async def test_ready_returns_same_shape_as_health_deep(self, client):
        """``/ready`` is the canonical k8s-convention path; must produce
        the same response shape as ``/health/deep`` (the back-compat alias)."""
        factory, _ = _build_async_session_factory_mock()
        fake_event_svc = MagicMock()
        fake_event_svc._redis = MagicMock()
        fake_event_svc._redis.ping = AsyncMock()
        fake_docker = MagicMock()
        fake_docker.containers.list = MagicMock(return_value=[])

        with patch(
            "app.routers.health.async_session_factory", factory,
        ), patch(
            "app.routers.health.event_service", fake_event_svc,
        ), patch(
            "app.routers.health.get_docker_client",
            return_value=fake_docker,
        ), patch(
            "os.path.isdir", return_value=True,
        ):
            deep_resp = await client.get("/health/deep")
            ready_resp = await client.get("/ready")

        assert deep_resp.status_code == ready_resp.status_code == 200
        deep_body = deep_resp.json()
        ready_body = ready_resp.json()
        assert deep_body["status"] == ready_body["status"] == "ok"
        # Same check keys present in both responses.
        assert set(deep_body["checks"].keys()) == set(ready_body["checks"].keys())
        assert set(deep_body["checks"].keys()) == {"db", "redis", "docker", "storage"}
