"""HTTP-layer tests for ``app.routers.component_map``.

Phase 2 Wave 5 file 5 of 6 — backfills router-level tests for
backend/app/routers/component_map.py (88 LOC, 1 endpoint) per intake
audit-test-coverage-routers-services-2026-05-04.

Single endpoint that returns a firmware component dependency graph,
cached per firmware. Tests cover the cache-hit path (returns immediately)
and the build-graph path (with mocked ComponentMapService + cache write).

Coverage targets:

* ``GET /``               — cache-hit returns nodes/edges from
  analysis_cache without rebuilding.
* ``GET /``               — cache-miss builds via ComponentMapService;
  empty-graph result NOT cached (avoids stale-empty trap); non-empty
  result IS cached.
* ``GET /``               — service exception → 500.

Per Rule #30: ``_cache``, ``ComponentMapService`` are module-imported at
top of component_map.py (lines 16-17). ``get_detection_roots`` is
LAZY-imported inside the endpoint body (line 50) — patches must hit the
SOURCE module ``app.services.firmware_paths.get_detection_roots``.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep


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


def _firmware_mock(project_id: uuid.UUID) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = "/tmp/extract"
    fw.extraction_dir = "/tmp/extract"
    fw.device_metadata = None
    return fw


# ===========================================================================
# Cache-hit path
# ===========================================================================


class TestCacheHit:
    @pytest.mark.asyncio
    async def test_cached_response_returns_immediately(
        self, client, project_id,
    ):
        firmware = _firmware_mock(project_id)
        cached = {
            "nodes": [
                {
                    "id": "n1", "label": "libssl", "type": "library",
                    "path": "/usr/lib/libssl.so", "size": 100000,
                    "metadata": {},
                },
            ],
            "edges": [],
            "truncated": False,
        }

        with patch(
            "app.routers.component_map._cache.get_cached",
            new=AsyncMock(return_value=cached),
        ), patch(
            "app.routers.component_map.ComponentMapService",
        ) as svc_cls:
            # Build path MUST NOT be reached on cache hit.
            svc_cls.side_effect = AssertionError(
                "ComponentMapService should NOT be constructed on cache hit"
            )

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/component-map",
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["node_count"] == 1
        assert body["edge_count"] == 0
        assert body["truncated"] is False
        assert body["nodes"][0]["label"] == "libssl"


# ===========================================================================
# Build path
# ===========================================================================


class TestBuildGraph:
    def _make_graph(self, *, with_nodes: bool = True):
        graph = MagicMock()
        if with_nodes:
            node = MagicMock()
            node.id = "n1"
            node.label = "openssl"
            node.type = "library"
            node.path = "/usr/lib/libssl.so"
            node.size = 100000
            node.metadata = {}
            graph.nodes = [node]
            edge = MagicMock()
            edge.source = "binary:lighttpd"
            edge.target = "n1"
            edge.type = "links_against"
            edge.details = {}
            graph.edges = [edge]
        else:
            graph.nodes = []
            graph.edges = []
        graph.truncated = False
        return graph

    @pytest.mark.asyncio
    async def test_cache_miss_builds_graph_and_caches_non_empty(
        self, client, project_id,
    ):
        firmware = _firmware_mock(project_id)
        graph = self._make_graph(with_nodes=True)

        store_calls: list = []

        async def _capture_store(*args, **kwargs):
            store_calls.append((args, kwargs))

        with patch(
            "app.routers.component_map._cache.get_cached",
            new=AsyncMock(return_value=None),
        ), patch(
            "app.routers.component_map._cache.store_cached",
            new=AsyncMock(side_effect=_capture_store),
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[firmware.extracted_path]),
        ), patch(
            "app.routers.component_map.ComponentMapService",
        ) as svc_cls:
            svc = MagicMock()
            svc.build_graph = MagicMock(return_value=graph)
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/component-map",
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["node_count"] == 1
        assert body["edge_count"] == 1
        assert body["nodes"][0]["label"] == "openssl"

        # Non-empty graph IS cached (1 store_cached call).
        assert len(store_calls) == 1, (
            "non-empty graph must be persisted to cache so subsequent "
            "calls hit the fast path"
        )

    @pytest.mark.asyncio
    async def test_empty_graph_is_not_cached(self, client, project_id):
        """Empty results aren't cached — a regression that caches them
        would freeze the empty state until manual cache eviction."""
        firmware = _firmware_mock(project_id)
        graph = self._make_graph(with_nodes=False)

        store_calls: list = []

        async def _capture_store(*args, **kwargs):
            store_calls.append((args, kwargs))

        with patch(
            "app.routers.component_map._cache.get_cached",
            new=AsyncMock(return_value=None),
        ), patch(
            "app.routers.component_map._cache.store_cached",
            new=AsyncMock(side_effect=_capture_store),
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[firmware.extracted_path]),
        ), patch(
            "app.routers.component_map.ComponentMapService",
        ) as svc_cls:
            svc = MagicMock()
            svc.build_graph = MagicMock(return_value=graph)
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/component-map",
            )

        assert resp.status_code == 200
        body = resp.json()
        assert body["node_count"] == 0

        # Empty graph NOT cached.
        assert len(store_calls) == 0, (
            "empty graph must NOT be cached — would freeze empty state"
        )

    @pytest.mark.asyncio
    async def test_build_exception_returns_500(self, client, project_id):
        firmware = _firmware_mock(project_id)

        with patch(
            "app.routers.component_map._cache.get_cached",
            new=AsyncMock(return_value=None),
        ), patch(
            "app.services.firmware_paths.get_detection_roots",
            new=AsyncMock(return_value=[firmware.extracted_path]),
        ), patch(
            "app.routers.component_map.ComponentMapService",
        ) as svc_cls:
            svc = MagicMock()
            svc.build_graph = MagicMock(
                side_effect=RuntimeError("graph builder crashed"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/component-map",
            )
        assert resp.status_code == 500
        assert "Failed to build component map" in resp.json()["detail"]
