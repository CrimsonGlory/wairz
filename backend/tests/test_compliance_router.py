"""HTTP-layer tests for ``app.routers.compliance``.

Phase 2 Wave 5 file 6 of 6 (FINAL ROUTER WAVE) — backfills router-level
tests for backend/app/routers/compliance.py (57 LOC, 1 endpoint) per
intake audit-test-coverage-routers-services-2026-05-04.

Single ETSI EN 303 645 compliance report endpoint. Tests cover:

* ``GET /etsi``                — project 404; cross-project firmware_id 404;
  happy path returns service report.

Per Rule #30: ``ETSIComplianceService`` is module-imported at top of
compliance.py (line 12). Service-module patches work for it.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.project import Project
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


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


# ===========================================================================
# Project boundary
# ===========================================================================


class TestProjectBoundary:
    @pytest.mark.asyncio
    async def test_project_not_found_returns_404(self, client, project_id):
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/compliance/etsi",
        )
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]


# ===========================================================================
# Cross-project firmware_id boundary
# ===========================================================================


class TestFirmwareCrossProjectBoundary:
    @pytest.mark.asyncio
    async def test_firmware_id_not_in_project_returns_404(
        self, client, project_id,
    ):
        """firmware_id provided but doesn't belong to the project — must
        404 even though the project itself exists. Stops cross-project
        report generation."""
        project = MagicMock(spec=Project)
        project.id = project_id

        # First execute = project (found); second = firmware lookup (None).
        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = project
        firmware_result = MagicMock()
        firmware_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[project_result, firmware_result])
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/compliance/etsi",
            params={"firmware_id": str(uuid.uuid4())},
        )
        assert resp.status_code == 404
        assert "Firmware not found" in resp.json()["detail"]


# ===========================================================================
# Happy path
# ===========================================================================


class TestEtsiCompliance:
    @pytest.mark.asyncio
    async def test_returns_service_report(self, client, project_id):
        project = MagicMock(spec=Project)
        project.id = project_id

        result = MagicMock()
        result.scalar_one_or_none.return_value = project
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[get_db] = lambda: db

        fake_report = {
            "standard": "ETSI EN 303 645",
            "summary": {"pass": 5, "fail": 2, "partial": 3, "not_tested": 3},
            "provisions": [
                {"id": "5.1-1", "name": "No universal default passwords",
                 "status": "pass"},
            ],
        }

        # The router does `service.generate_report(...)` (returns a
        # coroutine) and then `await report`. So generate_report must be
        # an async function (NOT an AsyncMock that returns a coroutine).
        async def _gen_report(*args, **kwargs):
            return fake_report

        with patch(
            "app.routers.compliance.ETSIComplianceService",
        ) as svc_cls:
            svc = MagicMock()
            svc.generate_report = _gen_report
            svc_cls.return_value = svc

            resp = await client.get(
                f"/api/v1/projects/{project_id}/compliance/etsi",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["standard"] == "ETSI EN 303 645"
        assert body["summary"]["pass"] == 5
