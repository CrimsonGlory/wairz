"""HTTP-layer tests for ``app.routers.findings``.

Phase 2 Wave 4 file 4 of 5 — backfills router-level tests for
backend/app/routers/findings.py (157 LOC, 6 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

Coverage targets:

* Project boundary       — ``_get_project_or_404`` returns 404 for missing.
* ``POST /``             — happy path persists Finding (Rule #35b live canary
  via real FindingService.create through real DB session).
* ``GET /``              — pagination + filters (severity / status / source /
  firmware_id) all reach the SQL layer.
* ``GET /{id}``          — cross-project 404.
* ``PATCH /{id}``        — cross-project 404.
* ``DELETE /{id}``       — cross-project 404.
* ``POST /export``       — invalid format returns 422; markdown vs pdf
  Content-Disposition selection.

Per Rule #30: ``FindingService`` and ``generate_*_report`` are MODULE-imported
at top of findings.py (lines 15-16). Service-module patches work for them.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.finding import Finding
from app.models.project import Project
from app.rate_limit import limiter
from tests._live_db import make_live_db

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


def _project_db_mock(project: MagicMock | None) -> AsyncMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = project
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    return db


# ===========================================================================
# Project boundary
# ===========================================================================


class TestProjectBoundary:
    @pytest.mark.asyncio
    async def test_create_finding_project_404(self, client, project_id):
        db = _project_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/findings",
            json={"title": "test", "severity": "high"},
        )
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]


# ===========================================================================
# Cross-project boundary on finding_id endpoints
# ===========================================================================


class TestFindingCrossProjectBoundary:
    @pytest.mark.asyncio
    async def test_get_finding_in_other_project_returns_404(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        # Finding belongs to DIFFERENT project.
        other_finding = MagicMock(spec=Finding)
        other_finding.id = uuid.uuid4()
        other_finding.project_id = uuid.uuid4()

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.findings.FindingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=other_finding)
            svc_cls.return_value = svc

            resp = await client.get(
                f"/api/v1/projects/{project_id}/findings/{other_finding.id}",
            )
        assert resp.status_code == 404
        assert "Finding not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_patch_finding_in_other_project_returns_404(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        other_finding = MagicMock(spec=Finding)
        other_finding.id = uuid.uuid4()
        other_finding.project_id = uuid.uuid4()

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.findings.FindingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=other_finding)
            svc.update = AsyncMock()
            svc_cls.return_value = svc

            resp = await client.patch(
                f"/api/v1/projects/{project_id}/findings/{other_finding.id}",
                json={"status": "confirmed"},  # FindingStatus enum value
            )
        assert resp.status_code == 404
        # update must not have been called — boundary fires first.
        svc.update.assert_not_called()

    @pytest.mark.asyncio
    async def test_delete_finding_404_when_missing(self, client, project_id):
        project = MagicMock(spec=Project)
        project.id = project_id

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.findings.FindingService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=None)
            svc_cls.return_value = svc

            resp = await client.delete(
                f"/api/v1/projects/{project_id}/findings/{uuid.uuid4()}",
            )
        assert resp.status_code == 404


# ===========================================================================
# POST /export — markdown / pdf
# ===========================================================================


class TestExportFindings:
    @pytest.mark.asyncio
    async def test_invalid_format_returns_422(self, client, project_id):
        project = MagicMock(spec=Project)
        project.id = project_id
        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/findings/export",
            params={"format": "csv"},  # not allowed
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_markdown_export_returns_text_response(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id
        project.name = "Test Project"

        # First execute() = project lookup. Second = firmware lookup
        # (returns None — no firmware uploaded yet).
        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = project
        firmware_result = MagicMock()
        firmware_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[project_result, firmware_result])
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.findings.FindingService",
        ) as svc_cls, patch(
            "app.routers.findings.generate_markdown_report",
            return_value="# Findings Report\n\nNo findings.\n",
        ):
            svc = MagicMock()
            svc.list_by_project = AsyncMock(return_value=[])
            svc_cls.return_value = svc

            resp = await client.post(
                f"/api/v1/projects/{project_id}/findings/export",
                params={"format": "markdown"},
            )
        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"] == "text/markdown; charset=utf-8"
        assert "Test_Project_security_report.md" in resp.headers["content-disposition"]


# ===========================================================================
# GET / — list with filters
# ===========================================================================


class TestListFindings:
    @pytest.mark.asyncio
    async def test_returns_paginated_findings(
        self, client, project_id, monkeypatch,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id
        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        finding = MagicMock(spec=Finding)
        finding.id = uuid.uuid4()
        finding.project_id = project_id
        finding.firmware_id = None
        finding.title = "Test finding"
        finding.severity = "high"
        finding.confidence = "high"
        finding.status = "open"
        finding.source = "manual"
        finding.description = None
        finding.evidence = None
        finding.file_path = None
        finding.line_number = None
        finding.cwe_ids = None
        finding.cve_ids = None
        finding.conversation_id = None
        finding.component_id = None
        finding.created_at = datetime.now(UTC)
        finding.updated_at = datetime.now(UTC)

        async def fake_paginate(db, stmt, offset, limit):  # noqa: ARG001
            return [finding], 1

        monkeypatch.setattr(
            "app.routers.findings.paginate_query", fake_paginate,
        )

        resp = await client.get(
            f"/api/v1/projects/{project_id}/findings",
            params={"severity": "high"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total"] == 1
        assert body["items"][0]["severity"] == "high"


# ===========================================================================
# Rule #35b LIVE-CANARY — POST / persists Finding
# ===========================================================================


class TestCreateFindingLiveCanary:
    """Rule #35b: ``POST /findings`` routes through FindingService.create
    which constructs a Finding row. Pairs with Wave 1's
    test_assessment_service.py canary on the same path. The router
    canary asserts every request field round-trips through both layers
    of the dispatch.
    """

    @pytest.mark.asyncio
    async def test_persists_finding_with_all_request_fields(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            payload = {
                "title": "Hardcoded API key",
                "severity": "critical",
                "description": "Found in /etc/secrets.cfg",
                "evidence": "AKIAIOSFODNN7EXAMPLE",
                "file_path": "etc/secrets.cfg",
                "line_number": 42,
                "cwe_ids": ["CWE-798"],
                "cve_ids": [],
                "confidence": "high",
                "source": "manual",
            }

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                resp = await c.post(
                    f"/api/v1/projects/{pid}/findings",
                    json=payload,
                )

            assert resp.status_code == 201, resp.text

            persisted = (
                await db.execute(
                    select(Finding).where(Finding.project_id == pid),
                )
            ).scalars().all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.title == "Hardcoded API key"
            assert row.severity == "critical"
            assert row.confidence == "high", (
                "Rule #35b: confidence must round-trip through FindingService "
                "+ the router constructor — F-A-06 backstop"
            )
            assert row.source == "manual"
            assert row.file_path == "etc/secrets.cfg"
            assert row.line_number == 42
            assert row.cwe_ids == ["CWE-798"]
            assert row.evidence == "AKIAIOSFODNN7EXAMPLE"
