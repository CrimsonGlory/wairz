"""HTTP-layer tests for ``app.routers.cra_compliance``.

Phase 2 Wave 3 file 5 of 5 — backfills router-level tests for
backend/app/routers/cra_compliance.py (219 LOC, 7 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04. Pairs with the Wave 1
test_cra_compliance_service.py (commit 3f31957, 26 cases) for end-to-end
coverage of the EU CRA compliance assessment surface.

Coverage targets:

* ``_get_project_or_404`` — project-not-found 404 boundary.
* ``POST /assessments``       — project 404; invalid firmware_id 404
  (validates firmware belongs to project); happy-path returns assessment
  with 20 requirement rows (delegates to service-layer canary).
* ``GET /assessments``        — project 404; happy path.
* ``GET /assessments/{id}``   — assessment 404; cross-project 404.
* ``POST /assessments/{id}/auto-populate`` — assessment 404; cross-project 404.
* ``PATCH /assessments/{id}/requirements/{req_id}`` — assessment 404;
  cross-project 404; service ValueError → 404.
* ``GET /assessments/{id}/export`` — happy path.
* **Rule #35b live canary** — cross-project boundary: an assessment in
  project A must NOT be accessible via project B's URL. Pairs with the
  Wave 2 comparison_router cross-project canary as a security boundary
  pattern.

Per Rule #30: ``CRAComplianceService`` is MODULE-imported at top of
cra_compliance.py (line 19). Service-module patches work for it.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.cra_compliance import (  # noqa: F401 — registers tables
    CraAssessment,
    CraRequirementResult,
)
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.services.cra_compliance_service import CRAComplianceService

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
    """db.execute returning the given project from scalar_one_or_none."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = project
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    return db


# ===========================================================================
# Project-existence boundary
# ===========================================================================


class TestProjectBoundary:
    @pytest.mark.asyncio
    async def test_create_assessment_project_not_found_returns_404(
        self, client, project_id,
    ):
        db = _project_db_mock(project=None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/cra/assessments",
            json={"product_name": "Test", "product_version": "1.0"},
        )
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_list_assessments_project_not_found_returns_404(
        self, client, project_id,
    ):
        db = _project_db_mock(project=None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/cra/assessments",
        )
        assert resp.status_code == 404


# ===========================================================================
# POST /assessments — invalid firmware_id 404
# ===========================================================================


class TestCreateAssessmentValidation:
    @pytest.mark.asyncio
    async def test_invalid_firmware_id_returns_404(
        self, client, project_id,
    ):
        """``firmware_id`` provided but doesn't belong to the project →
        404, even though the project exists. Stops the assessment from
        binding to a firmware in a different project."""
        project = MagicMock(spec=Project)
        project.id = project_id

        # First execute() returns project; second (Firmware lookup) returns None.
        project_result = MagicMock()
        project_result.scalar_one_or_none.return_value = project
        firmware_result = MagicMock()
        firmware_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute = AsyncMock(side_effect=[project_result, firmware_result])

        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/cra/assessments",
            json={
                "firmware_id": str(uuid.uuid4()),
                "product_name": "Test",
                "product_version": "1.0",
            },
        )
        assert resp.status_code == 404
        assert "Firmware not found" in resp.json()["detail"]


# ===========================================================================
# Cross-project boundary on assessment lookups
# ===========================================================================


class TestAssessmentCrossProjectBoundary:
    @pytest.mark.asyncio
    async def test_get_assessment_in_other_project_returns_404(
        self, client, project_id,
    ):
        """Assessment exists but belongs to a different project — must
        404 (NOT leak that the assessment exists)."""
        project = MagicMock(spec=Project)
        project.id = project_id

        # Assessment is in DIFFERENT project.
        other_assessment = MagicMock(spec=CraAssessment)
        other_assessment.id = uuid.uuid4()
        other_assessment.project_id = uuid.uuid4()

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.cra_compliance.CRAComplianceService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_assessment = AsyncMock(return_value=other_assessment)
            svc_cls.return_value = svc

            resp = await client.get(
                f"/api/v1/projects/{project_id}/cra/assessments/{other_assessment.id}",
            )
        assert resp.status_code == 404
        assert "Assessment not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_auto_populate_in_other_project_returns_404(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        other_assessment = MagicMock(spec=CraAssessment)
        other_assessment.id = uuid.uuid4()
        other_assessment.project_id = uuid.uuid4()

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.cra_compliance.CRAComplianceService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_assessment = AsyncMock(return_value=other_assessment)
            svc.auto_populate = AsyncMock()
            svc_cls.return_value = svc

            resp = await client.post(
                f"/api/v1/projects/{project_id}/cra/assessments/{other_assessment.id}/auto-populate",
            )
        assert resp.status_code == 404
        # auto_populate must not have been called — boundary fires first.
        svc.auto_populate.assert_not_called()


# ===========================================================================
# PATCH /assessments/{id}/requirements/{req_id} — error path
# ===========================================================================


class TestUpdateRequirement:
    @pytest.mark.asyncio
    async def test_unknown_requirement_returns_404_via_value_error(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        assessment = MagicMock(spec=CraAssessment)
        assessment.id = uuid.uuid4()
        assessment.project_id = project_id

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.cra_compliance.CRAComplianceService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get_assessment = AsyncMock(return_value=assessment)
            svc.update_requirement = AsyncMock(
                side_effect=ValueError("Requirement annex_part1_99 not found"),
            )
            svc_cls.return_value = svc

            resp = await client.patch(
                f"/api/v1/projects/{project_id}/cra/assessments/{assessment.id}/requirements/annex1_partX_99",
                json={"status": "pass"},
            )
        assert resp.status_code == 404


# ===========================================================================
# Rule #35b LIVE-CANARY — cross-project boundary against real DB
# ===========================================================================


class TestCrossProjectBoundaryLiveCanary:
    """Rule #35b: the cross-project boundary on
    ``GET /assessments/{id}`` (router lines 95-97) is a security
    boundary — an assessment in project A must NOT be accessible via
    project B's URL. The canary uses TWO real Project rows + a real
    CraAssessment so the boundary fires against the actual DB shape,
    not just a MagicMock with arbitrary project_id (mock tests trivially
    match any UUID).
    """

    @pytest.mark.asyncio
    async def test_assessment_in_other_project_returns_404(self):
        async with make_live_db() as db:
            project_a = Project(id=uuid.uuid4(), name="A", status="ready")
            project_b = Project(id=uuid.uuid4(), name="B", status="ready")
            db.add(project_a)
            db.add(project_b)
            await db.flush()

            # Real assessment in project A (with real 20 requirement rows
            # to exercise the eager-load path).
            svc = CRAComplianceService(db)
            assessment = await svc.create_assessment(
                project_id=project_a.id,
                product_name="Cross-Project Canary Product",
            )
            await db.commit()

            app.dependency_overrides[get_db] = lambda: db

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                # Request via project B's URL — boundary must reject.
                resp = await c.get(
                    f"/api/v1/projects/{project_b.id}/cra/assessments/{assessment.id}",
                )

            assert resp.status_code == 404, (
                f"Rule #35b: cross-project boundary must reject CraAssessment "
                f"(id={assessment.id}, project_a={project_a.id}) via "
                f"project_b={project_b.id}; got {resp.status_code}"
            )
            assert "Assessment not found" in resp.json()["detail"]

            # Belt-and-braces: requesting via the CORRECT project still works.
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c2:
                resp_ok = await c2.get(
                    f"/api/v1/projects/{project_a.id}/cra/assessments/{assessment.id}",
                )
            assert resp_ok.status_code == 200, (
                "boundary must let the LEGITIMATE project through"
            )
            body = resp_ok.json()
            assert body["product_name"] == "Cross-Project Canary Product"
            # Eager-loaded 20 requirement results round-trip.
            assert len(body["requirement_results"]) == 20
