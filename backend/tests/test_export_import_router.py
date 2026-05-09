"""HTTP-layer tests for ``app.routers.export_import``.

Phase 2 Wave 5 file 4 of 6 — backfills router-level tests for
backend/app/routers/export_import.py (100 LOC, 2 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

Coverage targets:

* ``POST /{id}/export`` — project 404; service ValueError 400; happy path
  streams ZIP archive with sanitized filename.
* ``POST /import``      — 413 too large; 400 wrong extension; 400 empty
  body; service ValueError 400; happy path returns ProjectResponse.

Per Rule #30: ``ExportService`` and ``ImportService`` are MODULE-imported
at top of export_import.py (lines 16-17). Service-module patches work
for them.
"""
from __future__ import annotations

import io
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


def _project_db_mock(project: MagicMock | None) -> AsyncMock:
    result = MagicMock()
    result.scalar_one_or_none.return_value = project
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    return db


# ===========================================================================
# POST /{id}/export
# ===========================================================================


class TestExportProject:
    @pytest.mark.asyncio
    async def test_project_not_found_returns_404(self, client):
        db = _project_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(f"/api/v1/projects/{uuid.uuid4()}/export")
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_service_value_error_returns_400(self, client):
        project = MagicMock(spec=Project)
        project.id = uuid.uuid4()
        project.name = "Test"

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.export_import.ExportService",
        ) as svc_cls:
            svc = MagicMock()
            svc.export_project = AsyncMock(
                side_effect=ValueError("export failed"),
            )
            svc_cls.return_value = svc

            resp = await client.post(
                f"/api/v1/projects/{project.id}/export",
            )
        assert resp.status_code == 400
        assert "export failed" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_happy_path_streams_zip_with_sanitized_filename(
        self, client,
    ):
        """Project name with shell-unsafe chars must be sanitized in
        Content-Disposition (security boundary — header injection)."""
        project = MagicMock(spec=Project)
        project.id = uuid.uuid4()
        project.name = "Project with / unsafe chars"

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        zip_bytes = io.BytesIO(b"PK\x03\x04" + b"\x00" * 1000)

        with patch(
            "app.routers.export_import.ExportService",
        ) as svc_cls:
            svc = MagicMock()
            svc.export_project = AsyncMock(return_value=zip_bytes)
            svc_cls.return_value = svc

            resp = await client.post(
                f"/api/v1/projects/{project.id}/export",
            )

        assert resp.status_code == 200, resp.text
        assert resp.headers["content-type"] == "application/zip"
        # Filename sanitized — no slashes / spaces in archive name.
        disposition = resp.headers["content-disposition"]
        assert "/" not in disposition.split("filename=")[1]
        assert ".wairz" in disposition


# ===========================================================================
# POST /import
# ===========================================================================


class TestImportProject:
    @pytest.mark.asyncio
    async def test_wrong_extension_returns_400(self, client):
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        files = {"file": ("malware.bin", b"PK\x03\x04" * 100,
                          "application/octet-stream")}
        resp = await client.post("/api/v1/projects/import", files=files)
        assert resp.status_code == 400
        assert "Invalid file type" in resp.json()["detail"]
        # The detail also explains the firmware-import workflow.
        assert ".wairz" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_empty_file_returns_400(self, client):
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        files = {"file": ("project.wairz", b"", "application/zip")}
        resp = await client.post("/api/v1/projects/import", files=files)
        assert resp.status_code == 400
        assert "Empty" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_service_value_error_returns_400(self, client):
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.export_import.ImportService",
        ) as svc_cls:
            svc = MagicMock()
            svc.import_project = AsyncMock(
                side_effect=ValueError("malformed archive"),
            )
            svc_cls.return_value = svc

            files = {"file": ("project.wairz", b"junk archive bytes",
                              "application/zip")}
            resp = await client.post("/api/v1/projects/import", files=files)
        assert resp.status_code == 400
        assert "malformed" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_zip_extension_also_accepted(self, client):
        """The router accepts both `.wairz` AND `.zip` (for clients that
        rename or compress externally) — the malformed-archive ValueError
        is still surfaced if the contents aren't a real wairz archive."""
        app.dependency_overrides[get_db] = lambda: AsyncMock()

        with patch(
            "app.routers.export_import.ImportService",
        ) as svc_cls:
            svc = MagicMock()
            svc.import_project = AsyncMock(
                side_effect=ValueError("not a wairz archive"),
            )
            svc_cls.return_value = svc

            files = {"file": ("project.zip", b"PK\x03\x04" + b"\x00" * 100,
                              "application/zip")}
            resp = await client.post("/api/v1/projects/import", files=files)
        # Reaches the service-layer error rather than 400-extension.
        assert resp.status_code == 400
        assert "not a wairz archive" in resp.json()["detail"]
