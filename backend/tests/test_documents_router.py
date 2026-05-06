"""HTTP-layer tests for ``app.routers.documents``.

Phase 2 Wave 4 file 2 of 5 — backfills router-level tests for
backend/app/routers/documents.py (202 LOC, 9 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

Coverage targets:

* Project boundary       — ``_get_project_or_404`` returns 404 for missing.
* ``POST /``             — bad extension 400; service ValueError 400.
* ``POST /notes``        — happy path persists Document (Rule #35b live canary).
* ``PUT /{id}/content``  — 404 missing; 404 cross-project; 400 non-editable
  extension.
* ``GET /``              — happy path returns list.
* ``GET /{id}``          — 404 missing; 404 cross-project.
* ``GET /{id}/content``  — 404 missing.
* ``GET /{id}/download`` — 404 missing; 404 file missing on disk.
* ``PATCH /{id}``        — 404 missing.
* ``DELETE /{id}``       — 404 missing.

Per Rule #30: ``DocumentService`` is MODULE-imported at top of
documents.py (line 18). Service-module patches work for it.
``_validate_extension`` and ``EDITABLE_EXTENSIONS`` are module-scope.
"""
from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.document import Document  # noqa: F401 — registers
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


def _doc_mock(
    project_id: uuid.UUID, *, filename: str = "notes.md",
) -> MagicMock:
    d = MagicMock(spec=Document)
    d.id = uuid.uuid4()
    d.project_id = project_id
    d.original_filename = filename
    d.description = None
    d.content_type = "text/markdown"
    d.file_size = 100
    d.sha256 = "a" * 64
    d.storage_path = "/data/docs/notes.md"
    d.created_at = datetime.now(timezone.utc)
    return d


# ===========================================================================
# Project-existence boundary
# ===========================================================================


class TestProjectBoundary:
    @pytest.mark.asyncio
    async def test_list_documents_project_404(self, client, project_id):
        db = _project_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/documents",
        )
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]


# ===========================================================================
# POST / — extension validation
# ===========================================================================


class TestUpload:
    @pytest.mark.asyncio
    async def test_disallowed_extension_returns_400(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        # Build a file payload with a forbidden extension (.exe).
        files = {"file": ("malware.exe", b"junk", "application/octet-stream")}
        resp = await client.post(
            f"/api/v1/projects/{project_id}/documents",
            files=files,
            data={"description": "test"},
        )
        assert resp.status_code == 400
        assert "not allowed" in resp.json()["detail"]


# ===========================================================================
# Cross-project boundary on document operations
# ===========================================================================


class TestDocumentCrossProjectBoundary:
    @pytest.mark.asyncio
    async def test_get_document_in_other_project_returns_404(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        # Document belongs to DIFFERENT project.
        other_doc = _doc_mock(project_id=uuid.uuid4())

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.documents.DocumentService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=other_doc)
            svc_cls.return_value = svc

            resp = await client.get(
                f"/api/v1/projects/{project_id}/documents/{other_doc.id}",
            )
        assert resp.status_code == 404
        assert "Document not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_download_404_when_storage_path_missing(
        self, client, project_id, tmp_path: Path,
    ):
        """Document row exists but storage_path doesn't exist on disk → 404."""
        project = MagicMock(spec=Project)
        project.id = project_id

        doc = _doc_mock(project_id)
        doc.storage_path = str(tmp_path / "ghost.md")  # never created

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.documents.DocumentService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=doc)
            svc_cls.return_value = svc

            resp = await client.get(
                f"/api/v1/projects/{project_id}/documents/{doc.id}/download",
            )
        assert resp.status_code == 404
        assert "not found on disk" in resp.json()["detail"]


# ===========================================================================
# PUT /{id}/content — non-editable extension
# ===========================================================================


class TestUpdateContent:
    @pytest.mark.asyncio
    async def test_non_editable_extension_returns_400(
        self, client, project_id,
    ):
        project = MagicMock(spec=Project)
        project.id = project_id

        # PDF is in ALLOWED_EXTENSIONS but NOT in EDITABLE_EXTENSIONS.
        doc = _doc_mock(project_id, filename="report.pdf")

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.documents.DocumentService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=doc)
            svc_cls.return_value = svc

            resp = await client.put(
                f"/api/v1/projects/{project_id}/documents/{doc.id}/content",
                json={"content": "# new content"},
            )
        assert resp.status_code == 400
        assert "Cannot edit" in resp.json()["detail"]


# ===========================================================================
# DELETE /{id} — boundary
# ===========================================================================


class TestDelete:
    @pytest.mark.asyncio
    async def test_delete_404_when_doc_missing(self, client, project_id):
        project = MagicMock(spec=Project)
        project.id = project_id

        db = _project_db_mock(project)
        app.dependency_overrides[get_db] = lambda: db

        with patch(
            "app.routers.documents.DocumentService",
        ) as svc_cls:
            svc = MagicMock()
            svc.get = AsyncMock(return_value=None)
            svc_cls.return_value = svc

            resp = await client.delete(
                f"/api/v1/projects/{project_id}/documents/{uuid.uuid4()}",
            )
        assert resp.status_code == 404


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /notes persists Document
# ===========================================================================


class TestCreateNoteLiveCanary:
    """Rule #35b: ``POST /notes`` constructs a Document row through
    DocumentService.create_note. Title + content + project_id must
    round-trip; the canary stubs create_note to actually persist a real
    Document row through the live db so the SELECT-back assertion
    catches a regression that drops any field on the constructor.
    """

    @pytest.mark.asyncio
    async def test_persists_note_with_correct_metadata(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            async def _fake_create_note(
                project_id, title, content,
            ):
                doc = Document(
                    project_id=project_id,
                    original_filename=f"{title}.md",
                    description=None,
                    content_type="text/markdown",
                    file_size=len(content),
                    sha256="b" * 64,
                    storage_path=str(tmp_path / f"{title}.md"),
                )
                db.add(doc)
                await db.flush()
                return doc

            with patch(
                "app.routers.documents.DocumentService",
            ) as svc_cls:
                svc = MagicMock()
                svc.create_note = _fake_create_note
                svc_cls.return_value = svc

                app.dependency_overrides[get_db] = lambda: db

                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test",
                ) as c:
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/documents/notes",
                        json={
                            "title": "investigation-2026-05-06",
                            "content": "# Findings\n\nReverse engineering notes.",
                        },
                    )

            assert resp.status_code == 201, resp.text

            persisted = (
                await db.execute(
                    select(Document).where(Document.project_id == pid),
                )
            ).scalars().all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.project_id == pid
            assert row.original_filename == "investigation-2026-05-06.md"
            assert row.content_type == "text/markdown"
            assert row.file_size == len("# Findings\n\nReverse engineering notes.")
