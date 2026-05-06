"""HTTP-layer tests for ``app.routers.firmware`` upload + 202+polling path.

Phase 1 of audit-test-coverage-routers-services-2026-05-04 focuses on the
two paths most likely to regress under refactor:

* ``POST /api/v1/projects/{project_id}/firmware`` — the upload endpoint.
  Mocks ``FirmwareService.upload`` so the test exercises the rate limiter
  + dependency wiring + response schema without writing real bytes through
  the unpack pipeline (which pulls in unblob, binwalk, magic, etc.).

* ``POST .../firmware/{firmware_id}/unpack`` — the 202+polling kickoff per
  CLAUDE.md Rule #33. Verifies all four guard clauses (project missing 404,
  firmware missing 404, already-unpacked 409, file-missing 410), the
  in-flight 409, and the happy-path 202 → ``project.status="unpacking"``
  transition.

Includes a Rule #35b live-canary that runs the ``/unpack`` endpoint
against a real SQLite session: seeds Project + Firmware rows with a
storage_path on disk (a real bytes file in tmp_path), patches the
background runner so the test does not block on actual extraction,
then SELECTs the project row to confirm ``status='unpacking'``
actually round-tripped through the DB layer.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.firmware import get_firmware_service

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _disable_api_key_auth(monkeypatch):
    """Disable APIKeyASGIMiddleware for these tests (auth has its own coverage)."""
    from app.middleware import asgi_auth as _auth_mod

    fake_settings = MagicMock()
    fake_settings.api_key = ""
    monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake_settings)


@pytest.fixture(autouse=True)
def _disable_rate_limit():
    """Disable the slowapi limiter for the test scope.

    ``POST /firmware`` is rate-limited at 5/minute (firmware.py:81). Without
    this fixture a tight test loop would 429 partway through.
    """
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


# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------

def _make_firmware_row(project_id: uuid.UUID, **overrides) -> MagicMock:
    """Build a Firmware-shaped mock row matching FirmwareDetailResponse."""
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.original_filename = "test.bin"
    fw.sha256 = "a" * 64
    fw.file_size = 1024
    fw.storage_path = "/tmp/storage/x.bin"
    fw.extracted_path = None
    fw.extraction_dir = None
    fw.architecture = None
    fw.endianness = None
    fw.os_info = None
    fw.kernel_path = None
    fw.version_label = None
    fw.unpack_log = None
    fw.unpack_stage = None
    fw.unpack_progress = None
    fw.binary_info = None
    fw.device_metadata = None
    fw.created_at = datetime.now(timezone.utc)
    for key, value in overrides.items():
        setattr(fw, key, value)
    return fw


# ---------------------------------------------------------------------------
# POST /firmware — upload happy path
# ---------------------------------------------------------------------------

class TestUploadFirmware:
    """``POST /api/v1/projects/{pid}/firmware`` — multipart upload."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_201_with_response_schema(
        self, client, project_id,
    ):
        """Upload returns 201 + the FirmwareUploadResponse fields."""
        # Service mock — actual bytes go nowhere.
        firmware_row = _make_firmware_row(project_id)
        svc = MagicMock()
        svc.upload = AsyncMock(return_value=firmware_row)

        app.dependency_overrides[get_firmware_service] = lambda: svc

        files = {"file": ("test.bin", b"\x00" * 64, "application/octet-stream")}
        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware",
            files=files,
        )

        assert resp.status_code == 201, resp.text
        body = resp.json()
        # FirmwareUploadResponse fields (schemas/firmware.py:7).
        for key in ("id", "original_filename", "sha256", "file_size", "created_at"):
            assert key in body, f"upload response missing '{key}'"
        assert body["sha256"] == "a" * 64
        assert body["file_size"] == 1024

        # Service was called with the right project_id + multipart UploadFile.
        assert svc.upload.await_count == 1
        await_args = svc.upload.await_args
        assert await_args.args[0] == project_id

    @pytest.mark.asyncio
    async def test_oversized_upload_returns_413(self, client, project_id):
        """File > MAX_UPLOAD_SIZE_MB is rejected before bytes stream into svc."""
        # The router's _check_upload_size guard fires when file.size > limit.
        # We don't need a service mock because the guard runs before any
        # service call.
        from app.routers import firmware as firmware_router

        # Force the limit to a tiny value for this test.
        original = firmware_router.MAX_UPLOAD_BYTES
        firmware_router.MAX_UPLOAD_BYTES = 8  # 8 bytes
        try:
            files = {
                "file": (
                    "huge.bin",
                    b"X" * 1024,  # 1 KiB > 8 byte limit
                    "application/octet-stream",
                ),
            }
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware",
                files=files,
            )
        finally:
            firmware_router.MAX_UPLOAD_BYTES = original

        assert resp.status_code == 413
        assert "too large" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# POST /firmware/{fid}/unpack — 202+polling guard clauses
# ---------------------------------------------------------------------------

class TestUnpackGuards:
    """All four pre-spawn guards on the unpack endpoint must fire correctly."""

    @pytest.mark.asyncio
    async def test_project_not_found_returns_404(self, client, project_id):
        # First execute() returns scalar_one_or_none = None for the
        # ``select(Project).with_for_update()`` lookup.
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = None

        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_db] = lambda: db

        svc = MagicMock()
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{uuid.uuid4()}/unpack"
        )
        assert resp.status_code == 404
        assert "Project not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_firmware_not_found_returns_404(self, client, project_id):
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "ready"
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project

        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_db] = lambda: db

        # Service returns None → 404.
        svc = MagicMock()
        svc.get_by_id = AsyncMock(return_value=None)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{uuid.uuid4()}/unpack"
        )
        assert resp.status_code == 404
        assert "Firmware not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_already_unpacked_returns_409(self, client, project_id):
        """Re-unpacking a row whose extracted_path is already set → 409."""
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "ready"
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project

        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_db] = lambda: db

        firmware_row = _make_firmware_row(
            project_id,
            extracted_path="/already/extracted",
            storage_path="/tmp/x.bin",
        )
        svc = MagicMock()
        svc.get_by_id = AsyncMock(return_value=firmware_row)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_row.id}/unpack"
        )
        assert resp.status_code == 409
        assert "already unpacked" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_already_unpacking_returns_409(self, client, project_id):
        """Project already in ``status='unpacking'`` → 409 (no double-spawn)."""
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "unpacking"  # in-flight
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project

        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_db] = lambda: db

        firmware_row = _make_firmware_row(project_id, storage_path="/tmp/x.bin")
        svc = MagicMock()
        svc.get_by_id = AsyncMock(return_value=firmware_row)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_row.id}/unpack"
        )
        assert resp.status_code == 409
        assert "already being unpacked" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_storage_file_missing_returns_410(
        self, client, project_id, tmp_path: Path,
    ):
        """firmware.storage_path missing on disk → 410 Gone (re-upload)."""
        project = MagicMock(spec=Project)
        project.id = project_id
        project.status = "ready"
        proj_result = MagicMock()
        proj_result.scalar_one_or_none.return_value = project

        db = AsyncMock()
        db.execute = AsyncMock(return_value=proj_result)
        app.dependency_overrides[get_db] = lambda: db

        firmware_row = _make_firmware_row(
            project_id,
            storage_path=str(tmp_path / "does-not-exist.bin"),
        )
        svc = MagicMock()
        svc.get_by_id = AsyncMock(return_value=firmware_row)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/firmware/{firmware_row.id}/unpack"
        )
        assert resp.status_code == 410
        assert "re-upload" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /firmware/{fid} — single-firmware lookup
# ---------------------------------------------------------------------------

class TestGetSingleFirmware:
    """Basic 404 contract for cross-project lookup."""

    @pytest.mark.asyncio
    async def test_firmware_belongs_to_other_project_returns_404(
        self, client, project_id,
    ):
        other_project = uuid.uuid4()
        firmware_row = _make_firmware_row(other_project)

        svc = MagicMock()
        svc.get_by_id = AsyncMock(return_value=firmware_row)
        app.dependency_overrides[get_firmware_service] = lambda: svc

        resp = await client.get(
            f"/api/v1/projects/{project_id}/firmware/{firmware_row.id}"
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Rule #35b LIVE-CANARY — real ORM round-trip + SELECT
# ---------------------------------------------------------------------------

class TestUnpackPersistenceLiveCanary:
    """Verifies the unpack 202+polling state transition end-to-end.

    The 202+polling pattern (Rule #33) requires that POST /unpack
    transitions ``project.status`` from ``ready`` to ``unpacking`` and
    flushes the row BEFORE returning 202 — otherwise the polling loop on
    the frontend sees stale state and the background task observes a
    race. Mock-only tests assert that ``project.status`` was assigned
    in memory; the live canary actually SELECTs the row to verify it
    landed in the database.
    """

    @pytest.mark.asyncio
    async def test_unpack_returns_202_and_persists_unpacking_status(
        self, client, project_id, tmp_path: Path,
    ):
        # A real bytes file on disk so the os.path.exists() guard passes.
        storage_file = tmp_path / "firmware.bin"
        storage_file.write_bytes(b"\x00" * 32)

        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="live-canary-unpack", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="d" * 64,
                storage_path=str(storage_file),
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            # The router uses Depends(get_firmware_service) — wire that to
            # a service that talks to the live session.
            from app.services.firmware_service import FirmwareService
            app.dependency_overrides[get_firmware_service] = lambda: FirmwareService(db)

            # Patch the background spawn paths so the test doesn't actually
            # run unblob/binwalk against the empty file. Both arq + the
            # asyncio fallback are intercepted.
            with patch(
                "app.routers.firmware._get_arq_pool",
                new=AsyncMock(return_value=None),
            ), patch(
                "app.routers.firmware.asyncio.create_task",
                new=MagicMock(),
            ) as mock_create_task:
                resp = await client.post(
                    f"/api/v1/projects/{pid}/firmware/{firmware.id}/unpack"
                )

            assert resp.status_code == 202, resp.text
            # The background runner must have been scheduled exactly once.
            assert mock_create_task.call_count == 1

            # Real SELECT — Rule #35b: did project.status actually round-trip?
            row = (
                await db.execute(select(Project).where(Project.id == pid))
            ).scalar_one()
            assert row.status == "unpacking", (
                f"expected project.status='unpacking' after POST /unpack, "
                f"got '{row.status}' — the router's flush() did not persist"
            )

            # The firmware row should still be queryable (no extraction yet).
            fw_row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware.id)
                )
            ).scalar_one()
            assert fw_row.extracted_path is None
