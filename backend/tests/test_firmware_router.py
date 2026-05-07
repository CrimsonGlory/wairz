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
    # Rule #29 + Rule #33 upload-stage state machine fields.
    fw.upload_stage = "detecting"
    fw.upload_stage_started_at = datetime.now(timezone.utc)
    fw.upload_stage_finished_at = None
    fw.upload_stage_error = None
    fw.detected_format = None
    for key, value in overrides.items():
        setattr(fw, key, value)
    return fw


# ---------------------------------------------------------------------------
# POST /firmware — upload happy path
# ---------------------------------------------------------------------------

class TestUploadFirmware:
    """``POST /api/v1/projects/{pid}/firmware`` — multipart upload (Rule #33 202+polling)."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_202_with_status_response(
        self, client, project_id,
    ):
        """Upload returns 202 + FirmwareUploadStatusResponse fields.

        Post-Rule-#33-refactor (commit 847eae9): the endpoint now returns
        202 Accepted with a status-response shape. The router spawns
        ``_run_upload_post_processing_background`` via asyncio.create_task;
        the test patches that target so the background task is a no-op
        (the ack itself is what we're verifying).
        """
        firmware_row = _make_firmware_row(project_id)
        svc = MagicMock()
        svc.upload_bytes_only = AsyncMock(return_value=firmware_row)

        app.dependency_overrides[get_firmware_service] = lambda: svc

        files = {"file": ("test.bin", b"\x00" * 64, "application/octet-stream")}
        with patch(
            "app.routers.firmware._run_upload_post_processing_background",
            new=AsyncMock(),
        ):
            resp = await client.post(
                f"/api/v1/projects/{project_id}/firmware",
                files=files,
            )

        assert resp.status_code == 202, resp.text
        body = resp.json()
        # FirmwareUploadStatusResponse fields (schemas/firmware.py).
        for key in (
            "id",
            "upload_stage",
            "detected_format",
            "extraction_capability",
            "capability_note",
            "sha256",
        ):
            assert key in body, f"upload response missing '{key}'"
        assert body["upload_stage"] == "detecting"
        assert body["sha256"] == "a" * 64

        # Service was called with the right project_id.
        assert svc.upload_bytes_only.await_count == 1
        await_args = svc.upload_bytes_only.await_args
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


# ---------------------------------------------------------------------------
# POST /firmware (Rule #33 202+polling) — upload-stage state machine
# ---------------------------------------------------------------------------

class TestUploadStateMachineLiveCanary:
    """End-to-end checks for the upload-stage state machine (Rule #33)."""

    @pytest.mark.asyncio
    async def test_upload_status_endpoint_round_trips_persisted_fields(
        self, client, project_id, tmp_path: Path,
    ):
        """GET /upload-status returns the row's stage + detected_format.

        Rule #35b live canary: seeds a Firmware row with the new columns
        populated, hits the GET endpoint, asserts the response carries
        the same values back. This catches Pydantic schema/ORM mismatch
        regressions (Rule #4) on the new columns.
        """
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="live-canary-upload-status", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="b" * 64,
                storage_path=str(tmp_path / "x.bin"),
                upload_stage="extracting",
                detected_format="linux_firmware_blob",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db
            from app.services.firmware_service import FirmwareService
            app.dependency_overrides[get_firmware_service] = lambda: FirmwareService(db)

            resp = await client.get(
                f"/api/v1/projects/{pid}/firmware/{firmware.id}/upload-status"
            )
            assert resp.status_code == 200, resp.text
            body = resp.json()
            assert body["upload_stage"] == "extracting"
            assert body["detected_format"] == "linux_firmware_blob"
            # Linux firmware blob → 'full' capability per the mapping in
            # services/format_detection.py:EXTRACTION_CAPABILITY.
            assert body["extraction_capability"] == "full"

    @pytest.mark.asyncio
    async def test_upload_status_404_on_wrong_project(
        self, client, project_id, tmp_path: Path,
    ):
        """firmware_id from a different project returns 404 (404-on-mismatch contract)."""
        async with make_live_db() as db:
            pid = uuid.uuid4()
            other_pid = uuid.uuid4()
            db.add(Project(id=pid, name="owner-proj", status="ready"))
            db.add(Project(id=other_pid, name="other-proj", status="ready"))
            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="c" * 64,
                storage_path=str(tmp_path / "y.bin"),
                upload_stage="ready",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db
            from app.services.firmware_service import FirmwareService
            app.dependency_overrides[get_firmware_service] = lambda: FirmwareService(db)

            # Ask for the firmware under the WRONG project — should 404.
            resp = await client.get(
                f"/api/v1/projects/{other_pid}/firmware/{firmware.id}/upload-status"
            )
            assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_capability_banner_for_acronis_backup(
        self, client, project_id, tmp_path: Path,
    ):
        """detected_format='acronis_backup' surfaces capability='none' + note.

        Verifies the round-trip through CAPABILITY_NOTES + EXTRACTION_CAPABILITY
        in services/format_detection.py — closes the value-flow contract per
        Rule #35b's 'mocks verify dispatch shape, not value flow' lesson.
        """
        async with make_live_db() as db:
            pid = uuid.uuid4()
            db.add(Project(id=pid, name="acronis-banner", status="ready"))
            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="e" * 64,
                storage_path=str(tmp_path / "backup.tibx"),
                upload_stage="ready",
                detected_format="acronis_backup",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db
            from app.services.firmware_service import FirmwareService
            app.dependency_overrides[get_firmware_service] = lambda: FirmwareService(db)

            resp = await client.get(
                f"/api/v1/projects/{pid}/firmware/{firmware.id}/upload-status"
            )
            assert resp.status_code == 200
            body = resp.json()
            assert body["extraction_capability"] == "none"
            assert body["capability_note"] is not None
            assert "Acronis" in body["capability_note"]


class TestUploadStageStateMachine:
    """Round-trip every legal upload_stage value through the live DB.

    Mirrors the vuln-scan precedent at test_sbom_router.py:932 — the
    DB CHECK constraint ``ck_firmware_upload_stage`` lives in the
    alembic migration (revision d2e3f4a5b6c7), not in the SQLAlchemy
    Base.metadata, so ``make_live_db``'s SQLite shim doesn't enforce it
    here. What the canary does verify: every legal stage round-trips
    through the ORM column without coercion, and the transitions match
    the ``UploadStage`` Literal contract on the response schema.

    PostgreSQL in production rejects out-of-band stage values via the
    CHECK constraint — the migration carries the authoritative
    enforcement. The Pydantic ``Literal`` on
    ``FirmwareUploadStatusResponse.upload_stage`` is the API-side gate.
    Together they implement Rule #33 (c)'s 'two gates' discipline.
    """

    @pytest.mark.asyncio
    async def test_every_legal_upload_stage_round_trips(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            db.add(Project(id=pid, name="stage-roundtrip", status="ready"))
            await db.flush()

            stages = [
                "uploading", "hashing", "detecting", "extracting",
                "analyzing", "ready", "failed",
            ]
            for stage in stages:
                firmware = Firmware(
                    id=uuid.uuid4(),
                    project_id=pid,
                    sha256=stage[:1] * 64,
                    storage_path=str(tmp_path / f"{stage}.bin"),
                    upload_stage=stage,
                )
                db.add(firmware)
                await db.flush()

                row = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware.id)
                    )
                ).scalar_one()
                assert row.upload_stage == stage, (
                    f"upload_stage='{stage}' did not round-trip; got "
                    f"'{row.upload_stage}' from the DB"
                )

    @pytest.mark.asyncio
    async def test_check_constraint_present_in_migration(self):
        """Verify the alembic migration declares ck_firmware_upload_stage.

        The constraint can't fire in the SQLite test shim (it's added by
        op.create_check_constraint, not by the ORM Base.metadata) — but
        the migration file IS the source of truth in production. This
        test guards against accidental constraint deletion in future
        migrations.
        """
        from pathlib import Path as _Path
        migration_dir = _Path(__file__).parent.parent / "alembic" / "versions"
        target = migration_dir / "d2e3f4a5b6c7_add_upload_stage_to_firmware.py"
        assert target.is_file(), f"migration not found: {target}"
        body = target.read_text()
        assert "ck_firmware_upload_stage" in body
        assert "create_check_constraint" in body
        # All seven legal stage values must appear in the migration's
        # UPLOAD_STAGE_VALUES tuple — the migration joins them at
        # runtime into the IN clause, so we check for the bare string
        # literal in the source rather than the rendered SQL.
        for stage in (
            "uploading", "hashing", "detecting", "extracting",
            "analyzing", "ready", "failed",
        ):
            assert f'"{stage}"' in body, (
                f"stage value '{stage}' missing from CHECK migration "
                "UPLOAD_STAGE_VALUES tuple"
            )
