"""Tests for the hardware-firmware router's new endpoints.

Covers:

* ``GET .../{blob_id}/download`` — happy path, missing blob (404), path
  escaping the firmware sandbox (403).
* ``GET .../cve-aggregate`` — severity breakdown fields populated.
* ``GET .../cves`` — CVE-centric aggregation returns one row per
  distinct CVE with affected blobs + formats rolled up.

These tests exercise the sandbox logic + schema contracts without
needing real firmware on disk — fixtures build a tmp tree and patch the
``resolve_firmware`` dependency so we can control what the router sees.
"""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import get_settings
from app.database import get_db
from app.main import app
from app.routers.deps import resolve_firmware as resolve_firmware_dep


def _make_firmware(project_id: uuid.UUID, extraction_dir: str) -> MagicMock:
    """Build a Firmware-shaped mock row for the dependency override."""
    fw = MagicMock()
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extraction_dir = extraction_dir
    fw.extracted_path = extraction_dir
    return fw


def _make_blob(firmware_id: uuid.UUID, blob_path: str) -> MagicMock:
    blob = MagicMock()
    blob.id = uuid.uuid4()
    blob.firmware_id = firmware_id
    blob.blob_path = blob_path
    blob.partition = None
    blob.blob_sha256 = "a" * 64
    blob.file_size = 1234
    blob.category = "tee"
    blob.vendor = "MediaTek"
    blob.format = "mtk_atf"
    blob.version = "v1.3"
    blob.signed = "signed"
    blob.signature_algorithm = None
    blob.cert_subject = None
    blob.chipset_target = None
    blob.driver_references = None
    blob.sbom_component_id = None
    blob.metadata_ = {}
    blob.detection_source = "magic"
    blob.detection_confidence = "high"
    blob.created_at = datetime.now(timezone.utc)
    return blob


@pytest.fixture
async def client():
    # Pre-attach X-API-Key so the APIKeyASGIMiddleware gate in
    # app/middleware/asgi_auth.py doesn't return 401 on every request.
    # get_settings() is @lru_cache'd and reads API_KEY from the container
    # env; tests that want to exercise the auth middleware itself should
    # use a different fixture.
    api_key = get_settings().api_key or ""
    headers = {"X-API-Key": api_key} if api_key else {}
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=headers,
    ) as c:
        yield c


@pytest.fixture
def project_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture(autouse=True)
def cleanup_overrides():
    """Reset dependency overrides after each test so they don't leak."""
    yield
    app.dependency_overrides.clear()


class TestDownloadBlob:
    """``GET .../{blob_id}/download`` sandbox enforcement."""

    @pytest.mark.asyncio
    async def test_happy_path_streams_file(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob path inside the firmware extraction_dir → 200 + file bytes."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        target = extraction_dir / "gz.img"
        target.write_bytes(b"GENIEZONE\x00\x01" * 100)

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(target))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 200, resp.text
        assert resp.content == target.read_bytes()
        assert "attachment" in resp.headers.get("content-disposition", "").lower()
        assert "gz.img" in resp.headers.get("content-disposition", "")

    @pytest.mark.asyncio
    async def test_missing_blob_returns_404(self, client, project_id, tmp_path: Path):
        firmware = _make_firmware(project_id, str(tmp_path))
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{uuid.uuid4()}/download"
        )
        assert resp.status_code == 404
        assert "Blob not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_path_escaping_sandbox_returns_403(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob path outside extraction_dir → 403 even if file exists."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        outside = tmp_path / "outside.bin"
        outside.write_bytes(b"escape")

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(outside))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 403
        assert "sandbox" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_symlink_to_outside_is_rejected(
        self, client, project_id, tmp_path: Path,
    ):
        """A symlink INSIDE extraction_dir that points OUTSIDE it must also
        be rejected — realpath collapses the link before the prefix check."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        outside = tmp_path / "secret.txt"
        outside.write_bytes(b"secret")
        link = extraction_dir / "looks-legit.img"
        os.symlink(str(outside), str(link))

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(link))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_missing_file_on_disk_returns_404(
        self, client, project_id, tmp_path: Path,
    ):
        """Blob row exists but its file was deleted → 404 (not a 200 with empty body)."""
        extraction_dir = tmp_path / "extract"
        extraction_dir.mkdir()
        phantom = extraction_dir / "vanished.img"
        # Intentionally do NOT create the file.

        firmware = _make_firmware(project_id, str(extraction_dir))
        blob = _make_blob(firmware.id, str(phantom))

        result = MagicMock()
        result.scalar_one_or_none.return_value = blob
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/{blob.id}/download"
        )
        assert resp.status_code == 404
        assert "missing" in resp.json()["detail"].lower()


class TestCveAggregateSeverity:
    """``GET .../cve-aggregate`` returns severity breakdown fields."""

    @pytest.mark.asyncio
    async def test_response_schema_includes_severity_breakdown(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))

        # No vulns in the DB → aggregate returns zero across the board.
        result = MagicMock()
        result.all.return_value = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/cve-aggregate"
        )
        assert resp.status_code == 200
        body = resp.json()
        for key in (
            "hw_firmware_cves",
            "kernel_cves",
            "advisory_count",
            "hw_severity_critical",
            "hw_severity_high",
            "hw_severity_medium",
            "hw_severity_low",
        ):
            assert key in body, f"aggregate missing '{key}' field"
            assert body[key] == 0


class TestListCves:
    """``GET .../cves`` returns the CVE-centric aggregation payload."""

    @pytest.mark.asyncio
    async def test_empty_firmware_returns_empty_list(
        self, client, project_id, tmp_path: Path,
    ):
        firmware = _make_firmware(project_id, str(tmp_path))
        result = MagicMock()
        result.all.return_value = []
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)
        app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/hardware-firmware/cves"
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body == {"cves": [], "total": 0}
