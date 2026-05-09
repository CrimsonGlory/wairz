"""HTTP-layer tests for ``app.routers.files``.

Phase 2 Wave 3 file 3 of 5 — backfills router-level tests for
backend/app/routers/files.py (244 LOC, 6 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04. The router is the
firmware filesystem-browser surface — sandbox enforcement is the
critical security boundary.

Coverage targets:

* ``GET /``           — directory listing happy path; FileNotFoundError → 404.
* ``GET /read``       — happy path with byte content; PermissionError → 403.
* ``GET /info``       — file metadata happy path; FileNotFoundError → 404.
* ``GET /download``   — happy path streams file; "not a file" → 400;
  FileNotFoundError → 404; PermissionError → 403.
* ``GET /uefi-modules`` — returns is_uefi=False for non-UEFI extraction.
* ``GET /search``     — happy path returns matches + truncated flag.
* **Rule #35b live canary** — ``GET /download`` against a real on-disk
  file inside a real extraction dir, served via the real FileService
  (no mocks for the service layer). Verifies the byte content
  round-trips through FileResponse with the right Content-Disposition
  filename — the F-A-06-shape contract for binary downloads.

Per Rule #30 audit, ``FileService`` and ``_normalize_firmware_device_metadata``
are MODULE-imported at top of files.py (lines 10-11). Service-module
patches work for them. The ``get_file_service`` dependency is a
LOCAL closure-style helper that constructs FileService inline; tests
override it via ``app.dependency_overrides[get_file_service]``.
"""
from __future__ import annotations

import dataclasses
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep
from app.routers.files import get_file_service
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


def _firmware_mock(project_id: uuid.UUID, extracted_path: str) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.device_metadata = None
    return fw


# ===========================================================================
# GET / — list directory
# ===========================================================================


class TestListDirectory:
    @pytest.mark.asyncio
    async def test_returns_entries_with_truncated_flag(
        self, client, project_id,
    ):
        # Build minimal entries that match what list_directory returns
        # (a list of FileEntry dataclasses + truncation bool).
        fake_service = MagicMock()
        @dataclasses.dataclass
        class _Entry:
            name: str = "test.bin"
            path: str = "/test.bin"
            type: str = "file"
            size: int = 100
            permissions: str = "rwxr-xr-x"
            is_symlink: bool = False
            link_target: str | None = None

        fake_service.list_directory = MagicMock(
            return_value=([_Entry()], False),
        )

        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files",
            params={"path": "/"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["path"] == "/"
        assert body["truncated"] is False
        assert len(body["entries"]) == 1
        assert body["entries"][0]["name"] == "test.bin"

    @pytest.mark.asyncio
    async def test_file_not_found_returns_404(self, client, project_id):
        fake_service = MagicMock()
        fake_service.list_directory = MagicMock(
            side_effect=FileNotFoundError("path missing"),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files",
            params={"path": "/missing"},
        )
        assert resp.status_code == 404


# ===========================================================================
# GET /read
# ===========================================================================


class TestReadFile:
    @pytest.mark.asyncio
    async def test_permission_error_returns_403(self, client, project_id):
        fake_service = MagicMock()
        fake_service.read_file = MagicMock(
            side_effect=PermissionError("escapes sandbox"),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/read",
            params={"path": "/etc/shadow"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_returns_file_content(self, client, project_id):
        fake_service = MagicMock()
        @dataclasses.dataclass
        class _Content:
            content: str = "file body"
            encoding: str = "utf-8"
            size: int = 9
            offset: int = 0
            truncated: bool = False

        fake_service.read_file = MagicMock(return_value=_Content())
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/read",
            params={"path": "/etc/passwd"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["content"] == "file body"


# ===========================================================================
# GET /info
# ===========================================================================


class TestFileInfo:
    @pytest.mark.asyncio
    async def test_file_not_found_returns_404(self, client, project_id):
        fake_service = MagicMock()
        fake_service.file_info = MagicMock(
            side_effect=FileNotFoundError("missing"),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/info",
            params={"path": "/missing"},
        )
        assert resp.status_code == 404


# ===========================================================================
# GET /download
# ===========================================================================


class TestDownload:
    @pytest.mark.asyncio
    async def test_file_not_found_returns_404(self, client, project_id):
        fake_service = MagicMock()
        fake_service._resolve = MagicMock(
            side_effect=FileNotFoundError("nope"),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/download",
            params={"path": "/missing"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_permission_error_returns_403(self, client, project_id):
        fake_service = MagicMock()
        fake_service._resolve = MagicMock(
            side_effect=PermissionError("escape"),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/download",
            params={"path": "../escape"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_directory_returns_400(
        self, client, project_id, tmp_path: Path,
    ):
        """Path resolves but points to a directory, not a file → 400.
        The router's check is ``if not os.path.isfile(real_path)``."""
        fake_service = MagicMock()
        fake_service._resolve = MagicMock(return_value=str(tmp_path))
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/download",
            params={"path": "/some/dir"},
        )
        assert resp.status_code == 400
        assert "not a file" in resp.json()["detail"]


# ===========================================================================
# GET /uefi-modules
# ===========================================================================


class TestUefiModules:
    @pytest.mark.asyncio
    async def test_non_uefi_extraction_returns_empty(
        self, client, project_id, tmp_path: Path,
    ):
        """Extraction dir without .dump → modules=[], is_uefi=False."""
        fake_service = MagicMock()
        fake_service.extracted_root = str(tmp_path)
        fake_service.extraction_dir = str(tmp_path)
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/uefi-modules",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["modules"] == []
        assert body["total"] == 0
        assert body["is_uefi"] is False


# ===========================================================================
# GET /search
# ===========================================================================


class TestSearchFiles:
    @pytest.mark.asyncio
    async def test_returns_matches_and_truncated_flag(
        self, client, project_id,
    ):
        fake_service = MagicMock()
        fake_service.search_files = MagicMock(
            return_value=(["/usr/bin/foo", "/usr/bin/bar"], False),
        )
        app.dependency_overrides[get_file_service] = lambda: fake_service

        resp = await client.get(
            f"/api/v1/projects/{project_id}/files/search",
            params={"pattern": "*foo*", "path": "/"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["pattern"] == "*foo*"
        assert body["matches"] == ["/usr/bin/foo", "/usr/bin/bar"]
        assert body["truncated"] is False


# ===========================================================================
# Rule #35b LIVE-CANARY — /download streams real bytes
# ===========================================================================


class TestDownloadLiveCanary:
    """Rule #35b: ``GET /download`` invokes the REAL FileService against
    a REAL extraction dir + a REAL on-disk file. Asserts the byte content
    round-trips through FileResponse with a sensible filename in the
    Content-Disposition header. Mock-only tests would assert
    ``service._resolve.assert_called_with('/foo')`` and pass even if the
    response sent zero bytes — the F-A-06 shape applied to file streaming.
    """

    @pytest.mark.asyncio
    async def test_download_streams_real_file_bytes(self, tmp_path: Path):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            # Real extraction dir + real binary file.
            extracted = tmp_path / "rootfs"
            extracted.mkdir()
            (extracted / "etc").mkdir()
            target = extracted / "etc" / "hostname"
            target.write_bytes(b"wairz-test-host\n")

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="q" * 64,
                extracted_path=str(extracted),
                extraction_dir=str(extracted),
            )
            db.add(firmware)
            await db.flush()

            # Override get_db AND resolve_firmware so the chain uses real
            # objects. The router builds FileService internally via
            # get_file_service which depends on resolve_firmware.
            app.dependency_overrides[get_db] = lambda: db
            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                resp = await c.get(
                    f"/api/v1/projects/{pid}/files/download",
                    params={"path": "/etc/hostname"},
                )

            assert resp.status_code == 200, resp.text
            assert resp.content == b"wairz-test-host\n", (
                "Rule #35b: file bytes must stream unchanged through FileResponse"
            )
            disposition = resp.headers.get("content-disposition", "").lower()
            assert "hostname" in disposition, (
                f"Content-Disposition must include the basename; got: "
                f"{resp.headers.get('content-disposition')!r}"
            )

            # The seed row really exists (sanity check on the canary).
            persisted = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware.id),
                )
            ).scalar_one()
            assert persisted.project_id == pid
