"""HTTP-layer tests for ``app.routers.comparison``.

Phase 2 Wave 3 file 2 of 5 — backfills router-level tests for
backend/app/routers/comparison.py (251 LOC, 5 diff endpoints) per
intake audit-test-coverage-routers-services-2026-05-04.

The router has its own ``_get_firmware`` helper (not the shared
``resolve_firmware`` dependency) that fetches firmware by ID, verifies
project ownership (404 on cross-project), and rejects un-extracted
firmware (400). Tests focus on the validation surface + the
``validate_path`` 404 boundaries; the actual diff computation is
handled by the comparison_service tests.

Coverage targets:

* ``_get_firmware`` — 404 missing; 404 cross-project; 400 un-extracted.
* ``POST /firmware``       — both-firmware validation paths.
* ``POST /binary``         — 404 binary-not-in-A; 404 binary-not-in-B.
* ``POST /text``           — both-paths-missing returns error response.
* ``POST /instructions``   — 404 binary-not-in-A.
* ``POST /decompilation``  — 404 binary-not-in-A.
* **Rule #35b live canary** — cross-project boundary on ``POST /firmware``
  uses a real Firmware row in project A; request via project B URL → 404.
  The canary asserts the boundary catches even when the firmware row
  exists (NOT just when the row is None) — the security-relevant
  value-flow contract.

Per Rule #30: ``diff_*`` functions and ``FirmwareService`` are MODULE-imported
at top of comparison.py (lines 22-30). Service-module patches work for them.
``validate_path`` is also module-imported — patch
``app.routers.comparison.validate_path`` for direct interception.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.firmware import Firmware
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


def _firmware_mock(project_id: uuid.UUID, *, extracted_path: str | None = "/tmp/x") -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    return fw


def _make_firmware_service_mock(*firmwares: MagicMock | None) -> MagicMock:
    """FirmwareService mock that yields given firmwares from sequential
    get_by_id calls. Used for the two-firmware diff endpoints."""
    queue = list(firmwares)

    async def _get_by_id(firmware_id):
        if queue:
            return queue.pop(0)
        return None

    svc = MagicMock()
    svc.get_by_id = _get_by_id
    return svc


# ===========================================================================
# _get_firmware helper — 404 + 400 paths
# ===========================================================================


class TestGetFirmwareValidation:
    @pytest.mark.asyncio
    async def test_missing_firmware_returns_404(self, client, project_id):
        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls:
            svc_cls.return_value = _make_firmware_service_mock(None)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/firmware",
                json={
                    "firmware_a_id": str(uuid.uuid4()),
                    "firmware_b_id": str(uuid.uuid4()),
                },
            )
        assert resp.status_code == 404
        assert "not found in project" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_cross_project_firmware_returns_404(self, client, project_id):
        """Firmware exists but belongs to a DIFFERENT project — must
        404, not leak the row's existence."""
        other_project_firmware = _firmware_mock(project_id=uuid.uuid4())
        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls:
            svc_cls.return_value = _make_firmware_service_mock(other_project_firmware)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/firmware",
                json={
                    "firmware_a_id": str(other_project_firmware.id),
                    "firmware_b_id": str(uuid.uuid4()),
                },
            )
        assert resp.status_code == 404
        assert "not found in project" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_unextracted_firmware_returns_400(self, client, project_id):
        firmware_unpacked = _firmware_mock(project_id, extracted_path=None)
        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls:
            svc_cls.return_value = _make_firmware_service_mock(firmware_unpacked)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/firmware",
                json={
                    "firmware_a_id": str(firmware_unpacked.id),
                    "firmware_b_id": str(uuid.uuid4()),
                },
            )
        assert resp.status_code == 400
        assert "not yet unpacked" in resp.json()["detail"]


# ===========================================================================
# POST /firmware — happy path
# ===========================================================================


class TestCompareFirmware:
    @pytest.mark.asyncio
    async def test_returns_firmware_diff_response(self, client, project_id):
        fw_a = _firmware_mock(project_id, extracted_path="/tmp/a")
        fw_b = _firmware_mock(project_id, extracted_path="/tmp/b")

        # Build a fake DiffResult shape.
        diff_result = MagicMock()
        diff_result.added = []
        diff_result.removed = []
        diff_result.modified = []
        diff_result.permissions_changed = []
        diff_result.total_files_a = 100
        diff_result.total_files_b = 110
        diff_result.truncated = False

        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls, patch(
            "app.routers.comparison.diff_filesystems",
            return_value=diff_result,
        ):
            svc_cls.return_value = _make_firmware_service_mock(fw_a, fw_b)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/firmware",
                json={
                    "firmware_a_id": str(fw_a.id),
                    "firmware_b_id": str(fw_b.id),
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["total_files_a"] == 100
        assert body["total_files_b"] == 110
        assert body["truncated"] is False


# ===========================================================================
# POST /binary — sandbox 404
# ===========================================================================


class TestCompareBinary:
    @pytest.mark.asyncio
    async def test_binary_not_in_firmware_a_returns_404(
        self, client, project_id,
    ):
        fw_a = _firmware_mock(project_id, extracted_path="/tmp/a")
        fw_b = _firmware_mock(project_id, extracted_path="/tmp/b")

        # validate_path raises on the first call (firmware A).
        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls, patch(
            "app.routers.comparison.validate_path",
            side_effect=Exception("escapes sandbox"),
        ):
            svc_cls.return_value = _make_firmware_service_mock(fw_a, fw_b)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/binary",
                json={
                    "firmware_a_id": str(fw_a.id),
                    "firmware_b_id": str(fw_b.id),
                    "binary_path": "/bin/missing",
                },
            )
        assert resp.status_code == 404
        assert "Binary not found in firmware A" in resp.json()["detail"]


# ===========================================================================
# POST /text — both files missing returns error response (NOT 404)
# ===========================================================================


class TestCompareText:
    @pytest.mark.asyncio
    async def test_both_files_missing_returns_error_response(
        self, client, project_id,
    ):
        """When the file is missing in BOTH firmware versions, the router
        returns a 200 with ``error="File not found in either firmware version"``
        instead of 404. Frontend can render the message inline."""
        fw_a = _firmware_mock(project_id, extracted_path="/tmp/a")
        fw_b = _firmware_mock(project_id, extracted_path="/tmp/b")

        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls, patch(
            "app.routers.comparison.validate_path",
            side_effect=Exception("not found"),
        ):
            svc_cls.return_value = _make_firmware_service_mock(fw_a, fw_b)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/text",
                json={
                    "firmware_a_id": str(fw_a.id),
                    "firmware_b_id": str(fw_b.id),
                    "file_path": "/etc/missing.conf",
                },
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["path"] == "/etc/missing.conf"
        assert "either firmware" in body["error"]
        assert body["diff"] == ""


# ===========================================================================
# POST /instructions + /decompilation — sandbox 404
# ===========================================================================


class TestCompareInstructions:
    @pytest.mark.asyncio
    async def test_binary_not_in_firmware_a_returns_404(
        self, client, project_id,
    ):
        fw_a = _firmware_mock(project_id, extracted_path="/tmp/a")
        fw_b = _firmware_mock(project_id, extracted_path="/tmp/b")

        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls, patch(
            "app.routers.comparison.validate_path",
            side_effect=Exception("escape"),
        ):
            svc_cls.return_value = _make_firmware_service_mock(fw_a, fw_b)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/instructions",
                json={
                    "firmware_a_id": str(fw_a.id),
                    "firmware_b_id": str(fw_b.id),
                    "binary_path": "/bin/missing",
                    "function_name": "main",
                },
            )
        assert resp.status_code == 404


class TestCompareDecompilation:
    @pytest.mark.asyncio
    async def test_binary_not_in_firmware_a_returns_404(
        self, client, project_id,
    ):
        fw_a = _firmware_mock(project_id, extracted_path="/tmp/a")
        fw_b = _firmware_mock(project_id, extracted_path="/tmp/b")

        with patch(
            "app.routers.comparison.FirmwareService",
        ) as svc_cls, patch(
            "app.routers.comparison.validate_path",
            side_effect=Exception("escape"),
        ):
            svc_cls.return_value = _make_firmware_service_mock(fw_a, fw_b)
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/compare/decompilation",
                json={
                    "firmware_a_id": str(fw_a.id),
                    "firmware_b_id": str(fw_b.id),
                    "binary_path": "/bin/missing",
                    "function_name": "main",
                    "context_lines": 3,
                },
            )
        assert resp.status_code == 404


# ===========================================================================
# Rule #35b LIVE-CANARY — cross-project boundary
# ===========================================================================


class TestCrossProjectBoundaryLiveCanary:
    """Rule #35b: ``_get_firmware``'s cross-project check (line 47) is a
    security boundary — a Firmware in project A must NOT be returned via
    project B's URL even though the row exists. A mock-only test would
    seed a `MagicMock(project_id=other_uuid)` which trivially matches; the
    canary uses a REAL Firmware row whose `project_id` is set in the DB
    and verifies the boundary catches even when the fetch succeeds.
    """

    @pytest.mark.asyncio
    async def test_firmware_in_other_project_returns_404(self):
        async with make_live_db() as db:
            # Two real projects.
            project_a = Project(id=uuid.uuid4(), name="A", status="ready")
            project_b = Project(id=uuid.uuid4(), name="B", status="ready")
            db.add(project_a)
            db.add(project_b)
            await db.flush()

            # Firmware belongs to project A.
            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=project_a.id,
                sha256="p" * 64,
                extracted_path="/tmp/extract",
                extraction_dir="/tmp/extract",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            # Request via project B's URL — boundary must reject.
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                resp = await c.post(
                    f"/api/v1/projects/{project_b.id}/compare/firmware",
                    json={
                        "firmware_a_id": str(firmware.id),
                        "firmware_b_id": str(firmware.id),
                    },
                )

            assert resp.status_code == 404, (
                f"Rule #35b: cross-project boundary must reject Firmware "
                f"(id={firmware.id}, project_a={project_a.id}) when "
                f"requested via project_b={project_b.id}; got {resp.status_code}"
            )
            assert "not found in project" in resp.json()["detail"]
