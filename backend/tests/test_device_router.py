"""HTTP-layer tests for ``app.routers.device``.

Phase 2 Wave 4 file 3 of 5 — backfills router-level tests for
backend/app/routers/device.py (185 LOC, 7 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

Exercises the device-acquisition surface — wairz-device-bridge proxy +
the Rule #33a idempotent 202+polling dump-session pattern (POST /dumps
returns 409 if a dump for the project is already queued/running, NOT a
silent second runner).

Coverage targets:

* ``GET /status``                  — bridge status pass-through.
* ``GET /devices``                 — ConnectionError → 502.
* ``GET /devices/{id}/info``       — ConnectionError → 502; ValueError → 400.
* ``POST /dumps``                  — 409 when active dump exists;
  ConnectionError → 502; ValueError → 400.
* ``GET /dumps/{id}/status``       — 404 missing.
* ``POST /dumps/{id}/cancel``      — 404 missing.
* ``POST /import``                 — ValueError → 400; ConnectionError → 502.

Per Rule #30: ``DeviceService`` is MODULE-imported at top of device.py
(line 23). Service-module patches work for it. ``get_device_service``
is a LOCAL closure-style dependency — tests override via
``app.dependency_overrides[get_device_service]``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient

from app.database import get_db
from app.main import app
from app.models.device_dump import DeviceDumpSession  # noqa: F401 — registers
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.device import get_device_service


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


def _dump_row_mock(
    project_id: uuid.UUID, *, status: str = "queued",
) -> MagicMock:
    row = MagicMock(spec=DeviceDumpSession)
    row.id = uuid.uuid4()
    row.project_id = project_id
    row.device_id = "ABC123"
    row.status = status
    row.partitions = []
    row.bytes_written = 0
    row.total_bytes = None
    row.error = None
    row.started_at = None
    row.finished_at = None
    row.created_at = datetime.now(timezone.utc)
    return row


# ===========================================================================
# GET /status
# ===========================================================================


class TestBridgeStatus:
    @pytest.mark.asyncio
    async def test_returns_bridge_status_payload(self, client, project_id):
        svc = MagicMock()
        svc.get_bridge_status = AsyncMock(return_value={
            "connected": True,
            "bridge_host": "host.docker.internal",
            "bridge_port": 9998,
            "error": None,
        })
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.get(
            f"/api/v1/projects/{project_id}/device/status",
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["connected"] is True


# ===========================================================================
# GET /devices  + /devices/{id}/info
# ===========================================================================


class TestListDevices:
    @pytest.mark.asyncio
    async def test_bridge_unreachable_returns_502(self, client, project_id):
        svc = MagicMock()
        svc.list_devices = AsyncMock(side_effect=ConnectionError("bridge down"))
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.get(
            f"/api/v1/projects/{project_id}/device/devices",
        )
        assert resp.status_code == 502
        assert "bridge unreachable" in resp.json()["detail"].lower()


class TestDeviceInfo:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        svc = MagicMock()
        svc.get_device_info = AsyncMock(side_effect=ValueError("device offline"))
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.get(
            f"/api/v1/projects/{project_id}/device/devices/UNKNOWN/info",
        )
        assert resp.status_code == 400


# ===========================================================================
# POST /dumps — Rule #33a idempotency
# ===========================================================================


class TestStartDump:
    @pytest.mark.asyncio
    async def test_active_dump_returns_409_with_existing_id(
        self, client, project_id,
    ):
        """Rule #33a: 409 conflict when a dump is already in flight, NOT
        a silent second concurrent runner. The detail includes the
        existing dump_id so the frontend can resume polling."""
        active = _dump_row_mock(project_id, status="running")

        svc = MagicMock()
        svc.find_active_dump = AsyncMock(return_value=active)
        # start_dump should NOT be called when active is found.
        svc.start_dump = AsyncMock()
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/dumps",
            json={"device_id": "ABC123", "partitions": ["boot", "system"]},
        )
        assert resp.status_code == 409
        assert "already running" in resp.json()["detail"]
        assert str(active.id) in resp.json()["detail"]
        svc.start_dump.assert_not_called()

    @pytest.mark.asyncio
    async def test_bridge_unreachable_returns_502(self, client, project_id):
        svc = MagicMock()
        svc.find_active_dump = AsyncMock(return_value=None)
        svc.start_dump = AsyncMock(side_effect=ConnectionError("bridge down"))
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/dumps",
            json={"device_id": "ABC123", "partitions": ["boot"]},
        )
        assert resp.status_code == 502

    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        svc = MagicMock()
        svc.find_active_dump = AsyncMock(return_value=None)
        svc.start_dump = AsyncMock(side_effect=ValueError("invalid partition"))
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/dumps",
            json={"device_id": "ABC123", "partitions": ["bogus"]},
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_happy_path_returns_202_with_dump_status(
        self, client, project_id,
    ):
        new_dump = _dump_row_mock(project_id, status="queued")

        svc = MagicMock()
        svc.find_active_dump = AsyncMock(return_value=None)
        svc.start_dump = AsyncMock(return_value=new_dump)
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/dumps",
            json={"device_id": "ABC123", "partitions": ["boot"]},
        )
        assert resp.status_code == 202, resp.text
        body = resp.json()
        assert body["dump_id"] == str(new_dump.id)
        assert body["status"] == "queued"


# ===========================================================================
# GET /dumps/{id}/status + cancel
# ===========================================================================


class TestDumpStatus:
    @pytest.mark.asyncio
    async def test_missing_dump_returns_404(self, client, project_id):
        svc = MagicMock()
        svc.get_dump = AsyncMock(return_value=None)
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.get(
            f"/api/v1/projects/{project_id}/device/dumps/{uuid.uuid4()}/status",
        )
        assert resp.status_code == 404


class TestCancelDump:
    @pytest.mark.asyncio
    async def test_missing_dump_returns_404(self, client, project_id):
        svc = MagicMock()
        svc.cancel_dump = AsyncMock(return_value=None)
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/dumps/{uuid.uuid4()}/cancel",
        )
        assert resp.status_code == 404


# ===========================================================================
# POST /import
# ===========================================================================


class TestImportDump:
    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        svc = MagicMock()
        svc.import_dump = AsyncMock(side_effect=ValueError("dump incomplete"))
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/import",
            json={
                "dump_id": str(uuid.uuid4()),
                "device_id": "ABC123",
                "version_label": "1.0",
            },
        )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_happy_path_returns_201_with_firmware_id(
        self, client, project_id,
    ):
        firmware = MagicMock(spec=Firmware)
        firmware.id = uuid.uuid4()
        firmware.device_metadata = {
            "schema_version": 1,
            "manufacturer": "Acme",
            "model": "Router-9000",
        }

        svc = MagicMock()
        svc.import_dump = AsyncMock(return_value=firmware)
        app.dependency_overrides[get_device_service] = lambda: svc

        resp = await client.post(
            f"/api/v1/projects/{project_id}/device/import",
            json={
                "dump_id": str(uuid.uuid4()),
                "device_id": "ABC123",
                "version_label": "1.0",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert body["firmware_id"] == str(firmware.id)
        assert "Dump imported" in body["message"]
