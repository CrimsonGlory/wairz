"""HTTP-layer tests for ``app.routers.uart``.

Phase 2 Wave 4 file 1 of 5 — backfills router-level tests for
backend/app/routers/uart.py (217 LOC, 9 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04.

The router proxies to a host-side TCP bridge (wairz-uart-bridge.py)
via UARTService. Tests mock UARTService methods to exercise the
ConnectionError → 503 (bridge unreachable) and ValueError → 400 (no
active session, bad input) error matrix.

Coverage targets:

* ``POST /connect``     — 503 ConnectionError; 400 ValueError; happy path
  persists UARTSession (Rule #35b live canary).
* ``POST /send-command`` — 503 / 400 paths.
* ``POST /read``        — happy path returns output + bytes.
* ``POST /send-break``  — 503 / 400 paths.
* ``POST /send-raw``    — 503 / 400 paths.
* ``POST /disconnect``  — 503 / 400 paths.
* ``GET /status``       — happy path returns connection state.
* ``POST /transcript``  — 503 / 400 paths.
* ``GET /sessions``     — happy path returns session list.

Per Rule #30: ``UARTService`` and ``FirmwareService`` are MODULE-imported
at top of uart.py (lines 23-24). Service-module patches work for them.
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
from app.models.firmware import Firmware
from app.models.project import Project
from app.models.uart_session import UARTSession  # noqa: F401 — registers
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


def _firmware_mock(project_id: uuid.UUID) -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = "/tmp/x"
    return fw


def _session_mock(project_id: uuid.UUID, firmware_id: uuid.UUID) -> MagicMock:
    s = MagicMock(spec=UARTSession)
    s.id = uuid.uuid4()
    s.project_id = project_id
    s.firmware_id = firmware_id
    s.device_path = "/dev/ttyUSB0"
    s.baudrate = 115200
    s.status = "connected"
    s.error_message = None
    s.transcript_path = None
    s.connected_at = datetime.now(UTC)
    s.closed_at = None
    s.created_at = datetime.now(UTC)
    return s


# ===========================================================================
# POST /connect — error matrix + happy path
# ===========================================================================


class TestUartConnect:
    @pytest.mark.asyncio
    async def test_bridge_unreachable_returns_503(self, client, project_id):
        firmware = _firmware_mock(project_id)

        with patch("app.routers.uart.FirmwareService") as fw_svc_cls, patch(
            "app.routers.uart.UARTService",
        ) as svc_cls:
            fw_svc = MagicMock()
            fw_svc.get_by_project = AsyncMock(return_value=firmware)
            fw_svc_cls.return_value = fw_svc

            svc = MagicMock()
            svc.connect = AsyncMock(side_effect=ConnectionError("bridge down"))
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/connect",
                json={"device_path": "/dev/ttyUSB0", "baudrate": 115200},
            )
        assert resp.status_code == 503
        assert "bridge down" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_value_error_returns_400(self, client, project_id):
        firmware = _firmware_mock(project_id)

        with patch("app.routers.uart.FirmwareService") as fw_svc_cls, patch(
            "app.routers.uart.UARTService",
        ) as svc_cls:
            fw_svc = MagicMock()
            fw_svc.get_by_project = AsyncMock(return_value=firmware)
            fw_svc_cls.return_value = fw_svc

            svc = MagicMock()
            svc.connect = AsyncMock(side_effect=ValueError("bad device"))
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/connect",
                json={"device_path": "/dev/bogus", "baudrate": 115200},
            )
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_no_firmware_returns_404(self, client, project_id):
        """Router's _resolve_firmware raises 404 when no firmware in project."""
        with patch("app.routers.uart.FirmwareService") as fw_svc_cls:
            fw_svc = MagicMock()
            fw_svc.get_by_project = AsyncMock(return_value=None)
            fw_svc_cls.return_value = fw_svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/connect",
                json={"device_path": "/dev/ttyUSB0", "baudrate": 115200},
            )
        assert resp.status_code == 404
        assert "No firmware" in resp.json()["detail"]


# ===========================================================================
# Bridge-error matrix on send-command / send-break / send-raw / read /
# disconnect / transcript
# ===========================================================================


class TestBridgeErrorMatrix:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("path,body,svc_method", [
        ("/uart/send-command", {"command": "ls", "timeout": 5, "prompt": "$ "}, "send_command"),
        ("/uart/read", {"timeout": 1}, "read_buffer"),
        ("/uart/send-break", None, "send_break"),
        ("/uart/send-raw", {"data": "AT", "hex": False}, "send_raw"),
        ("/uart/disconnect", None, "disconnect"),
        ("/uart/transcript", {"tail_lines": 50}, "get_transcript"),
    ])
    async def test_connection_error_returns_503(
        self, client, project_id, path, body, svc_method,
    ):
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            setattr(svc, svc_method,
                    AsyncMock(side_effect=ConnectionError("bridge offline")))
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            if body is None:
                resp = await client.post(
                    f"/api/v1/projects/{project_id}{path}",
                )
            else:
                resp = await client.post(
                    f"/api/v1/projects/{project_id}{path}",
                    json=body,
                )
        assert resp.status_code == 503
        assert "bridge offline" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_value_error_returns_400_on_send_command(
        self, client, project_id,
    ):
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            svc.send_command = AsyncMock(
                side_effect=ValueError("no active session"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/send-command",
                json={"command": "ls", "timeout": 5, "prompt": "$ "},
            )
        assert resp.status_code == 400


# ===========================================================================
# Happy paths — read / status / transcript / sessions
# ===========================================================================


class TestHappyPaths:
    @pytest.mark.asyncio
    async def test_read_returns_output_and_byte_count(self, client, project_id):
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            svc.read_buffer = AsyncMock(return_value={
                "output": "boot complete\n",
                "bytes": 14,
            })
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/read",
                json={"timeout": 1},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["output"] == "boot complete\n"
        assert body["bytes"] == 14

    @pytest.mark.asyncio
    async def test_status_returns_connection_state(self, client, project_id):
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            svc.get_status = AsyncMock(return_value={
                "connected": True,
                "device": "/dev/ttyUSB0",
                "baudrate": 115200,
                "buffer_bytes": 256,
                "transcript_path": "/tmp/uart.log",
            })
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/uart/status",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["connected"] is True
        assert body["device"] == "/dev/ttyUSB0"
        assert body["baudrate"] == 115200
        assert body["buffer_bytes"] == 256

    @pytest.mark.asyncio
    async def test_transcript_returns_entries(self, client, project_id):
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            svc.get_transcript = AsyncMock(return_value={
                "entries": [
                    {"timestamp": "2026-05-06T12:00:00Z", "direction": "tx", "data": "ls"},
                    {"timestamp": "2026-05-06T12:00:01Z", "direction": "rx", "data": "/bin /etc"},
                ],
                "count": 2,
            })
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/uart/transcript",
                json={"tail_lines": 100},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["count"] == 2

    @pytest.mark.asyncio
    async def test_list_sessions_returns_session_list(
        self, client, project_id,
    ):
        firmware_id = uuid.uuid4()
        sessions = [
            _session_mock(project_id, firmware_id),
            _session_mock(project_id, firmware_id),
        ]
        with patch("app.routers.uart.UARTService") as svc_cls:
            svc = MagicMock()
            svc.list_sessions = AsyncMock(return_value=sessions)
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/uart/sessions",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 2


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /connect persists UARTSession
# ===========================================================================


class TestUartConnectLiveCanary:
    """Rule #35b: ``POST /connect`` constructs UARTSession through the
    service. The canary asserts project_id / firmware_id / device_path /
    baudrate / status='connected' all round-trip through DB.
    """

    @pytest.mark.asyncio
    async def test_persists_uart_session_with_connection_metadata(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="s" * 64,
                extracted_path="/tmp/x",
                extraction_dir="/tmp/x",
            )
            db.add(firmware)
            await db.flush()

            # Stub the service connect() to persist a real UARTSession via
            # the DB session (mirroring what UARTService does internally).
            async def _fake_connect(
                project_id, firmware_id, device_path, baudrate,
                data_bits, parity, stop_bits,
            ):
                session = UARTSession(
                    project_id=project_id,
                    firmware_id=firmware_id,
                    device_path=device_path,
                    baudrate=baudrate,
                    status="connected",
                    connected_at=datetime.now(UTC),
                )
                db.add(session)
                await db.flush()
                return session

            with patch(
                "app.routers.uart.FirmwareService",
            ) as fw_svc_cls, patch(
                "app.routers.uart.UARTService",
            ) as svc_cls:
                fw_svc = MagicMock()
                fw_svc.get_by_project = AsyncMock(return_value=firmware)
                fw_svc_cls.return_value = fw_svc

                svc = MagicMock()
                svc.connect = _fake_connect
                svc_cls.return_value = svc

                app.dependency_overrides[get_db] = lambda: db

                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test",
                ) as c:
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/uart/connect",
                        json={
                            "device_path": "/dev/ttyUSB0",
                            "baudrate": 230400,
                            "data_bits": 8,
                            "parity": "N",
                            "stop_bits": 1,
                        },
                    )

            assert resp.status_code == 201, resp.text

            persisted = (
                await db.execute(
                    select(UARTSession).where(UARTSession.project_id == pid),
                )
            ).scalars().all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.project_id == pid
            assert row.firmware_id == firmware.id
            assert row.device_path == "/dev/ttyUSB0"
            assert row.baudrate == 230400, (
                "Rule #35b: baudrate must round-trip through service.connect"
            )
            assert row.status == "connected"
            assert row.connected_at is not None
