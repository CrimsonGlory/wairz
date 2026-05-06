"""HTTP-layer tests for ``app.routers.emulation``.

Phase 2 Wave 2 file 3 of 5 — backfills router-level tests for the
emulation router (966 LOC, 22 endpoints) per intake
audit-test-coverage-routers-services-2026-05-04. The router covers:

- 7 user-mode REST: start (202+polling), delete, stop, exec, list, status, logs
- 5 preset CRUD: POST/GET/GET-one/PATCH/DELETE
- 8 system-mode REST: start, status, services, stop, command, capture,
  pcap-download, network-analysis, nvram
- 1 WebSocket terminal endpoint — covered separately in test_terminal_router.py
  (Phase 1) so this file does NOT duplicate the auth/lifespan-race tests.

Coverage targets:

* Cross-project boundary — every endpoint that takes a session_id or
  preset_id verifies it belongs to the URL's project_id; mismatch → 404.
* POST /start — ValueError → 400; happy-path returns 202 + EmulationSession
  with status='pending' (Rule #35b live canary).
* POST /presets — happy-path returns 201 + EmulationPreset row with the
  exact fields the router constructs (Rule #35b live canary on the
  preset CRUD path).
* GET /sessions — list response with optional status refresh.
* POST /system — ValueError → 400; status surfaces unchanged.
* GET /system/{id}/pcap — no-pcap-path 404; missing-file 404.

Per Rule #30, ``EmulationService``, ``SystemEmulationService``,
``PcapAnalysisService``, ``get_settings`` are all MODULE-imported at top
of emulation.py (lines 14-41) — patches target the consumer module.
``async_session_factory`` is module-imported but only used in the
WebSocket terminal handler (out of scope here). ``_get_arq_pool`` is
module-scope helper at emulation.py:62 — patch
``app.routers.emulation._get_arq_pool``.
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
from app.models.emulation_preset import EmulationPreset  # noqa: F401 — registers table
from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.models.project import Project
from app.rate_limit import limiter
from app.routers.deps import resolve_firmware as resolve_firmware_dep

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


def _make_firmware(project_id: uuid.UUID, extracted_path: str = "/tmp/x") -> MagicMock:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.project_id = project_id
    fw.extracted_path = extracted_path
    fw.extraction_dir = extracted_path
    fw.architecture = "arm"
    fw.storage_path = "/data/firmware/test.bin"
    fw.device_metadata = None
    return fw


def _session_db_mock(session: EmulationSession | MagicMock | None) -> AsyncMock:
    """db.execute returns a result whose scalar_one_or_none yields ``session``."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = session
    db = AsyncMock()
    db.execute = AsyncMock(return_value=result)
    db.flush = AsyncMock()
    db.commit = AsyncMock()
    db.add = MagicMock()
    return db


# ===========================================================================
# Cross-project boundary — every endpoint must reject session_id from
# a different project as 404 (NOT leak that the session exists).
# ===========================================================================


class TestCrossProjectBoundary:
    @pytest.mark.asyncio
    async def test_status_rejects_session_in_different_project_as_404(
        self, client, project_id,
    ):
        # Session belongs to OTHER project, not URL project.
        other_session = MagicMock(spec=EmulationSession)
        other_session.id = uuid.uuid4()
        other_session.project_id = uuid.uuid4()  # different project

        db = _session_db_mock(other_session)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/{other_session.id}/status",
        )
        assert resp.status_code == 404
        assert "Session not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_stop_rejects_missing_session_as_404(
        self, client, project_id,
    ):
        db = _session_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/emulation/{uuid.uuid4()}/stop",
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_logs_rejects_missing_session_as_404(
        self, client, project_id,
    ):
        db = _session_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/{uuid.uuid4()}/logs",
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_exec_rejects_missing_session_as_404(
        self, client, project_id,
    ):
        db = _session_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.post(
            f"/api/v1/projects/{project_id}/emulation/{uuid.uuid4()}/exec",
            json={"command": "ls /"},
        )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_rejects_missing_session_as_404(
        self, client, project_id,
    ):
        db = _session_db_mock(None)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.delete(
            f"/api/v1/projects/{project_id}/emulation/{uuid.uuid4()}",
        )
        assert resp.status_code == 404


# ===========================================================================
# POST /start — 202 + ValueError → 400
# ===========================================================================


class TestStartEmulation:
    @pytest.mark.asyncio
    async def test_invalid_input_returns_400(self, client, project_id):
        firmware = _make_firmware(project_id)
        db = AsyncMock()
        db.commit = AsyncMock()

        # EmulationService.create_pending_session raises ValueError on
        # things like missing binary_path for user-mode.
        with patch(
            "app.routers.emulation.EmulationService",
        ) as svc_cls:
            svc = MagicMock()
            svc.create_pending_session = AsyncMock(
                side_effect=ValueError("binary_path required"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            resp = await client.post(
                f"/api/v1/projects/{project_id}/emulation/start",
                json={"mode": "user"},
            )
        assert resp.status_code == 400
        assert "binary_path required" in resp.json()["detail"]


# ===========================================================================
# GET /sessions — happy path
# ===========================================================================


class TestListSessions:
    @pytest.mark.asyncio
    async def test_returns_session_list(self, client, project_id):
        firmware = _make_firmware(project_id)
        # Build a session that's already in a terminal status so
        # list_sessions does NOT call get_status on it (avoids extra mock).
        session = MagicMock(spec=EmulationSession)
        session.id = uuid.uuid4()
        session.project_id = project_id
        session.firmware_id = firmware.id
        session.mode = "user"
        session.status = "stopped"
        session.architecture = "arm"
        session.binary_path = "/bin/test"
        session.arguments = None
        session.port_forwards = []
        session.container_id = None
        session.error_message = None
        session.logs = None
        session.started_at = datetime.now(timezone.utc)
        session.stopped_at = datetime.now(timezone.utc)
        session.created_at = datetime.now(timezone.utc)
        session.discovered_services = None
        session.system_emulation_stage = None
        session.kernel_used = None
        session.firmware_ip = None
        session.nvram_state = None
        session.idle_since = None
        session.pcap_path = None

        with patch(
            "app.routers.emulation.EmulationService",
        ) as svc_cls:
            svc = MagicMock()
            svc.list_sessions = AsyncMock(return_value=[session])
            svc_cls.return_value = svc

            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.get(
                f"/api/v1/projects/{project_id}/emulation/sessions",
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert len(body) == 1
        assert body[0]["status"] == "stopped"


# ===========================================================================
# Preset CRUD
# ===========================================================================


class TestPresetCRUD:
    @pytest.mark.asyncio
    async def test_get_preset_rejects_wrong_project_as_404(
        self, client, project_id,
    ):
        # Preset belongs to OTHER project.
        other_preset = MagicMock(spec=EmulationPreset)
        other_preset.id = uuid.uuid4()
        other_preset.project_id = uuid.uuid4()

        result = MagicMock()
        result.scalar_one_or_none.return_value = other_preset
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/presets/{other_preset.id}",
        )
        assert resp.status_code == 404
        assert "Preset not found" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_delete_preset_404_when_not_found(
        self, client, project_id,
    ):
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        db = AsyncMock()
        db.execute = AsyncMock(return_value=result)

        app.dependency_overrides[get_db] = lambda: db

        resp = await client.delete(
            f"/api/v1/projects/{project_id}/emulation/presets/{uuid.uuid4()}",
        )
        assert resp.status_code == 404


# ===========================================================================
# System emulation REST
# ===========================================================================


class TestSystemEmulation:
    @pytest.mark.asyncio
    async def test_start_system_value_error_returns_400(
        self, client, project_id,
    ):
        firmware = _make_firmware(project_id)
        with patch(
            "app.routers.emulation.SystemEmulationService",
        ) as svc_cls:
            svc = MagicMock()
            svc.start_system_emulation = AsyncMock(
                side_effect=ValueError("already running"),
            )
            svc_cls.return_value = svc

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: AsyncMock()

            resp = await client.post(
                f"/api/v1/projects/{project_id}/emulation/system",
                json={"brand": "netgear", "timeout": 600},
            )
        assert resp.status_code == 400
        assert "already running" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_pcap_download_404_when_no_pcap_path(
        self, client, project_id,
    ):
        session = MagicMock(spec=EmulationSession)
        session.id = uuid.uuid4()
        session.project_id = project_id
        session.pcap_path = None  # No capture yet.

        db = _session_db_mock(session)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/system/{session.id}/pcap",
        )
        assert resp.status_code == 404
        assert "No pcap" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_pcap_download_404_when_file_missing_on_disk(
        self, client, project_id, tmp_path: Path,
    ):
        session = MagicMock(spec=EmulationSession)
        session.id = uuid.uuid4()
        session.project_id = project_id
        # Path that does NOT exist on disk.
        session.pcap_path = str(tmp_path / "ghost.pcap")

        db = _session_db_mock(session)
        app.dependency_overrides[get_db] = lambda: db

        resp = await client.get(
            f"/api/v1/projects/{project_id}/emulation/system/{session.id}/pcap",
        )
        assert resp.status_code == 404
        assert "Pcap file not found" in resp.json()["detail"]


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /presets writes EmulationPreset row
# ===========================================================================


class TestCreatePresetLiveCanary:
    """Rule #35b: ``POST /presets`` constructs an EmulationPreset row via
    EmulationPresetService. The canary asserts every constructor field
    round-trips through the JSONB ``port_forwards`` column AND the simple
    string columns. Mock-only tests would assert ``svc.create_preset.
    assert_called_once_with(name='X', mode='user', ...)`` and pass even
    if the service silently dropped ``stub_profile`` (the F-A-06 shape).
    """

    @pytest.mark.asyncio
    async def test_persists_preset_with_all_request_fields(self):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            app.dependency_overrides[get_db] = lambda: db

            payload = {
                "name": "Test Preset",
                "description": "User-mode test profile",
                "mode": "user",
                "binary_path": "/bin/busybox",
                "arguments": "ash -i",
                "architecture": "arm",
                "port_forwards": [
                    {"host": 8080, "guest": 80},
                ],
                "kernel_name": None,
                "init_path": None,
                "pre_init_script": None,
                "stub_profile": "generic",
            }

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test",
            ) as c:
                resp = await c.post(
                    f"/api/v1/projects/{pid}/emulation/presets",
                    json=payload,
                )

            assert resp.status_code == 201, resp.text

            persisted = (
                await db.execute(
                    select(EmulationPreset).where(EmulationPreset.project_id == pid),
                )
            ).scalars().all()
            assert len(persisted) == 1
            row = persisted[0]
            assert row.name == "Test Preset"
            assert row.description == "User-mode test profile"
            assert row.mode == "user"
            assert row.binary_path == "/bin/busybox"
            assert row.arguments == "ash -i"
            assert row.architecture == "arm"
            assert row.kernel_name is None
            assert row.stub_profile == "generic", (
                "Rule #35b: stub_profile must round-trip through preset constructor — "
                "F-A-06 shape would silently drop optional Literal fields"
            )
            # JSONB port_forwards round-trip — single entry, exact shape.
            assert row.port_forwards == [
                {"host": 8080, "guest": 80},
            ]


# ===========================================================================
# Rule #35b LIVE-CANARY — POST /start persists pending EmulationSession
# ===========================================================================


class TestStartEmulationLiveCanary:
    """Rule #35b: ``POST /start`` returns 202 with status='pending' AND
    persists an EmulationSession row that the background task can pick up.
    The canary verifies firmware_id, mode, status, binary_path, port_forwards
    all round-trip — the shape that gates the 202+polling pattern (Rule #33).
    """

    @pytest.mark.asyncio
    async def test_persists_pending_session_with_correct_fields(
        self, tmp_path: Path,
    ):
        async with make_live_db() as db:
            pid = uuid.uuid4()
            project = Project(id=pid, name="canary", status="ready")
            db.add(project)
            await db.flush()

            extracted_path = tmp_path / "extract"
            extracted_path.mkdir()
            (extracted_path / "bin").mkdir()
            (extracted_path / "bin" / "busybox").write_bytes(b"\x7fELF" + b"\x00" * 100)

            firmware = Firmware(
                id=uuid.uuid4(),
                project_id=pid,
                sha256="k" * 64,
                extracted_path=str(extracted_path),
                extraction_dir=str(extracted_path),
                architecture="arm",
            )
            db.add(firmware)
            await db.flush()

            app.dependency_overrides[resolve_firmware_dep] = lambda: firmware
            app.dependency_overrides[get_db] = lambda: db

            # Stub _get_arq_pool to return None (forces the in-process
            # asyncio.create_task fallback). Stub the background task so
            # it doesn't actually start Docker.
            async def _noop_background(*args, **kwargs):
                return None

            with patch(
                "app.routers.emulation._get_arq_pool",
                new=AsyncMock(return_value=None),
            ), patch(
                "app.routers.emulation._run_spawn_background",
                _noop_background,
            ):
                async with AsyncClient(
                    transport=ASGITransport(app=app), base_url="http://test",
                ) as c:
                    resp = await c.post(
                        f"/api/v1/projects/{pid}/emulation/start",
                        json={
                            "mode": "user",
                            "binary_path": "bin/busybox",
                            "arguments": "ash -i",
                            "port_forwards": [
                                {"host": 1234, "guest": 4321},
                            ],
                        },
                    )

            assert resp.status_code == 202, resp.text
            body = resp.json()
            assert body["status"] == "pending"

            # Real SELECT — Rule #33's idempotency contract requires the
            # row to actually exist so the background task can find it.
            persisted = (
                await db.execute(
                    select(EmulationSession).where(
                        EmulationSession.project_id == pid,
                    )
                )
            ).scalars().all()
            assert len(persisted) == 1, (
                "Rule #35b: POST /start must persist EXACTLY one pending row"
            )
            row = persisted[0]
            assert row.firmware_id == firmware.id
            assert row.mode == "user"
            assert row.status == "pending"
            assert row.binary_path == "bin/busybox"
            assert row.arguments == "ash -i"
            assert row.architecture == "arm"
            assert row.port_forwards == [
                {"host": 1234, "guest": 4321},
            ]
