"""Service-layer tests for ``app.services.system_emulation_service``.

Phase 2 Wave 1 file 4 of 5 — backfills service-layer tests for the
FirmAE system emulation orchestrator (772 LOC, 11 public methods + 4
internal helpers) per intake audit-test-coverage-routers-services-2026-05-04.

The service spawns a privileged Docker sidecar (FirmAE pipeline) and
communicates with its Flask shim over httpx. Tests mock at the service
boundary (Docker SDK calls + httpx client) so the actual sidecar never
launches; the live-canary discipline focuses on EmulationSession row
state transitions through ``start_system_emulation`` and
``stop_system_emulation``.

Coverage targets:

* ``_count_active_system_sessions`` — counts only ``mode='system-full'``
  sessions in pending/starting/running states.
* ``start_system_emulation`` — no_storage_path raises ValueError;
  concurrent-session raises ValueError; happy-path persists EmulationSession
  with mode='system-full', status flowing pending → starting + container_id
  set + started_at set (Rule #35b live canary).
* ``poll_system_status`` — session-not-found raises; wrong-mode raises;
  no-container-id raises; terminal-states (stopped/error) short-circuit.
* ``get_firmware_services`` — session-not-found / no-container-id raise.
* ``stop_system_emulation`` — session-not-found raises; no_container_id
  short-circuits to status=stopped + stopped_at (live canary).
* ``run_command_in_firmware`` — session-not-found / not-running /
  no-container-id raise.
* ``get_nvram_state`` + ``interact_web_endpoint`` + ``capture_network_traffic``
  — guard-clause coverage.

Per Rule #30, ``get_docker_client`` and ``get_settings`` are MODULE-imported
at the top of system_emulation_service.py (lines 19, 23) — the service-
module patch path works for them. ``httpx.AsyncClient`` is also module-
imported — patch at ``app.services.system_emulation_service.httpx``.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import select

from app.models.emulation_session import EmulationSession  # noqa: F401 — registers table
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.system_emulation_service import SystemEmulationService

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _seed_project_firmware(db, *, with_storage: bool = True) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="sysemu-test", status="ready")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="g" * 64,
        extracted_path="/tmp/extract",
        extraction_dir="/tmp/extract",
        storage_path="/data/firmware/test.bin" if with_storage else None,
        architecture="arm",
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _fake_docker_client_for_start(container_id: str = "c0ffee123") -> MagicMock:
    """Build a Docker SDK mock that supports the start_system_emulation flow.

    Covers: networks.get / networks.create, containers.run, container.attrs
    with the NetworkSettings shape _wait_for_shim expects.
    """
    container = MagicMock()
    container.id = container_id
    container.attrs = {
        "NetworkSettings": {
            "Networks": {"emulation_net": {"IPAddress": "172.20.0.5"}},
            "Ports": {},
        },
    }
    container.reload = MagicMock()

    networks_mock = MagicMock()
    networks_mock.get = MagicMock(return_value=MagicMock())  # net exists
    networks_mock.create = MagicMock()

    containers_mock = MagicMock()
    containers_mock.run = MagicMock(return_value=container)
    containers_mock.get = MagicMock(return_value=container)

    client = MagicMock()
    client.networks = networks_mock
    client.containers = containers_mock
    return client


def _fake_settings_for_start() -> MagicMock:
    """Settings stub matching the attributes start_system_emulation reads."""
    s = MagicMock()
    s.storage_root = "/data/firmware"
    s.emulation_network = "emulation_net"
    s.system_emulation_image = "wairz/firmae:latest"
    s.system_emulation_ram_limit = "4g"
    s.system_emulation_cpu_limit = 2.0
    s.docker_host = ""
    return s


# ===========================================================================
# Validation surface — start_system_emulation
# ===========================================================================


class TestStartSystemEmulationValidation:
    @pytest.mark.asyncio
    async def test_no_storage_path_raises_value_error(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db, with_storage=False)
            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="no storage_path"):
                    await svc.start_system_emulation(
                        firmware=firmware, project_id=project.id,
                    )

    @pytest.mark.asyncio
    async def test_already_running_session_raises_value_error(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)

            # Seed an existing system-full session in 'running' state.
            existing = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="system-full", port_forwards=[],
                status="running",
                container_id="existing-c0ntainer",
            )
            db.add(existing)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="already running"):
                    await svc.start_system_emulation(
                        firmware=firmware, project_id=project.id,
                    )


class TestStartSystemEmulationLiveCanary:
    """Rule #35b: ``start_system_emulation`` writes an EmulationSession row
    AND mutates it through pending → starting + container_id + started_at +
    system_emulation_stage='starting'. A mock-only test would assert
    ``db.add.call_count == 1`` and pass even if the constructor silently
    dropped ``mode='system-full'`` (the F-A-06 confidence-bypass shape).
    """

    @pytest.mark.asyncio
    async def test_persists_session_with_pending_then_starting_state(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)

            fake_client = _fake_docker_client_for_start(container_id="dead-beef")

            # Mock httpx for both the _wait_for_shim health probe and the
            # /start call. The _wait_for_shim path uses
            # `async with httpx.AsyncClient(timeout=5.0) as http: ... http.get`,
            # and /start uses `async with httpx.AsyncClient(timeout=30.0) as http: ... http.post`.
            health_resp = MagicMock(status_code=200)
            start_resp = MagicMock(status_code=202)
            start_resp.headers = {"content-type": "application/json"}
            start_resp.json = MagicMock(return_value={})

            class _FakeAsyncHttpClient:
                """Async-context-manager mock that yields itself, supports
                .get() and .post() returning predetermined responses."""
                def __init__(self, *_a, **_kw): ...
                async def __aenter__(self): return self
                async def __aexit__(self, *_a): return False
                async def get(self, *_a, **_kw): return health_resp
                async def post(self, *_a, **_kw): return start_resp

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ), patch(
                "app.services.system_emulation_service.get_docker_client",
                return_value=fake_client,
            ), patch(
                "app.services.system_emulation_service.httpx.AsyncClient",
                _FakeAsyncHttpClient,
            ), patch(
                "os.path.exists", return_value=False,  # _resolve_host_path /.dockerenv check
            ):
                svc = SystemEmulationService(db)
                session = await svc.start_system_emulation(
                    firmware=firmware,
                    project_id=project.id,
                    brand="netgear",
                )

            # Real SELECT — the canary that mocks cannot fake.
            persisted = (
                await db.execute(
                    select(EmulationSession).where(
                        EmulationSession.id == session.id,
                    )
                )
            ).scalar_one()

            assert persisted.project_id == project.id
            assert persisted.firmware_id == firmware.id
            assert persisted.mode == "system-full", (
                "Rule #35b: mode must round-trip — F-A-06 shape would silently drop"
            )
            assert persisted.architecture == "arm"
            assert persisted.container_id == "dead-beef"
            assert persisted.status == "starting"
            assert persisted.started_at is not None
            assert persisted.system_emulation_stage == "starting"
            assert persisted.error_message is None


# ===========================================================================
# Concurrency counter
# ===========================================================================


class TestCountActiveSessions:
    @pytest.mark.asyncio
    async def test_counts_only_system_full_active_sessions(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            other_project, other_firmware = await _seed_project_firmware(db)

            # Active system-full session for THIS project — counts.
            db.add(EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="running",
            ))
            # Stopped session — does NOT count.
            db.add(EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="stopped",
            ))
            # User-mode active session — does NOT count.
            db.add(EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="user", port_forwards=[], status="running",
            ))
            # Other project's active system-full — does NOT count.
            db.add(EmulationSession(
                project_id=other_project.id, firmware_id=other_firmware.id,
                mode="system-full", port_forwards=[], status="running",
            ))
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                count = await svc._count_active_system_sessions(project.id)
                assert count == 1


# ===========================================================================
# poll_system_status — guard-clause surface
# ===========================================================================


class TestPollSystemStatus:
    @pytest.mark.asyncio
    async def test_session_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.poll_system_status(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_wrong_mode_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="user", port_forwards=[], status="running", container_id="x",
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="Not a system emulation session"):
                    await svc.poll_system_status(session.id)

    @pytest.mark.asyncio
    async def test_no_container_id_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="starting", container_id=None,
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="No container associated"):
                    await svc.poll_system_status(session.id)

    @pytest.mark.asyncio
    async def test_terminal_status_returns_session_unchanged(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="stopped", container_id="x",
                error_message="prior",
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                result = await svc.poll_system_status(session.id)
                assert result.status == "stopped"
                assert result.error_message == "prior"


# ===========================================================================
# stop_system_emulation — no_container short-circuit
# ===========================================================================


class TestStopSystemEmulation:
    @pytest.mark.asyncio
    async def test_session_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.stop_system_emulation(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_no_container_id_marks_stopped_with_timestamp(self):
        """Live-canary path: status flips to 'stopped' and stopped_at is set."""
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="error", container_id=None,
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                result = await svc.stop_system_emulation(session.id)
                assert result.status == "stopped"
                assert result.stopped_at is not None

                # SELECT back to verify persisted.
                refreshed = (
                    await db.execute(
                        select(EmulationSession).where(
                            EmulationSession.id == session.id,
                        )
                    )
                ).scalar_one()
                assert refreshed.status == "stopped"
                assert refreshed.stopped_at is not None


# ===========================================================================
# get_firmware_services + run_command_in_firmware — guard clauses
# ===========================================================================


class TestGetFirmwareServices:
    @pytest.mark.asyncio
    async def test_session_not_found_raises(self):
        async with make_live_db() as db:
            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="not found"):
                    await svc.get_firmware_services(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_no_container_id_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="running", container_id=None,
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="No container associated"):
                    await svc.get_firmware_services(session.id)


class TestRunCommandInFirmware:
    @pytest.mark.asyncio
    async def test_not_running_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="starting", container_id="x",
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="not running"):
                    await svc.run_command_in_firmware(session.id, "ls /")

    @pytest.mark.asyncio
    async def test_no_container_id_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="running", container_id=None,
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="No container associated"):
                    await svc.run_command_in_firmware(session.id, "ls /")


# ===========================================================================
# get_nvram_state + interact_web_endpoint — guard clauses
# ===========================================================================


class TestGetNvramState:
    @pytest.mark.asyncio
    async def test_session_not_running_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="starting", container_id="x",
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="not running"):
                    await svc.get_nvram_state(session.id)


class TestInteractWebEndpoint:
    @pytest.mark.asyncio
    async def test_no_firmware_ip_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed_project_firmware(db)
            session = EmulationSession(
                project_id=project.id, firmware_id=firmware.id,
                mode="system-full", port_forwards=[], status="running", container_id="x",
                firmware_ip=None,
            )
            db.add(session)
            await db.flush()

            with patch(
                "app.services.system_emulation_service.get_settings",
                return_value=_fake_settings_for_start(),
            ):
                svc = SystemEmulationService(db)
                with pytest.raises(ValueError, match="No firmware IP discovered"):
                    await svc.interact_web_endpoint(session.id, method="GET", path="/")
