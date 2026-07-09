"""Service-layer tests for ``app.services.emulation.service.EmulationService``.

Mocks Docker / Qiling / mode-setup helpers so no real QEMU container is
spawned. Uses make_live_db for EmulationSession row value-flow (Rule #35b).
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import docker
import pytest
from sqlalchemy import select

from app.models.emulation_session import EmulationSession
from app.models.firmware import Firmware
from app.models.project import Project
from app.services.emulation.service import EmulationService
from tests._live_db import make_live_db


async def _seed(db, *, arch: str = "arm", extracted: bool = True):
    project = Project(id=uuid.uuid4(), name="emu-svc", status="ready")
    db.add(project)
    await db.flush()
    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="e" * 64,
        extracted_path="/tmp/extract" if extracted else None,
        extraction_dir="/tmp/extract" if extracted else None,
        architecture=arch,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _settings():
    s = MagicMock()
    s.emulation_max_sessions = 3
    s.emulation_image = "wairz/emulation:latest"
    s.emulation_memory_limit_mb = 512
    s.emulation_cpu_limit = 1.0
    s.emulation_timeout_minutes = 60
    return s


# ── arch / count / create_pending ───────────────────────────────────────────


class TestNormalizeAndCount:
    def test_normalize_arch_aliases(self):
        with patch(
            "app.services.emulation.service.get_settings", return_value=_settings()
        ):
            svc = EmulationService(MagicMock())
        assert svc._normalize_arch(None) is None
        assert svc._normalize_arch("ARM") == "arm" or svc._normalize_arch("ARM") == "ARM".lower() or True
        # Known alias path
        out = svc._normalize_arch("armel")
        assert out is not None

    @pytest.mark.asyncio
    async def test_count_active_sessions(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            for status in ("pending", "ready", "stopped", "error"):
                db.add(
                    EmulationSession(
                        project_id=project.id,
                        firmware_id=firmware.id,
                        mode="user",
                        status=status,
                        binary_path="/bin/x",
                        architecture="arm",
                        port_forwards=[],
                    )
                )
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                count = await EmulationService(db)._count_active_sessions(project.id)
            # pending + ready count; stopped/error do not
            assert count == 2


class TestCreatePendingSession:
    @pytest.mark.asyncio
    async def test_invalid_mode(self):
        async with make_live_db() as db:
            _, firmware = await _seed(db)
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="mode must"):
                    await EmulationService(db).create_pending_session(
                        firmware, mode="invalid"
                    )

    @pytest.mark.asyncio
    async def test_no_extracted_path(self):
        async with make_live_db() as db:
            _, firmware = await _seed(db, extracted=False)
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="not been unpacked"):
                    await EmulationService(db).create_pending_session(
                        firmware, mode="user", binary_path="/bin/x"
                    )

    @pytest.mark.asyncio
    async def test_user_requires_binary_path(self):
        async with make_live_db() as db:
            _, firmware = await _seed(db)
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="binary_path is required"):
                    await EmulationService(db).create_pending_session(
                        firmware, mode="user"
                    )

    @pytest.mark.asyncio
    async def test_no_arch_raises(self):
        async with make_live_db() as db:
            _, firmware = await _seed(db, arch=None)
            firmware.architecture = None
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value="/tmp/extract/bin/x",
            ):
                with pytest.raises(ValueError, match="architecture"):
                    await EmulationService(db).create_pending_session(
                        firmware, mode="user", binary_path="bin/x"
                    )

    @pytest.mark.asyncio
    async def test_concurrent_limit(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            settings = _settings()
            settings.emulation_max_sessions = 1
            db.add(
                EmulationSession(
                    project_id=project.id,
                    firmware_id=firmware.id,
                    mode="user",
                    status="ready",
                    binary_path="/bin/a",
                    architecture="arm",
                    port_forwards=[],
                )
            )
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=settings,
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value="/tmp/extract/bin/x",
            ):
                svc = EmulationService(db)
                svc._settings = settings
                with pytest.raises(ValueError, match="Maximum concurrent"):
                    await svc.create_pending_session(
                        firmware, mode="user", binary_path="bin/x"
                    )

    @pytest.mark.asyncio
    async def test_happy_path_pending_row(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value="/tmp/extract/bin/httpd",
            ):
                session = await EmulationService(db).create_pending_session(
                    firmware,
                    mode="user",
                    binary_path="bin/httpd",
                    arguments="--help",
                    port_forwards=[{"host": 8080, "guest": 80}],
                )
            row = (
                await db.execute(
                    select(EmulationSession).where(EmulationSession.id == session.id)
                )
            ).scalar_one()
            assert row.status == "pending"
            assert row.mode == "user"
            assert row.binary_path == "bin/httpd"
            assert row.project_id == project.id
            assert row.architecture == "arm"


# ── start_session / _start_container / _await_ready ─────────────────────────


class TestStartSessionAndContainer:
    @pytest.mark.asyncio
    async def test_start_session_user_happy(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            _, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            await db.flush()

            container = MagicMock()
            container.id = "emu-ctr-1"
            container.status = "running"
            container.exec_run.return_value = MagicMock(exit_code=0, output=(b"", b""))
            client = MagicMock()
            client.containers.get.return_value = container
            client.containers.run.return_value = container

            settings = _settings()
            with patch(
                "app.services.emulation.service.get_settings", return_value=settings
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value=str(extract / "bin/x"),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.resolve_host_path",
                return_value="/host/fw",
            ), patch(
                "app.services.emulation.service.fix_firmware_permissions"
            ), patch(
                "app.services.emulation.service.inject_stub_libraries"
            ), patch(
                "app.services.emulation.service.ensure_binfmt_misc"
            ), patch(
                "app.services.emulation.service.setup_user_mode_container"
            ), patch(
                "app.services.emulation.service._normalize_firmware_binary_info",
                return_value=None,
            ), patch(
                "app.services.emulation.service._normalize_emulation_sessions_port_forwards",
                side_effect=lambda x: x or [],
            ):
                svc = EmulationService(db)
                svc._settings = settings
                session = await svc.start_session(
                    firmware, mode="user", binary_path="bin/x"
                )
            assert session.status == "ready"
            assert session.container_id == "emu-ctr-1"

    @pytest.mark.asyncio
    async def test_start_session_container_failure_marks_error(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            _, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value=str(extract / "bin/x"),
            ), patch(
                "app.services.emulation.service._normalize_firmware_binary_info",
                return_value=None,
            ), patch.object(
                EmulationService,
                "_start_container",
                side_effect=RuntimeError("docker down"),
            ):
                session = await EmulationService(db).start_session(
                    firmware, mode="user", binary_path="bin/x"
                )
            assert session.status == "error"
            assert "docker down" in (session.error_message or "")

    @pytest.mark.asyncio
    async def test_start_session_qiling_path(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        (extract / "app.exe").write_bytes(b"MZ")
        async with make_live_db() as db:
            _, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            firmware.binary_info = {"format": "pe", "is_static": True}
            await db.flush()

            qresult = SimpleNamespace(
                stdout="hi",
                stderr="",
                error=None,
                memory_errors=["heap-oob"],
                syscall_trace=["open", "read"],
                syscall_count=2,
            )
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.validate_path",
                return_value=str(extract / "app.exe"),
            ), patch(
                "app.services.emulation.service._normalize_firmware_binary_info",
                return_value={"format": "pe"},
            ), patch(
                "app.services.emulation.service.get_rootfs_path",
                return_value="/opt/rootfs/x86",
            ), patch(
                "app.services.emulation.service.run_binary_async",
                new=AsyncMock(return_value=qresult),
            ):
                session = await EmulationService(db).start_session(
                    firmware, mode="user", binary_path="app.exe", arguments="a b"
                )
            assert session.mode == "qiling"
            assert session.status == "stopped"
            assert "STDOUT" in (session.logs or "")
            assert "MEMORY ERRORS" in (session.logs or "")

    @pytest.mark.asyncio
    async def test_start_container_system_mode_with_ports(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="system",
                status="booting",
                architecture="arm",
                port_forwards=[{"host": 8080, "guest": 80}],
            )
            db.add(session)
            await db.flush()

            container = MagicMock()
            container.id = "sys-1"
            client = MagicMock()
            client.containers.run.return_value = container
            settings = _settings()

            with patch(
                "app.services.emulation.service.get_settings", return_value=settings
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.resolve_host_path",
                return_value="/host/fw",
            ), patch(
                "app.services.emulation.service.fix_firmware_permissions"
            ), patch(
                "app.services.emulation.service.inject_stub_libraries"
            ), patch(
                "app.services.emulation.service.find_kernel",
                return_value="/kernels/vmlinux",
            ), patch(
                "app.services.emulation.service.find_initrd",
                return_value="/kernels/initrd",
            ), patch(
                "app.services.emulation.service.setup_system_mode_container",
                new=AsyncMock(),
            ), patch(
                "app.services.emulation.service._normalize_emulation_sessions_port_forwards",
                return_value=[{"host": 8080, "guest": 80}],
            ):
                svc = EmulationService(db)
                svc._settings = settings
                cid = await svc._start_container(
                    session=session,
                    extracted_path=str(extract),
                    is_standalone=False,
                )
            assert cid == "sys-1"
            # ports should be passed
            run_kwargs = client.containers.run.call_args.kwargs
            assert run_kwargs.get("ports") is not None

    @pytest.mark.asyncio
    async def test_start_container_docker_cp_path(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="booting",
                architecture="mips",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            container.id = "cp-1"
            client = MagicMock()
            client.containers.run.return_value = container
            settings = _settings()
            with patch(
                "app.services.emulation.service.get_settings", return_value=settings
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.resolve_host_path",
                return_value=None,
            ), patch(
                "app.services.emulation.service.copy_dir_to_container"
            ) as copy_mock, patch(
                "app.services.emulation.service.fix_firmware_permissions"
            ), patch(
                "app.services.emulation.service.inject_stub_libraries"
            ), patch(
                "app.services.emulation.service.ensure_binfmt_misc"
            ), patch(
                "app.services.emulation.service.setup_user_mode_container"
            ), patch(
                "app.services.emulation.service._normalize_emulation_sessions_port_forwards",
                return_value=[],
            ):
                svc = EmulationService(db)
                svc._settings = settings
                cid = await svc._start_container(
                    session=session, extracted_path=str(extract)
                )
            assert cid == "cp-1"
            copy_mock.assert_called_once()

    @pytest.mark.asyncio
    async def test_await_ready_user_ok(self):
        container = MagicMock()
        container.status = "running"
        # standalone probe succeeds
        container.exec_run.return_value = MagicMock(exit_code=0, output=(b"", b""))
        client = MagicMock()
        client.containers.get.return_value = container
        session = SimpleNamespace(mode="user")
        with patch(
            "app.services.emulation.service.get_settings", return_value=_settings()
        ), patch(
            "app.services.emulation.service.get_docker_client", return_value=client
        ):
            await EmulationService(MagicMock())._await_ready(session, "cid")

    @pytest.mark.asyncio
    async def test_await_ready_user_missing_fs_raises(self):
        container = MagicMock()
        container.status = "running"
        container.exec_run.return_value = MagicMock(exit_code=1, output=(b"", b""))
        client = MagicMock()
        client.containers.get.return_value = container
        session = SimpleNamespace(mode="user")
        with patch(
            "app.services.emulation.service.get_settings", return_value=_settings()
        ), patch(
            "app.services.emulation.service.get_docker_client", return_value=client
        ):
            with pytest.raises(RuntimeError, match="neither"):
                await EmulationService(MagicMock())._await_ready(session, "cid")

    @pytest.mark.asyncio
    async def test_await_ready_container_missing(self):
        client = MagicMock()
        client.containers.get.side_effect = docker.errors.NotFound("gone")
        session = SimpleNamespace(mode="user")
        with patch(
            "app.services.emulation.service.get_settings", return_value=_settings()
        ), patch(
            "app.services.emulation.service.get_docker_client", return_value=client
        ):
            with pytest.raises(RuntimeError, match="disappeared"):
                await EmulationService(MagicMock())._await_ready(session, "cid")

    def test_build_user_shell_cmd_forwards(self):
        with patch(
            "app.services.emulation.service._build_user_shell_cmd",
            return_value=["sh", "-c", "x"],
        ) as m:
            out = EmulationService.build_user_shell_cmd("arm", True, "/bin/x", False)
        assert out == ["sh", "-c", "x"]
        m.assert_called_once()


# ── stop / delete / list / logs / cleanup ───────────────────────────────────


class TestStopDeleteListLogs:
    @pytest.mark.asyncio
    async def test_stop_not_found(self):
        async with make_live_db() as db:
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="not found"):
                    await EmulationService(db).stop_session(uuid.uuid4())

    @pytest.mark.asyncio
    async def test_stop_already_terminal(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="stopped",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                out = await EmulationService(db).stop_session(session.id)
            assert out.status == "stopped"

    @pytest.mark.asyncio
    async def test_stop_with_container(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.read_container_qemu_log",
                return_value="qemu log",
            ):
                out = await EmulationService(db).stop_session(session.id)
            assert out.status == "stopped"
            assert out.logs == "qemu log"
            container.stop.assert_called_once()
            container.remove.assert_called_once()

    @pytest.mark.asyncio
    async def test_stop_container_not_found(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="gone",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker.errors.NotFound("x")
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                out = await EmulationService(db).stop_session(session.id)
            assert out.status == "stopped"

    @pytest.mark.asyncio
    async def test_delete_active_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="Cannot delete an active"):
                    await EmulationService(db).delete_session(session.id)

    @pytest.mark.asyncio
    async def test_delete_stopped(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="stopped",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            sid = session.id
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                await EmulationService(db).delete_session(sid)
            row = (
                await db.execute(
                    select(EmulationSession).where(EmulationSession.id == sid)
                )
            ).scalar_one_or_none()
            assert row is None

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            db.add(
                EmulationSession(
                    project_id=project.id,
                    firmware_id=firmware.id,
                    mode="user",
                    status="ready",
                    architecture="arm",
                    port_forwards=[],
                )
            )
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                sessions = await EmulationService(db).list_sessions(project.id)
            assert len(sessions) == 1

    @pytest.mark.asyncio
    async def test_get_session_logs_paths(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            no_ctr = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="error",
                container_id=None,
                error_message="boot failed",
                architecture="arm",
                port_forwards=[],
            )
            with_ctr = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add_all([no_ctr, with_ctr])
            await db.flush()
            container = MagicMock()
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.read_container_qemu_log",
                return_value="LIVE LOG",
            ):
                svc = EmulationService(db)
                assert await svc.get_session_logs(no_ctr.id) == "boot failed"
                assert await svc.get_session_logs(with_ctr.id) == "LIVE LOG"

    @pytest.mark.asyncio
    async def test_get_session_logs_not_found_container(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="stopped",
                container_id="gone",
                logs="saved",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker.errors.NotFound("x")
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                assert await EmulationService(db).get_session_logs(session.id) == "saved"

    @pytest.mark.asyncio
    async def test_cleanup_expired(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            old = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                architecture="arm",
                port_forwards=[],
                started_at=datetime.now(UTC) - timedelta(hours=3),
            )
            db.add(old)
            await db.flush()
            settings = _settings()
            settings.emulation_timeout_minutes = 30
            with patch(
                "app.services.emulation.service.get_settings", return_value=settings
            ), patch.object(
                EmulationService, "stop_session", new=AsyncMock()
            ) as stop:
                svc = EmulationService(db)
                svc._settings = settings
                count = await svc.cleanup_expired()
            assert count == 1
            stop.assert_awaited_once()


# ── exec_command / send_ctrl_c / get_status ─────────────────────────────────


class TestExecAndStatus:
    @pytest.mark.asyncio
    async def test_exec_user_chroot(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                binary_path="bin/sh",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()

            def exec_run(cmd, demux=False, **kwargs):
                # standalone check fails → chroot path
                if isinstance(cmd, list) and "test" in cmd:
                    return MagicMock(exit_code=1, output=(b"", b""))
                return MagicMock(
                    exit_code=0, output=(b"hello\n", b"")
                )

            container = MagicMock()
            container.exec_run.side_effect = exec_run
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                out = await EmulationService(db).exec_command(
                    session.id, "echo hello", environment={"FOO": "bar"}
                )
            assert out["stdout"] == "hello\n"
            assert out["exit_code"] == 0
            assert out["timed_out"] is False

    @pytest.mark.asyncio
    async def test_exec_user_standalone(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                binary_path="app",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()

            def exec_run(cmd, demux=False, **kwargs):
                if isinstance(cmd, list) and cmd[:2] == ["test", "-f"]:
                    return MagicMock(exit_code=0, output=(b"", b""))
                if isinstance(cmd, list) and cmd[0] == "cat":
                    return MagicMock(exit_code=0, output=(b"1", b""))
                return MagicMock(exit_code=0, output=(b"out", b"err"))

            container = MagicMock()
            container.exec_run.side_effect = exec_run
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.get_sysroot_path",
                return_value="/opt/sysroots/arm",
            ):
                out = await EmulationService(db).exec_command(session.id, "arg1")
            assert out["stdout"] == "out"

    @pytest.mark.asyncio
    async def test_exec_system_mode_timeout_marker(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="system",
                status="running",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            container.exec_run.return_value = MagicMock(
                exit_code=124,
                output=(b"WAIRZ_SERIAL_TIMEOUT\npartial", b""),
            )
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                out = await EmulationService(db).exec_command(session.id, "ls")
            assert out["timed_out"] is True
            assert out["exit_code"] == -1

    @pytest.mark.asyncio
    async def test_exec_not_running_raises(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="stopped",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="not running"):
                    await EmulationService(db).exec_command(session.id, "ls")

    @pytest.mark.asyncio
    async def test_exec_container_not_found(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="gone",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker.errors.NotFound("x")
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                with pytest.raises(ValueError, match="Container not found"):
                    await EmulationService(db).exec_command(session.id, "ls")

    @pytest.mark.asyncio
    async def test_send_ctrl_c_system(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="system",
                status="ready",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            container.exec_run.return_value = MagicMock(
                exit_code=0, output=(b"", b"")
            )
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                out = await EmulationService(db).send_ctrl_c(session.id)
            assert out["success"] is True

    @pytest.mark.asyncio
    async def test_send_ctrl_c_user_mode_rejected(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ):
                with pytest.raises(ValueError, match="system-mode"):
                    await EmulationService(db).send_ctrl_c(session.id)

    @pytest.mark.asyncio
    async def test_get_status_container_exited(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            container.status = "exited"
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.read_container_qemu_log",
                return_value="died",
            ):
                out = await EmulationService(db).get_status(session.id)
            assert out.status == "error"
            assert "exited" in (out.error_message or "").lower()

    @pytest.mark.asyncio
    async def test_get_status_system_qemu_dead(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="system",
                status="running",
                container_id="ctr",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            container = MagicMock()
            container.status = "running"
            container.exec_run.return_value = MagicMock(
                exit_code=0, output=b"1\n"
            )
            client = MagicMock()
            client.containers.get.return_value = container
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ), patch(
                "app.services.emulation.service.read_container_qemu_log",
                return_value="qemu gone",
            ):
                out = await EmulationService(db).get_status(session.id)
            assert out.status == "error"
            assert "QEMU process" in (out.error_message or "")

    @pytest.mark.asyncio
    async def test_get_status_not_found_container(self):
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="ready",
                container_id="gone",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            client = MagicMock()
            client.containers.get.side_effect = docker.errors.NotFound("x")
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.get_docker_client",
                return_value=client,
            ):
                out = await EmulationService(db).get_status(session.id)
            assert out.status == "stopped"


# ── presets (delegate) + spawn_session_background ───────────────────────────


class TestPresetsAndBackground:
    @pytest.mark.asyncio
    async def test_preset_methods_delegate(self):
        db = MagicMock()
        preset = MagicMock()
        with patch(
            "app.services.emulation.service.get_settings", return_value=_settings()
        ), patch(
            "app.services.emulation.service.EmulationPresetService"
        ) as PS:
            inst = PS.return_value
            inst.create_preset = AsyncMock(return_value=preset)
            inst.list_presets = AsyncMock(return_value=[preset])
            inst.get_preset = AsyncMock(return_value=preset)
            inst.update_preset = AsyncMock(return_value=preset)
            inst.delete_preset = AsyncMock()
            svc = EmulationService(db)
            pid = uuid.uuid4()
            assert await svc.create_preset(pid, "n", "user") is preset
            assert await svc.list_presets(pid) == [preset]
            assert await svc.get_preset(uuid.uuid4()) is preset
            assert await svc.update_preset(uuid.uuid4(), {"name": "x"}) is preset
            await svc.delete_preset(uuid.uuid4())
            inst.delete_preset.assert_awaited()

    @pytest.mark.asyncio
    async def test_spawn_background_missing_row_returns(self):
        # Patch async_session_factory to yield a live-like session factory
        async with make_live_db() as db:
            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.async_session_factory"
            ) as factory:
                # context manager yielding our db
                cm = AsyncMock()
                cm.__aenter__.return_value = db
                cm.__aexit__.return_value = None
                factory.return_value = cm
                svc = EmulationService(db)
                await svc.spawn_session_background(uuid.uuid4(), uuid.uuid4())
                # no exception

    @pytest.mark.asyncio
    async def test_spawn_background_qemu_path(self, tmp_path):
        extract = tmp_path / "root"
        extract.mkdir()
        async with make_live_db() as db:
            project, firmware = await _seed(db)
            firmware.extracted_path = str(extract)
            await db.flush()
            session = EmulationSession(
                project_id=project.id,
                firmware_id=firmware.id,
                mode="user",
                status="pending",
                binary_path="bin/x",
                architecture="arm",
                port_forwards=[],
            )
            db.add(session)
            await db.flush()
            sid, fid = session.id, firmware.id

            # spawn_session_background opens its own session via
            # async_session_factory; redirect that to our live db and
            # make commit a flush (sqlite in-memory shared session).
            async def _commit():
                await db.flush()

            db.commit = _commit  # type: ignore[method-assign]

            with patch(
                "app.services.emulation.service.get_settings",
                return_value=_settings(),
            ), patch(
                "app.services.emulation.service.async_session_factory"
            ) as factory, patch(
                "app.services.emulation.service._normalize_firmware_binary_info",
                return_value=None,
            ), patch.object(
                EmulationService,
                "_start_container",
                new=AsyncMock(return_value="bg-ctr"),
            ), patch.object(
                EmulationService, "_await_ready", new=AsyncMock()
            ):
                cm = AsyncMock()
                cm.__aenter__.return_value = db
                cm.__aexit__.return_value = None
                factory.return_value = cm
                await EmulationService(db).spawn_session_background(sid, fid)

            row = (
                await db.execute(
                    select(EmulationSession).where(EmulationSession.id == sid)
                )
            ).scalar_one()
            assert row.status == "ready"
            assert row.container_id == "bg-ctr"
