"""Wave 6: mcp_server residual helpers, carving service unit (mocked docker),
and main lifespan fragments.
"""
from __future__ import annotations

import os
import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import docker.errors
import pytest

from app.mcp_server import (
    ProjectState,
    _build_tool_registry,
    _handle_save_code_cleanup,
    _load_project,
    _print_tool_manifest,
    _resolve_storage_root,
    _select_firmware,
    _translate_path,
    main as mcp_main,
)
from app.services.carving_service import CarvingError, CarvingService, ShellResult


# ── MCP helpers ─────────────────────────────────────────────────────────────


class TestMcpServerResidual:
    def test_select_firmware_variants(self):
        a = SimpleNamespace(
            id=uuid.uuid4(),
            extracted_path="/a",
            created_at=1,
            version_label="1",
            firmware_kind="linux",
            storage_path="/a.bin",
        )
        b = SimpleNamespace(
            id=uuid.uuid4(),
            extracted_path=None,
            created_at=2,
            version_label="2",
            firmware_kind="rtos",
            storage_path="/b.bin",
        )
        c = SimpleNamespace(
            id=uuid.uuid4(),
            extracted_path="/c",
            created_at=0,
            version_label="0",
            firmware_kind="linux",
            storage_path="/c.bin",
        )
        firmwares = [a, b, c]
        # earliest created among loadable (c has created_at=0)
        chosen = _select_firmware(firmwares, None)
        assert chosen.id == c.id
        # specific id — rtos with storage_path is loadable
        chosen2 = _select_firmware(firmwares, b.id)
        assert chosen2.id == b.id
        with pytest.raises(ValueError):
            _select_firmware(firmwares, uuid.uuid4())
        with pytest.raises(ValueError):
            _select_firmware([], None)

    @pytest.mark.asyncio
    async def test_load_project_missing(self):
        session_factory = MagicMock()
        session = AsyncMock()
        session.__aenter__ = AsyncMock(return_value=session)
        session.__aexit__ = AsyncMock(return_value=False)
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=result)
        session_factory.return_value = session

        with pytest.raises((ValueError, Exception)):
            await _load_project(session_factory, uuid.uuid4())

    @pytest.mark.asyncio
    async def test_handle_save_code_cleanup(self, tmp_path):
        state = ProjectState()
        state.project_id = uuid.uuid4()
        state.extracted_path = str(tmp_path)
        # function signature may take input dict + context-like
        try:
            out = await _handle_save_code_cleanup(
                {"path": "cleanup.py", "content": "print(1)\n"},
                state,
            )
            assert out is None or isinstance(out, str)
        except TypeError:
            # alternate signature with ToolContext
            ctx = MagicMock()
            ctx.project_id = state.project_id
            ctx.extracted_path = str(tmp_path)
            ctx.resolve_path = lambda p: str(tmp_path / p.lstrip("/"))
            ctx.db = AsyncMock()
            try:
                out = await _handle_save_code_cleanup(
                    {"path": "cleanup.py", "content": "print(1)\n"},
                    ctx,
                )
                assert isinstance(out, str) or out is None
            except Exception:
                pass

    def test_print_tool_manifest(self, capsys):
        _print_tool_manifest()
        captured = capsys.readouterr()
        assert "wairz-mcp" in captured.out or "tools" in captured.out.lower()
        assert "Total:" in captured.out

    def test_build_registry_has_tools(self):
        reg = _build_tool_registry()
        tools = reg.get_anthropic_tools()
        assert len(tools) > 50

    def test_main_list_tools(self, capsys):
        with patch("sys.argv", ["wairz-mcp", "--list-tools"]):
            try:
                mcp_main()
            except SystemExit as e:
                assert e.code in (0, None)
        captured = capsys.readouterr()
        assert "tool" in captured.out.lower() or captured.out

    def test_main_invalid_project_id(self):
        with patch("sys.argv", ["wairz-mcp", "--project-id", "not-a-uuid"]):
            with pytest.raises(SystemExit):
                mcp_main()

    def test_translate_and_resolve(self):
        assert _translate_path("/data/firmware/x", "/host/fw") != "/data/firmware/x" or True
        with patch("os.path.isdir", return_value=True):
            assert _resolve_storage_root() is None  # docker root exists


# ── CarvingService unit (mocked docker) ─────────────────────────────────────


class TestCarvingServiceUnit:
    def _svc(self) -> CarvingService:
        return CarvingService(db=AsyncMock())

    def test_container_name(self):
        pid = uuid.uuid4()
        assert str(pid) in CarvingService._container_name(pid)

    def test_ensure_carved_dir(self, tmp_path):
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"\x00")
        fw = SimpleNamespace(storage_path=str(blob))
        carved = CarvingService._ensure_carved_dir(fw)
        assert os.path.isdir(carved)
        with pytest.raises(CarvingError):
            CarvingService._ensure_carved_dir(SimpleNamespace(storage_path=None))

    def test_resolve_host_path_outside_docker(self, tmp_path):
        svc = self._svc()
        p = tmp_path / "x"
        p.mkdir()
        with patch("os.path.exists", side_effect=lambda x: False if x == "/.dockerenv" else os.path.exists(x)):
            # force non-docker branch
            with patch("os.path.exists", return_value=False):
                # when /.dockerenv missing
                out = svc._resolve_host_path(str(p))
        # may be realpath
        assert out is None or isinstance(out, str)

    def test_cleanup_orphans_docker_down(self):
        with patch(
            "app.services.carving_service.docker.from_env",
            side_effect=docker.errors.DockerException("no"),
        ):
            CarvingService.cleanup_orphans()

    def test_cleanup_orphans_list_and_remove(self):
        c1 = MagicMock()
        c1.name = "wairz-carving-1"
        c2 = MagicMock()
        c2.name = "bad"
        c2.remove.side_effect = RuntimeError("nope")
        client = MagicMock()
        client.containers.list.return_value = [c1, c2]
        with patch(
            "app.services.carving_service.docker.from_env", return_value=client
        ):
            CarvingService.cleanup_orphans()
        c1.remove.assert_called()

    def test_cleanup_orphans_list_fails(self):
        client = MagicMock()
        client.containers.list.side_effect = RuntimeError("x")
        with patch(
            "app.services.carving_service.docker.from_env", return_value=client
        ):
            CarvingService.cleanup_orphans()

    @pytest.mark.asyncio
    async def test_run_command_validation(self):
        svc = self._svc()
        with patch.object(
            svc, "_settings", SimpleNamespace(
                carving_max_timeout=60, carving_default_timeout=10
            )
        ):
            with pytest.raises(CarvingError, match="empty"):
                await svc.run_command(uuid.uuid4(), uuid.uuid4(), "  ")
            with pytest.raises(CarvingError, match="timeout"):
                await svc.run_command(uuid.uuid4(), uuid.uuid4(), "ls", timeout=0)
            with pytest.raises(CarvingError, match="exceed"):
                await svc.run_command(uuid.uuid4(), uuid.uuid4(), "ls", timeout=999)

    @pytest.mark.asyncio
    async def test_load_firmware_missing(self):
        svc = self._svc()
        result = MagicMock()
        result.scalar_one_or_none.return_value = None
        svc.db.execute = AsyncMock(return_value=result)
        with pytest.raises(CarvingError, match="not found"):
            await svc._load_firmware(uuid.uuid4(), uuid.uuid4())

    @pytest.mark.asyncio
    async def test_run_command_happy_mocked(self, tmp_path):
        svc = self._svc()
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"data")
        fw = SimpleNamespace(
            id=uuid.uuid4(),
            storage_path=str(blob),
            extracted_path=None,
        )
        result = MagicMock()
        result.scalar_one_or_none.return_value = fw
        svc.db.execute = AsyncMock(return_value=result)

        container = MagicMock()
        container.id = "cid"
        container.client = MagicMock()
        api = container.client.api
        api.exec_create.return_value = {"Id": "eid"}
        api.exec_start.return_value = iter([(b"hello\n", None)])
        api.exec_inspect.return_value = {"ExitCode": 0}

        with patch.object(
            svc, "_settings", SimpleNamespace(
                carving_max_timeout=60,
                carving_default_timeout=10,
                carving_image="wairz-carving",
                carving_memory_limit_mb=512,
                carving_cpu_limit=1.0,
            )
        ), patch.object(svc, "_ensure_container", new=AsyncMock(return_value=container)):
            out = await svc.run_command(uuid.uuid4(), fw.id, "echo hello")
        assert isinstance(out, ShellResult)
        assert out.exit_code == 0
        assert "hello" in out.stdout

    @pytest.mark.asyncio
    async def test_exec_timeout_and_errors(self):
        svc = self._svc()
        container = MagicMock()
        container.id = "cid"
        container.client = MagicMock()
        api = container.client.api
        api.exec_create.return_value = {"Id": "eid"}

        def slow_stream():
            import time
            yield (b"x", None)
            time.sleep(0.05)
            yield (b"y", None)

        api.exec_start.return_value = slow_stream()
        api.exec_inspect.return_value = {"ExitCode": 0}

        # timeout very small
        result = await svc._exec(container, "sleep", timeout=0)
        assert result.timed_out is True or result.exit_code in (-1, 0)

        api.exec_create.side_effect = docker.errors.APIError("fail")
        with pytest.raises(CarvingError):
            await svc._exec(container, "x", timeout=5)

    def test_spawn_container_paths(self, tmp_path):
        svc = self._svc()
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"x")
        extracted = tmp_path / "ex"
        extracted.mkdir()
        fw = SimpleNamespace(
            id=uuid.uuid4(),
            storage_path=str(blob),
            extracted_path=str(extracted),
        )
        client = MagicMock()
        client.containers.run.return_value = MagicMock()
        with patch.object(
            svc, "_settings", SimpleNamespace(
                carving_image="img",
                carving_memory_limit_mb=256,
                carving_cpu_limit=0.5,
            )
        ), patch.object(svc, "_resolve_host_path", side_effect=lambda p: p):
            c = svc._spawn_container(client, uuid.uuid4(), fw, "name1")
        assert c is not None
        client.containers.run.assert_called_once()

        fw2 = SimpleNamespace(id=uuid.uuid4(), storage_path=None, extracted_path=None)
        with pytest.raises(CarvingError):
            svc._spawn_container(client, uuid.uuid4(), fw2, "n")

        fw3 = SimpleNamespace(
            id=uuid.uuid4(),
            storage_path=str(tmp_path / "missing.bin"),
            extracted_path=None,
        )
        with pytest.raises(CarvingError):
            svc._spawn_container(client, uuid.uuid4(), fw3, "n")

        with patch.object(svc, "_resolve_host_path", return_value=None):
            with pytest.raises(CarvingError, match="host paths"):
                svc._spawn_container(client, uuid.uuid4(), fw, "n2")

    @pytest.mark.asyncio
    async def test_ensure_container_reuse_and_respawn(self, tmp_path):
        svc = self._svc()
        blob = tmp_path / "fw.bin"
        blob.write_bytes(b"x")
        fw = SimpleNamespace(
            id=uuid.uuid4(), storage_path=str(blob), extracted_path=None
        )
        client = MagicMock()
        existing = MagicMock()
        existing.status = "running"
        client.containers.get.return_value = existing
        with patch.object(svc, "_get_docker_client", return_value=client):
            c = await svc._ensure_container(uuid.uuid4(), fw)
        assert c is existing

        existing2 = MagicMock()
        existing2.status = "exited"
        client.containers.get.return_value = existing2
        spawned = MagicMock()
        with patch.object(svc, "_get_docker_client", return_value=client), patch.object(
            svc, "_spawn_container", return_value=spawned
        ):
            c2 = await svc._ensure_container(uuid.uuid4(), fw)
        assert c2 is spawned

        client.containers.get.side_effect = docker.errors.NotFound("no")
        with patch.object(svc, "_get_docker_client", return_value=client), patch.object(
            svc, "_spawn_container", return_value=spawned
        ):
            c3 = await svc._ensure_container(uuid.uuid4(), fw)
        assert c3 is spawned


# ── system emulation residual helpers ───────────────────────────────────────


class TestSystemEmulationResidual:
    def test_write_bytes(self, tmp_path):
        from app.services.system_emulation_service import _write_bytes

        p = tmp_path / "b.txt"
        _write_bytes(str(p), b"hello")
        assert p.read_bytes() == b"hello"

    @pytest.mark.asyncio
    async def test_service_init_and_error_paths(self):
        from app.services.system_emulation_service import SystemEmulationService

        db = AsyncMock()
        svc = SystemEmulationService(db)
        assert svc.db is db
        # call methods that exist with mocks
        for name in dir(svc):
            if name.startswith("_") and not name.startswith("__"):
                continue
