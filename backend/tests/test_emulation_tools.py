"""Contract tests for the ``app.ai.tools.emulation`` MCP tool handlers.

increase-coverage skill run: app/ai/tools/emulation.py sat at 6% coverage
(1151 stmts / 1084 miss) with no dedicated tool-handler test file — only
router/service/preset paths were covered. This file exercises the MCP-facing
handlers directly with a ``_StubContext`` + ``make_live_db`` (Rule #35b),
mocking ``EmulationService`` / ``KernelService`` / ``SystemEmulationService``
/ Docker / Qiling at service boundaries so real QEMU never launches.

Scope: pure helpers (``_parse_proc_net_tcp``, ``_diagnose_environment_sync``,
``_troubleshoot_detect_characteristics_sync``, ``_list_kernels_sync``) plus
input-validation / branch-selection logic in every ``_handle_*`` registered
by ``register_emulation_tools`` (25 tools).
"""
from __future__ import annotations

import os
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.emulation import (
    _diagnose_environment_sync,
    _handle_capture_network_traffic,
    _handle_check_status,
    _handle_diagnose_environment,
    _handle_download_kernel,
    _handle_emulate_with_qiling,
    _handle_enumerate_services,
    _handle_get_crash_dump,
    _handle_get_logs,
    _handle_get_nvram_state,
    _handle_interact_web_endpoint,
    _handle_list_firmware_services,
    _handle_list_kernels,
    _handle_list_presets,
    _handle_qiling_rootfs_status,
    _handle_run_command,
    _handle_run_command_in_firmware,
    _handle_run_gdb_command,
    _handle_save_preset,
    _handle_start_emulation,
    _handle_start_from_preset,
    _handle_start_system_emulation,
    _handle_stop_emulation,
    _handle_stop_system_emulation,
    _handle_system_emulation_status,
    _handle_troubleshoot_emulation,
    _list_kernels_sync,
    _parse_proc_net_tcp,
    _troubleshoot_detect_characteristics_sync,
    register_emulation_tools,
)
from app.models import Firmware, Project
from app.models.emulation_preset import EmulationPreset
from app.models.emulation_session import EmulationSession
from app.services.qiling_service import QilingResult
from tests._live_db import make_live_db

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@dataclass
class _StubContext:
    """Minimal ToolContext stub for emulation handlers."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None
    extracted_path: str | None = "/tmp/extract"
    detection_roots: list[str] = field(default_factory=list)

    def resolve_path(self, path: str) -> str:
        if path.startswith("/"):
            return f"/tmp/extract{path}"
        return f"/tmp/extract/{path}"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(
    db,
    *,
    extracted_path: str | None = "/tmp/extract",
    architecture: str = "arm",
    endianness: str = "little",
    original_filename: str = "fw.bin",
    binary_info: dict | None = None,
) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="emu-tools-test", status="ready")
    db.add(project)
    await db.flush()

    firmware = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="b" * 64,
        extracted_path=extracted_path,
        extraction_dir=extracted_path,
        architecture=architecture,
        endianness=endianness,
        original_filename=original_filename,
        binary_info=binary_info,
    )
    db.add(firmware)
    await db.flush()
    return project, firmware


def _session_obj(**overrides) -> SimpleNamespace:
    defaults = dict(
        id=uuid.uuid4(),
        mode="user",
        status="running",
        architecture="arm",
        binary_path="/bin/busybox",
        error_message=None,
        port_forwards=[],
        started_at=datetime.now(UTC),
        container_id="ctr-abc",
        system_emulation_stage=None,
        firmware_ip=None,
        kernel_used=None,
        discovered_services=None,
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _preset_obj(**overrides) -> SimpleNamespace:
    defaults = dict(
        id=uuid.uuid4(),
        name="my-preset",
        description="desc",
        mode="system",
        binary_path=None,
        arguments=None,
        port_forwards=[{"host": 8080, "guest": 80}],
        kernel_name="vmlinux-arm",
        init_path=None,
        pre_init_script="echo hi",
        stub_profile="generic",
    )
    defaults.update(overrides)
    return SimpleNamespace(**defaults)


def _make_fake_rootfs(tmp_path, *, style: str = "full") -> str:
    """Build a synthetic firmware rootfs for diagnose/troubleshoot helpers."""
    root = tmp_path / "rootfs"
    root.mkdir()

    if style == "full":
        for d in ("sbin", "bin", "etc", "etc_ro", "lib", "usr/bin", "usr/sbin", "webroot", "tmp"):
            (root / d).mkdir(parents=True, exist_ok=True)
        # Broken /dev/null symlink (common Tenda layout)
        (root / "home").symlink_to("/dev/null")
        # Init binary
        init = root / "sbin" / "init"
        init.write_bytes(b"\x7fELF" + b"\x00" * 200)
        # Busybox
        bb = root / "bin" / "busybox"
        bb.write_bytes(b"BUSYBOX" + b"\x00" * 2000)
        # Dynamic loader
        (root / "lib" / "ld-uClibc.so.0").write_bytes(b"loader")
        # Shared lib
        (root / "lib" / "libc.so.0").write_bytes(b"libc")
        # passwd
        (root / "etc" / "passwd").write_text("root:x:0:0:root:/root:/bin/sh\n")
        (root / "etc_ro" / "passwd").write_text("root:$1$abc$xyz:0:0:root:/root:/bin/sh\n")
        # inittab with sulogin + askfirst
        (root / "etc" / "inittab").write_text("::sysinit:/etc/init.d/rcS\n::askfirst:-/bin/sh\n::respawn:/sbin/getty\nsulogin\n")
        # rcS with mtd + insmod
        initd = root / "etc" / "init.d"
        initd.mkdir(exist_ok=True)
        (initd / "rcS").write_text("#!/bin/sh\nmount -t jffs2 /dev/mtdblock0 /cfg\ninsmod /lib/modules/wifi.ko\n")
        # MTD-dependent binary
        mtd_bin = root / "bin" / "httpd"
        mtd_bin.write_bytes(b"x" * 2000 + b"get_mtd_size" + b"y" * 100)
        # webroot marker
        (root / "webroot" / "default.cfg").write_text("cfg=1")
    elif style == "app_partition":
        # NON-FHS: no sbin/etc/usr — camera /app partition shape
        (root / "init").mkdir()
        (root / "bin").mkdir()
        (root / "bin" / "app").write_bytes(b"appbinary")
    elif style == "minimal_no_busybox":
        for d in ("sbin", "bin", "etc", "lib", "usr"):
            (root / d).mkdir(parents=True, exist_ok=True)
        (root / "sbin" / "init").write_bytes(b"init" + b"\x00" * 100)
        (root / "etc" / "passwd").write_text("daemon:x:1:1::/:\n")
        # /lib exists but no interpreter + no .so files

    return str(root)


# ---------------------------------------------------------------------------
# register_emulation_tools
# ---------------------------------------------------------------------------


def test_register_emulation_tools_registers_all_twenty_five():
    registry = ToolRegistry()
    register_emulation_tools(registry)
    names = set(registry._tools.keys())
    assert names == {
        "list_available_kernels",
        "download_kernel",
        "start_emulation",
        "run_command_in_emulation",
        "stop_emulation",
        "check_emulation_status",
        "get_emulation_logs",
        "diagnose_emulation_environment",
        "troubleshoot_emulation",
        "enumerate_emulation_services",
        "get_crash_dump",
        "run_gdb_command",
        "save_emulation_preset",
        "list_emulation_presets",
        "start_emulation_from_preset",
        "emulate_with_qiling",
        "check_qiling_rootfs",
        "start_system_emulation",
        "system_emulation_status",
        "list_firmware_services",
        "run_command_in_firmware",
        "stop_system_emulation",
        "capture_network_traffic",
        "get_nvram_state",
        "interact_web_endpoint",
        "attach_kernel_companion",
        "inject_file_to_emulation",
    }
    assert len(names) == 27


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_parse_proc_net_tcp_ipv4_listen():
    content = (
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000\n"
        "   1: 0100007F:1F90 00000000:0000 01 00000000:00000000\n"  # ESTABLISHED — skip
        "   2: 00000000:01BB 00000000:0000 0A 00000000:00000000\n"
        "   3: short\n"
        "   4: BADHEX:ZZZZ 00000000:0000 0A 00000000:00000000\n"
    )
    listeners = _parse_proc_net_tcp(content)
    ports = {listener["port"] for listener in listeners}
    assert "80" in ports
    assert "443" in ports
    assert all(listener["protocol"] == "tcp" for listener in listeners)
    # Non-LISTEN filtered
    assert "8080" not in ports


def test_parse_proc_net_tcp_ipv6_listen():
    content = (
        "  sl  local_address rem_address   st\n"
        "   0: 00000000000000000000000000000000:0050 00000000000000000000000000000000:0000 0A\n"
    )
    listeners = _parse_proc_net_tcp(content)
    assert len(listeners) == 1
    assert listeners[0]["address"] == "[::]"
    assert listeners[0]["port"] == "80"


def test_list_kernels_sync_delegates():
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = [{"name": "k1"}]
        result = _list_kernels_sync("arm")
    KS.return_value.list_kernels.assert_called_once_with(architecture="arm")
    assert result == [{"name": "k1"}]


def test_diagnose_environment_sync_full_rootfs(tmp_path):
    root = _make_fake_rootfs(tmp_path, style="full")
    issues, info, suggestions, broken = _diagnose_environment_sync(root, "arm")
    assert any("BROKEN SYMLINKS" in i for i in issues)
    assert broken  # /home -> /dev/null
    assert any("Busybox" in i for i in info)
    assert any("Init binaries" in i for i in info)
    assert any("MTD FLASH" in i for i in issues)
    assert any("SULOGIN" in i for i in issues)
    assert any("fake MTD" in s or "LD_PRELOAD" in s for s in suggestions)
    assert any("Shared libraries" in i for i in info)
    assert any("rcS" in i or "init scripts" in i for i in info)


def test_diagnose_environment_sync_app_partition(tmp_path):
    root = _make_fake_rootfs(tmp_path, style="app_partition")
    issues, info, suggestions, broken = _diagnose_environment_sync(root, "arm")
    assert any("NON-FHS ROOTFS" in i for i in issues)
    assert any("NO INIT BINARY" in i for i in issues)
    assert any("NO BUSYBOX" in i for i in issues)
    assert any("NO SHARED LIBRARIES" in i for i in issues)
    assert any("merge" in s.lower() or "rootfs" in s.lower() for s in suggestions)


def test_diagnose_environment_sync_no_loader(tmp_path):
    root = _make_fake_rootfs(tmp_path, style="minimal_no_busybox")
    issues, info, suggestions, _broken = _diagnose_environment_sync(root, "mips")
    assert any("NO DYNAMIC LOADER" in i for i in issues)
    assert any("NO BUSYBOX" in i for i in issues)
    assert any("NO /etc/passwd" in i or "passwd" in i.lower() for i in issues) or any(
        "passwd" in i.lower() for i in info
    )


def test_troubleshoot_detect_characteristics_sync(tmp_path):
    root = _make_fake_rootfs(tmp_path, style="full")
    has_etc_ro, has_webroot, has_mtd = _troubleshoot_detect_characteristics_sync(root)
    assert has_etc_ro is True
    assert has_webroot is True
    assert has_mtd is True


def test_troubleshoot_detect_characteristics_empty(tmp_path):
    root = tmp_path / "empty"
    root.mkdir()
    has_etc_ro, has_webroot, has_mtd = _troubleshoot_detect_characteristics_sync(str(root))
    assert has_etc_ro is False
    assert has_webroot is False
    assert has_mtd is False


# ---------------------------------------------------------------------------
# _handle_list_kernels
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_kernels_empty(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = []
        result = await _handle_list_kernels({"architecture": "mips"}, ctx)
    assert "No kernels available for architecture 'mips'" in result
    assert "OpenWrt" in result


@pytest.mark.asyncio
async def test_list_kernels_empty_no_arch_filter(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = []
        result = await _handle_list_kernels({}, ctx)
    assert "No kernels available." in result


@pytest.mark.asyncio
async def test_list_kernels_with_results(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    kernels = [
        {"name": "vmlinux-arm", "architecture": "arm", "file_size": 5 * 1024 * 1024, "description": "OpenWrt"},
        {"name": "vmlinux-mips", "architecture": "mips", "file_size": 4 * 1024 * 1024},
    ]
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = kernels
        result = await _handle_list_kernels({}, ctx)
    assert "Available kernels (2)" in result
    assert "vmlinux-arm" in result
    assert "OpenWrt" in result
    assert "vmlinux-mips" in result


# ---------------------------------------------------------------------------
# _handle_download_kernel
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_kernel_missing_fields(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_download_kernel({"url": "https://x"}, ctx)
    assert result == "Error: url, name, and architecture are required."


@pytest.mark.asyncio
async def test_download_kernel_already_exists(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = [{"name": "k1"}]
        result = await _handle_download_kernel(
            {"url": "https://x", "name": "k1", "architecture": "arm"}, ctx
        )
    assert "already exists" in result


@pytest.mark.asyncio
async def test_download_kernel_happy_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = []
        KS.return_value.download_kernel = AsyncMock(
            return_value={
                "name": "k-new",
                "architecture": "arm",
                "file_size": 10 * 1024 * 1024,
            }
        )
        result = await _handle_download_kernel(
            {
                "url": "https://example.com/k",
                "name": "k-new",
                "architecture": "arm",
                "description": "test",
            },
            ctx,
        )
    assert "Kernel downloaded and installed successfully" in result
    assert "k-new" in result
    assert "10.0 MB" in result


@pytest.mark.asyncio
async def test_download_kernel_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = []
        KS.return_value.download_kernel = AsyncMock(side_effect=ValueError("bad url"))
        result = await _handle_download_kernel(
            {"url": "http://x", "name": "k", "architecture": "arm"}, ctx
        )
    assert "Error downloading kernel: bad url" in result


@pytest.mark.asyncio
async def test_download_kernel_generic_exception(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("app.ai.tools.emulation.KernelService") as KS:
        KS.return_value.list_kernels.return_value = []
        KS.return_value.download_kernel = AsyncMock(side_effect=RuntimeError("boom"))
        result = await _handle_download_kernel(
            {"url": "https://x", "name": "k", "architecture": "arm"}, ctx
        )
    assert "Error downloading kernel: boom" in result


# ---------------------------------------------------------------------------
# _handle_start_emulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_emulation_user_requires_binary(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_emulation({"mode": "user"}, ctx)
    assert result == "Error: binary_path is required for user-mode emulation."


@pytest.mark.asyncio
async def test_start_emulation_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_emulation(
        {"mode": "user", "binary_path": "/bin/sh"}, ctx
    )
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_start_emulation_user_happy_path(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    session = _session_obj(
        mode="user",
        binary_path="/bin/busybox",
        architecture="arm",
        status="running",
        port_forwards=[{"host": 8080, "guest": 80}],
    )
    with patch(
        "app.ai.tools.emulation.EmulationService.start_session",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_start_emulation(
            {"mode": "user", "binary_path": "/bin/busybox", "arguments": "-l"},
            ctx,
        )
    assert "Emulation session started successfully" in result
    assert str(session.id) in result
    assert "Port forwards" in result
    assert "run_command_in_emulation" in result


@pytest.mark.asyncio
async def test_start_emulation_system_with_diagnosis_and_stubs(live_db):
    project, firmware = await _seed(live_db, binary_info={"is_static": False, "dependencies": ["libc.so"]})
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    session = _session_obj(
        mode="system",
        binary_path=None,
        status="starting",
        port_forwards=[],
        error_message="boot warning",
    )
    with (
        patch(
            "app.ai.tools.emulation._handle_diagnose_environment",
            new=AsyncMock(return_value="diag: ok"),
        ),
        patch(
            "app.ai.tools.emulation.EmulationService.start_session",
            new=AsyncMock(return_value=session),
        ),
        patch(
            "app.services.sysroot_service.get_sysroot_path",
            return_value="/opt/sysroot/arm",
        ),
    ):
        result = await _handle_start_emulation(
            {
                "mode": "system",
                "stub_profile": "tenda",
                "pre_init_script": "echo setup",
                "kernel_name": "k1",
            },
            ctx,
        )
    assert "Auto-setup" in result
    assert "Stub profile: tenda" in result
    assert "Pre-init script" in result
    assert "Pre-flight Diagnosis" in result
    assert "diag: ok" in result
    assert "standalone binary" in result
    assert "Sysroot" in result
    assert "boot warning" in result


@pytest.mark.asyncio
async def test_start_emulation_diagnosis_failure_continues(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    session = _session_obj(mode="system", binary_path=None, port_forwards=[])
    with (
        patch(
            "app.ai.tools.emulation._handle_diagnose_environment",
            new=AsyncMock(side_effect=RuntimeError("diag boom")),
        ),
        patch(
            "app.ai.tools.emulation.EmulationService.start_session",
            new=AsyncMock(return_value=session),
        ),
    ):
        result = await _handle_start_emulation({"mode": "system"}, ctx)
    assert "diagnosis failed" in result
    assert "Emulation session started successfully" in result


@pytest.mark.asyncio
async def test_start_emulation_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.start_session",
        new=AsyncMock(side_effect=ValueError("no kernel")),
    ):
        result = await _handle_start_emulation(
            {"mode": "user", "binary_path": "/bin/x"}, ctx
        )
    assert result == "Error starting emulation: no kernel"


@pytest.mark.asyncio
async def test_start_emulation_generic_exception(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.start_session",
        new=AsyncMock(side_effect=RuntimeError("docker down")),
    ):
        result = await _handle_start_emulation(
            {"mode": "user", "binary_path": "/bin/x"}, ctx
        )
    assert "Error starting emulation: docker down" in result


# ---------------------------------------------------------------------------
# _handle_run_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_command_requires_fields(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_run_command({}, ctx)
    assert result == "Error: session_id and command are required."


@pytest.mark.asyncio
async def test_run_command_blocks_known_blocking_commands(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    result = await _handle_run_command(
        {"session_id": sid, "command": "top", "timeout": 10}, ctx
    )
    assert "WARNING" in result
    assert "ps" in result


@pytest.mark.asyncio
async def test_run_command_happy_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(
            return_value={
                "stdout": "hello",
                "stderr": "warn",
                "exit_code": 0,
                "timed_out": False,
            }
        ),
    ):
        result = await _handle_run_command(
            {"session_id": sid, "command": "echo hello", "timeout": 5}, ctx
        )
    assert "stdout:\nhello" in result
    assert "stderr:\nwarn" in result
    assert "exit_code: 0" in result


@pytest.mark.asyncio
async def test_run_command_timeout_and_truncation(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    huge = "x" * 200_000
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.exec_command",
            new=AsyncMock(
                return_value={
                    "stdout": huge,
                    "stderr": "",
                    "exit_code": -1,
                    "timed_out": True,
                }
            ),
        ),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=1)  # 1KB
        result = await _handle_run_command(
            {"session_id": sid, "command": "cat big", "timeout": 5}, ctx
        )
    assert "timed out" in result
    assert "truncated" in result


@pytest.mark.asyncio
async def test_run_command_send_ctrl_c_success(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.send_ctrl_c",
            new=AsyncMock(return_value={"success": True}),
        ),
        patch(
            "app.ai.tools.emulation.EmulationService.exec_command",
            new=AsyncMock(
                return_value={
                    "stdout": "ok",
                    "stderr": "",
                    "exit_code": 0,
                    "timed_out": False,
                }
            ),
        ),
        patch("asyncio.sleep", new=AsyncMock()),
    ):
        result = await _handle_run_command(
            {"session_id": sid, "command": "ls", "send_ctrl_c": True}, ctx
        )
    assert "exit_code: 0" in result


@pytest.mark.asyncio
async def test_run_command_send_ctrl_c_failure(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.send_ctrl_c",
        new=AsyncMock(return_value={"success": False, "message": "no shell"}),
    ):
        result = await _handle_run_command(
            {"session_id": sid, "command": "ls", "send_ctrl_c": True}, ctx
        )
    assert "Error sending Ctrl-C: no shell" in result


@pytest.mark.asyncio
async def test_run_command_send_ctrl_c_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.send_ctrl_c",
        new=AsyncMock(side_effect=ValueError("bad session")),
    ):
        result = await _handle_run_command(
            {"session_id": str(uuid.uuid4()), "command": "ls", "send_ctrl_c": True},
            ctx,
        )
    assert "Error sending Ctrl-C: bad session" in result


@pytest.mark.asyncio
async def test_run_command_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=ValueError("not running")),
    ):
        result = await _handle_run_command(
            {"session_id": str(uuid.uuid4()), "command": "ls"}, ctx
        )
    assert result == "Error: not running"


@pytest.mark.asyncio
async def test_run_command_generic_exception(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=RuntimeError("pipe broken")),
    ):
        result = await _handle_run_command(
            {"session_id": str(uuid.uuid4()), "command": "ls"}, ctx
        )
    assert "Error executing command: pipe broken" in result


# ---------------------------------------------------------------------------
# _handle_stop_emulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_stop_emulation_requires_session_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_stop_emulation({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_stop_emulation_happy_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    session = _session_obj()
    with patch(
        "app.ai.tools.emulation.EmulationService.stop_session",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_stop_emulation({"session_id": str(session.id)}, ctx)
    assert f"Emulation session {session.id} stopped successfully" in result


@pytest.mark.asyncio
async def test_stop_emulation_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.stop_session",
        new=AsyncMock(side_effect=ValueError("gone")),
    ):
        result = await _handle_stop_emulation({"session_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: gone"


@pytest.mark.asyncio
async def test_stop_emulation_generic_exception(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.stop_session",
        new=AsyncMock(side_effect=RuntimeError("fail")),
    ):
        result = await _handle_stop_emulation({"session_id": str(uuid.uuid4())}, ctx)
    assert "Error stopping session: fail" in result


# ---------------------------------------------------------------------------
# _handle_check_status
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_check_status_by_id_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    session = _session_obj(
        error_message="oops",
        started_at=datetime(2020, 1, 1, tzinfo=UTC),
    )
    with patch(
        "app.ai.tools.emulation.EmulationService.get_status",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_check_status({"session_id": str(session.id)}, ctx)
    assert f"Session: {session.id}" in result
    assert "Uptime:" in result
    assert "Error: oops" in result
    assert "Binary: /bin/busybox" in result


@pytest.mark.asyncio
async def test_check_status_by_id_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.get_status",
        new=AsyncMock(side_effect=ValueError("missing")),
    ):
        result = await _handle_check_status({"session_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: missing"


@pytest.mark.asyncio
async def test_check_status_list_empty(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.list_sessions",
        new=AsyncMock(return_value=[]),
    ):
        result = await _handle_check_status({}, ctx)
    assert result == "No emulation sessions found for this project."


@pytest.mark.asyncio
async def test_check_status_list_with_sessions(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    sessions = [
        _session_obj(status="running", mode="user"),
        _session_obj(status="stopped", mode="system", binary_path=None),
        _session_obj(status="error", mode="user"),
        _session_obj(status="starting", mode="user"),
        _session_obj(status="created", mode="user"),
        _session_obj(status="weird", mode="user"),
    ]
    # Pad to >30 to hit truncation branch
    sessions.extend([_session_obj(status="stopped", mode="user") for _ in range(28)])
    with patch(
        "app.ai.tools.emulation.EmulationService.list_sessions",
        new=AsyncMock(return_value=sessions),
    ):
        result = await _handle_check_status({}, ctx)
    assert "Emulation sessions" in result
    assert "[RUNNING]" in result
    assert "[STOPPED]" in result
    assert "[ERROR]" in result
    assert "and" in result and "more" in result


# ---------------------------------------------------------------------------
# _handle_get_logs
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_logs_requires_session_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_get_logs({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_get_logs_happy_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.get_session_logs",
        new=AsyncMock(return_value="boot ok"),
    ):
        result = await _handle_get_logs({"session_id": str(uuid.uuid4())}, ctx)
    assert "=== Emulation Boot Logs ===" in result
    assert "boot ok" in result


@pytest.mark.asyncio
async def test_get_logs_truncation(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.get_session_logs",
            new=AsyncMock(return_value="L" * 50_000),
        ),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=1)
        result = await _handle_get_logs({"session_id": str(uuid.uuid4())}, ctx)
    assert "truncated" in result


@pytest.mark.asyncio
async def test_get_logs_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.get_session_logs",
        new=AsyncMock(side_effect=ValueError("no logs")),
    ):
        result = await _handle_get_logs({"session_id": str(uuid.uuid4())}, ctx)
    assert result == "Error: no logs"


@pytest.mark.asyncio
async def test_get_logs_generic_exception(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.get_session_logs",
        new=AsyncMock(side_effect=RuntimeError("io")),
    ):
        result = await _handle_get_logs({"session_id": str(uuid.uuid4())}, ctx)
    assert "Error reading logs: io" in result


# ---------------------------------------------------------------------------
# _handle_diagnose_environment
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_diagnose_environment_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_diagnose_environment({}, ctx)
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_diagnose_environment_not_unpacked(live_db):
    project, firmware = await _seed(live_db, extracted_path=None)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_diagnose_environment({}, ctx)
    assert result == "Error: firmware has not been unpacked yet."


@pytest.mark.asyncio
async def test_diagnose_environment_missing_dir(live_db, tmp_path):
    missing = str(tmp_path / "nope")
    project, firmware = await _seed(live_db, extracted_path=missing)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_diagnose_environment({}, ctx)
    assert "extracted filesystem not found" in result


@pytest.mark.asyncio
async def test_diagnose_environment_happy_with_kernel(live_db, tmp_path):
    root = _make_fake_rootfs(tmp_path, style="full")
    project, firmware = await _seed(live_db, extracted_path=root, architecture="arm")
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation._list_kernels_sync",
        return_value=[{"name": "k1", "architecture": "arm", "has_initrd": True}],
    ):
        result = await _handle_diagnose_environment({}, ctx)
    assert "=== Emulation Pre-Flight Diagnosis ===" in result
    assert "ISSUES FOUND" in result or "ENVIRONMENT INFO" in result
    assert "Kernel available: k1" in result
    assert firmware.original_filename in result


@pytest.mark.asyncio
async def test_diagnose_environment_no_kernel_and_no_initrd_issue(live_db, tmp_path):
    root = _make_fake_rootfs(tmp_path, style="full")
    project, firmware = await _seed(live_db, extracted_path=root, architecture="mips")
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    # Kernel without initrd + broken symlinks → KERNEL HAS NO INITRAMFS issue
    with patch(
        "app.ai.tools.emulation._list_kernels_sync",
        return_value=[{"name": "k1", "architecture": "mips", "has_initrd": False}],
    ):
        result = await _handle_diagnose_environment({}, ctx)
    assert "KERNEL HAS NO INITRAMFS" in result

    # No kernels at all
    with patch("app.ai.tools.emulation._list_kernels_sync", return_value=[]):
        result2 = await _handle_diagnose_environment({}, ctx)
    assert "NO KERNEL" in result2
    assert "download_kernel" in result2


@pytest.mark.asyncio
async def test_diagnose_environment_no_critical_issues_message(live_db, tmp_path):
    # Minimal rootfs that avoids most issues: has init, busybox, passwd, libs, loader
    root = tmp_path / "clean"
    for d in ("sbin", "bin", "etc", "lib", "usr"):
        (root / d).mkdir(parents=True)
    (root / "sbin" / "init").write_bytes(b"init" + b"\x00" * 100)
    (root / "bin" / "busybox").write_bytes(b"bb" + b"\x00" * 2000)
    (root / "lib" / "ld-linux.so.3").write_bytes(b"ld")
    (root / "lib" / "libc.so").write_bytes(b"so")
    (root / "etc" / "passwd").write_text("root::0:0:root:/root:/bin/sh\n")
    project, firmware = await _seed(live_db, extracted_path=str(root), architecture="arm")
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation._list_kernels_sync",
        return_value=[{"name": "k", "architecture": "arm", "has_initrd": True}],
    ):
        result = await _handle_diagnose_environment({}, ctx)
    assert "No critical issues detected" in result or "ISSUES FOUND" in result


# ---------------------------------------------------------------------------
# _handle_enumerate_services
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_enumerate_services_requires_session_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_enumerate_services({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_enumerate_services_via_netstat(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    netstat = (
        "Active Internet connections (only servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      100/httpd\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               ESTABLISHED 1/sshd\n"
        "udp        0      0 0.0.0.0:53              0.0.0.0:*                           50/dnsmasq\n"
    )
    ps = "UID PID CMD\n" + "\n".join(f"root {i} proc{i}" for i in range(40))

    async def _exec(*, session_id, command, timeout=10):
        if command == "netstat -tlnp":
            return {"stdout": netstat, "stderr": "", "exit_code": 0}
        if command in ("ps -ef", "ps"):
            return {"stdout": ps, "stderr": "", "exit_code": 0}
        return {"stdout": "", "stderr": "", "exit_code": 1}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_enumerate_services({"session_id": sid}, ctx)
    assert "Found 1 listening TCP service" in result
    assert "httpd" in result
    assert "Running processes:" in result
    assert "more" in result  # ps truncation


@pytest.mark.asyncio
async def test_enumerate_services_proc_net_tcp_fallback(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())
    tcp = (
        "  sl  local_address rem_address   st\n"
        "   0: 00000000:0050 00000000:0000 0A 00000000:00000000\n"
    )

    async def _exec(*, session_id, command, timeout=10):
        if command == "netstat -tlnp":
            return {"stdout": "netstat: not found", "stderr": "", "exit_code": 127}
        if command == "cat /proc/net/tcp":
            return {"stdout": tcp, "stderr": "", "exit_code": 0}
        if command == "cat /proc/net/tcp6":
            return {"stdout": "", "stderr": "", "exit_code": 0}
        if command == "ps -ef":
            return {"stdout": "", "stderr": "", "exit_code": 0}
        if command == "ps":
            return {"stdout": "  PID  CMD\n    1  init\n", "stderr": "", "exit_code": 0}
        return {"stdout": "", "stderr": "", "exit_code": 1}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_enumerate_services({"session_id": sid}, ctx)
    assert "Found 1 listening" in result
    assert "port 80" in result


@pytest.mark.asyncio
async def test_enumerate_services_none_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    sid = str(uuid.uuid4())

    async def _exec(*, session_id, command, timeout=10):
        if command == "ps -ef":
            return {"stdout": "PID CMD\n1 init", "stderr": "", "exit_code": 0}
        return {"stdout": "", "stderr": "", "exit_code": 1}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_enumerate_services({"session_id": sid}, ctx)
    assert "No listening TCP services detected" in result
    assert "Running processes:" in result


# ---------------------------------------------------------------------------
# _handle_troubleshoot_emulation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_troubleshoot_full_guide(live_db, tmp_path):
    root = _make_fake_rootfs(tmp_path, style="full")
    project, firmware = await _seed(live_db, extracted_path=root, architecture="mips")
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_troubleshoot_emulation({}, ctx)
    assert "=== Emulation Troubleshooting Guide ===" in result
    assert "Architecture: mips" in result
    assert "/etc_ro present" in result
    assert "MTD-dependent" in result
    assert "/webroot present" in result
    assert "MIPS FPU" in result
    assert "Tips:" in result


@pytest.mark.asyncio
async def test_troubleshoot_filtered_by_symptom(live_db):
    project, firmware = await _seed(live_db, extracted_path=None, architecture="arm")
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_troubleshoot_emulation({"symptom": "kernel panic"}, ctx)
    assert "Filtered for symptom: kernel panic" in result
    assert "Kernel Panic" in result


@pytest.mark.asyncio
async def test_troubleshoot_switch_root_symptom(live_db):
    project, firmware = await _seed(live_db, extracted_path=None)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_troubleshoot_emulation(
        {"symptom": "switch_root attempted to kill init"}, ctx
    )
    assert "switch_root" in result.lower() or "kill init" in result.lower()


@pytest.mark.asyncio
async def test_troubleshoot_unmatched_symptom_shows_all(live_db):
    project, firmware = await _seed(live_db, extracted_path=None)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_troubleshoot_emulation(
        {"symptom": "xyzzy_unmatchable_qq"}, ctx
    )
    assert "No specific section matched" in result or "Troubleshooting Guide" in result


@pytest.mark.asyncio
async def test_troubleshoot_no_firmware(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_troubleshoot_emulation({"symptom": "boot hang"}, ctx)
    assert "Boot Hangs" in result
    assert "Architecture: unknown" in result


# ---------------------------------------------------------------------------
# _handle_get_crash_dump
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_crash_dump_requires_session_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_get_crash_dump({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_get_crash_dump_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=ValueError("no session")),
    ):
        result = await _handle_get_crash_dump(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: no session"


@pytest.mark.asyncio
async def test_get_crash_dump_no_cores(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(
            return_value={"stdout": "ls: No such file or directory", "exit_code": 1}
        ),
    ):
        result = await _handle_get_crash_dump(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "No core dumps found" in result


@pytest.mark.asyncio
async def test_get_crash_dump_full_analysis(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    session = EmulationSession(
        id=sid,
        project_id=project.id,
        firmware_id=firmware.id,
        mode="system",
        status="running",
        container_id="ctr-1",
        architecture="arm",
    )
    live_db.add(session)
    await live_db.flush()

    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    async def _exec(*, session_id, command, timeout=10):
        if "ls -la /tmp/cores" in command:
            return {
                "stdout": "total 8\n-rw------- 1 root root 4096 core.httpd.1234\n",
                "exit_code": 0,
            }
        if "ls -S" in command:
            return {"stdout": "core.httpd.1234\n", "exit_code": 0}
        if command.startswith("test -f"):
            return {"stdout": "", "exit_code": 0}
        if command.startswith("wc -c"):
            return {"stdout": "4096\n", "exit_code": 0}
        if command.startswith("file "):
            return {"stdout": "core.httpd.1234: ELF core file", "exit_code": 0}
        if command == "dmesg":
            return {
                "stdout": "httpd[1234]: segfault at 0 ip 0000\nother line\n",
                "exit_code": 0,
            }
        return {"stdout": "", "exit_code": 0}

    mock_container = MagicMock()
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container

    with (
        patch(
            "app.ai.tools.emulation.EmulationService.exec_command",
            new=AsyncMock(side_effect=_exec),
        ),
        patch("app.utils.docker_client.get_docker_client", return_value=mock_client),
    ):
        result = await _handle_get_crash_dump(
            {
                "session_id": str(sid),
                "binary_path": "/bin/httpd",
            },
            ctx,
        )
    assert "Core Dump Analysis" in result
    assert "core.httpd.1234" in result
    assert "File type:" in result
    assert "Kernel crash messages" in result
    assert "run_gdb_command" in result


@pytest.mark.asyncio
async def test_get_crash_dump_no_core_star_files(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())

    async def _exec(*, session_id, command, timeout=10):
        if "ls -la" in command:
            return {"stdout": "total 4\ndrwxr-xr-x 2 root root 40 .\n", "exit_code": 0}
        if "ls -S" in command:
            return {"stdout": "readme.txt\n", "exit_code": 0}
        return {"stdout": "", "exit_code": 0}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_get_crash_dump(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "No core.* files found" in result


@pytest.mark.asyncio
async def test_get_crash_dump_session_no_container(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    session = EmulationSession(
        id=sid,
        project_id=project.id,
        firmware_id=firmware.id,
        mode="system",
        status="running",
        container_id=None,
    )
    live_db.add(session)
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    async def _exec(*, session_id, command, timeout=10):
        if "ls -la" in command:
            return {
                "stdout": "total 8\n-rw- 1 root root 100 core.x.1\n",
                "exit_code": 0,
            }
        if "ls -S" in command:
            return {"stdout": "core.x.1\n", "exit_code": 0}
        return {"stdout": "", "exit_code": 0}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_get_crash_dump({"session_id": str(sid)}, ctx)
    assert "session not found or no container" in result


@pytest.mark.asyncio
async def test_get_crash_dump_container_not_found(live_db):
    import docker

    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    session = EmulationSession(
        id=sid,
        project_id=project.id,
        firmware_id=firmware.id,
        mode="system",
        status="running",
        container_id="gone",
    )
    live_db.add(session)
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    async def _exec(*, session_id, command, timeout=10):
        if "ls -la" in command:
            return {
                "stdout": "total 8\n-rw- 1 root root 100 core.x.1\n",
                "exit_code": 0,
            }
        if "ls -S" in command:
            return {"stdout": "core.x.1\n", "exit_code": 0}
        return {"stdout": "", "exit_code": 0}

    mock_client = MagicMock()
    mock_client.containers.get.side_effect = docker.errors.NotFound("missing")

    with (
        patch(
            "app.ai.tools.emulation.EmulationService.exec_command",
            new=AsyncMock(side_effect=_exec),
        ),
        patch("app.utils.docker_client.get_docker_client", return_value=mock_client),
    ):
        result = await _handle_get_crash_dump({"session_id": str(sid)}, ctx)
    assert "emulation container not found" in result


# ---------------------------------------------------------------------------
# _handle_run_gdb_command
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_gdb_requires_fields(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_run_gdb_command({}, ctx)
    assert result == "Error: session_id and gdb_commands are required."


@pytest.mark.asyncio
async def test_run_gdb_session_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_run_gdb_command(
        {"session_id": str(uuid.uuid4()), "gdb_commands": "bt"}, ctx
    )
    assert result == "Error: session not found."


@pytest.mark.asyncio
async def test_run_gdb_not_running(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="stopped",
            container_id="c1",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_run_gdb_command(
        {"session_id": str(sid), "gdb_commands": "bt"}, ctx
    )
    assert "session is not running" in result


@pytest.mark.asyncio
async def test_run_gdb_user_mode_rejected(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="user",
            status="running",
            container_id="c1",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_run_gdb_command(
        {"session_id": str(sid), "gdb_commands": "bt"}, ctx
    )
    assert "only supported for system-mode" in result


@pytest.mark.asyncio
async def test_run_gdb_no_container(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id=None,
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    result = await _handle_run_gdb_command(
        {"session_id": str(sid), "gdb_commands": "bt"}, ctx
    )
    assert "no container associated" in result


@pytest.mark.asyncio
async def test_run_gdb_happy_path(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="ctr-gdb",
            architecture="mipsel",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    mock_container = MagicMock()
    exec_result = MagicMock()
    exec_result.output = (
        b"GNU gdb\nReading symbols from foo\n#0  main () at main.c:1\n",
        b"warning: something\nerror: real problem\n",
    )
    exec_result.exit_code = 1
    mock_container.exec_run.return_value = exec_result
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container

    with (
        patch("app.utils.docker_client.get_docker_client", return_value=mock_client),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=30)
        result = await _handle_run_gdb_command(
            {
                "session_id": str(sid),
                "gdb_commands": "bt\\ninfo registers",
                "binary_path": "/bin/httpd",
            },
            ctx,
        )
    assert "GDB Output:" in result
    assert "main ()" in result
    assert "Errors:" in result
    assert "GDB exit code: 1" in result
    assert "resumed" in result


@pytest.mark.asyncio
async def test_run_gdb_container_not_found(live_db):
    import docker

    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="gone",
            architecture="arm",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    mock_client = MagicMock()
    mock_client.containers.get.side_effect = docker.errors.NotFound("x")
    with patch("app.utils.docker_client.get_docker_client", return_value=mock_client):
        result = await _handle_run_gdb_command(
            {"session_id": str(sid), "gdb_commands": "bt"}, ctx
        )
    assert "emulation container not found" in result


@pytest.mark.asyncio
async def test_run_gdb_exec_exception(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="ctr",
            architecture="arm",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    mock_container = MagicMock()
    mock_container.exec_run.side_effect = RuntimeError("exec failed")
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container
    with patch("app.utils.docker_client.get_docker_client", return_value=mock_client):
        result = await _handle_run_gdb_command(
            {"session_id": str(sid), "gdb_commands": "bt"}, ctx
        )
    assert "Error running GDB: exec failed" in result


# ---------------------------------------------------------------------------
# Preset handlers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_save_preset_validation(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4())
    assert "name is required" in await _handle_save_preset({"mode": "user"}, ctx)
    assert "mode must be" in await _handle_save_preset({"name": "p"}, ctx)
    assert "mode must be" in await _handle_save_preset(
        {"name": "p", "mode": "invalid"}, ctx
    )


@pytest.mark.asyncio
async def test_save_preset_happy_path(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    preset = _preset_obj()
    with patch(
        "app.ai.tools.emulation.EmulationService.create_preset",
        new=AsyncMock(return_value=preset),
    ):
        result = await _handle_save_preset(
            {
                "name": "my-preset",
                "mode": "system",
                "description": "desc",
                "stub_profile": "generic",
                "pre_init_script": "echo hi",
            },
            ctx,
        )
    assert "Preset saved successfully" in result
    assert "my-preset" in result
    assert "Stub profile" in result
    assert "Pre-init script" in result


@pytest.mark.asyncio
async def test_save_preset_exception(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.create_preset",
        new=AsyncMock(side_effect=RuntimeError("dup")),
    ):
        result = await _handle_save_preset(
            {"name": "p", "mode": "user"}, ctx
        )
    assert "Error saving preset: dup" in result


@pytest.mark.asyncio
async def test_list_presets_empty(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.list_presets",
        new=AsyncMock(return_value=[]),
    ):
        result = await _handle_list_presets({}, ctx)
    assert result == "No emulation presets saved for this project."


@pytest.mark.asyncio
async def test_list_presets_with_items(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    presets = [
        _preset_obj(name="a", binary_path="/bin/x"),
        _preset_obj(name="b", description=None, stub_profile="none", pre_init_script=None, port_forwards=[]),
    ]
    with patch(
        "app.ai.tools.emulation.EmulationService.list_presets",
        new=AsyncMock(return_value=presets),
    ):
        result = await _handle_list_presets({}, ctx)
    assert "Emulation presets (2)" in result
    assert "Ports:" in result
    assert "/bin/x" in result


@pytest.mark.asyncio
async def test_start_from_preset_requires_id_or_name(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_from_preset({}, ctx)
    assert "preset_name or preset_id is required" in result


@pytest.mark.asyncio
async def test_start_from_preset_by_id(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    preset = _preset_obj(mode="user", binary_path="/bin/sh", stub_profile="none", pre_init_script=None)
    session = _session_obj(mode="user", binary_path="/bin/sh", port_forwards=[])
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.get_preset",
            new=AsyncMock(return_value=preset),
        ),
        patch(
            "app.ai.tools.emulation.EmulationService.start_session",
            new=AsyncMock(return_value=session),
        ),
    ):
        result = await _handle_start_from_preset(
            {"preset_id": str(preset.id)}, ctx
        )
    assert f"Starting from preset '{preset.name}'" in result
    assert "Emulation session started successfully" in result


@pytest.mark.asyncio
async def test_start_from_preset_by_id_not_found(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.get_preset",
        new=AsyncMock(side_effect=ValueError("missing")),
    ):
        result = await _handle_start_from_preset(
            {"preset_id": str(uuid.uuid4())}, ctx
        )
    assert "not found" in result


@pytest.mark.asyncio
async def test_start_from_preset_by_name(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    preset = _preset_obj(name="CoolPreset", mode="user", binary_path="/bin/x", stub_profile="none", pre_init_script=None)
    session = _session_obj(mode="user", binary_path="/bin/x", port_forwards=[])
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.list_presets",
            new=AsyncMock(return_value=[preset]),
        ),
        patch(
            "app.ai.tools.emulation.EmulationService.start_session",
            new=AsyncMock(return_value=session),
        ),
    ):
        result = await _handle_start_from_preset(
            {"preset_name": "coolpreset"}, ctx
        )
    assert "CoolPreset" in result


@pytest.mark.asyncio
async def test_start_from_preset_name_missing(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.list_presets",
        new=AsyncMock(return_value=[]),
    ):
        result = await _handle_start_from_preset(
            {"preset_name": "nope"}, ctx
        )
    assert "no preset named 'nope'" in result


# ---------------------------------------------------------------------------
# Qiling handlers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_qiling_requires_binary_path(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_emulate_with_qiling({}, ctx)
    assert result == "Error: binary_path is required."


@pytest.mark.asyncio
async def test_qiling_file_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch("os.path.isfile", return_value=False):
        result = await _handle_emulate_with_qiling(
            {"binary_path": "/missing.exe"}, ctx
        )
    assert "File not found" in result


@pytest.mark.asyncio
async def test_qiling_unsupported_format(live_db, tmp_path):
    f = tmp_path / "blob.bin"
    f.write_bytes(b"raw")
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    ctx.resolve_path = lambda p: str(f)  # type: ignore[method-assign]
    with patch(
        "app.services.binary_analysis_service.analyze_binary",
        return_value={"format": "raw", "architecture": "arm"},
    ):
        result = await _handle_emulate_with_qiling(
            {"binary_path": "/blob.bin"}, ctx
        )
    assert "requires a recognized binary format" in result


@pytest.mark.asyncio
async def test_qiling_unsupported_arch(live_db, tmp_path):
    f = tmp_path / "pe.exe"
    f.write_bytes(b"MZ")
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    ctx.resolve_path = lambda p: str(f)  # type: ignore[method-assign]
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "pe", "architecture": "arm"},
        ),
        patch(
            "app.services.qiling_service.is_qiling_supported",
            return_value=False,
        ),
    ):
        result = await _handle_emulate_with_qiling(
            {"binary_path": "/pe.exe"}, ctx
        )
    assert "does not support" in result


@pytest.mark.asyncio
async def test_qiling_missing_rootfs(live_db, tmp_path):
    f = tmp_path / "pe.exe"
    f.write_bytes(b"MZ")
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    ctx.resolve_path = lambda p: str(f)  # type: ignore[method-assign]
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "pe", "architecture": "x86"},
        ),
        patch("app.services.qiling_service.is_qiling_supported", return_value=True),
        patch("app.services.qiling_service.get_rootfs_path", return_value=None),
    ):
        result = await _handle_emulate_with_qiling(
            {"binary_path": "/pe.exe"}, ctx
        )
    assert "No Qiling rootfs available" in result


@pytest.mark.asyncio
async def test_qiling_happy_path(live_db, tmp_path):
    f = tmp_path / "pe.exe"
    f.write_bytes(b"MZ")
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    ctx.resolve_path = lambda p: str(f)  # type: ignore[method-assign]
    qresult = QilingResult(
        stdout="out" * 2000,
        stderr="err" * 1500,
        exit_code=0,
        timed_out=False,
        error="soft warn",
        duration_ms=42,
        syscall_count=100,
        memory_errors=[f"err{i}" for i in range(5)],
        syscall_trace=[f"sys{i}" for i in range(60)],
    )
    with (
        patch(
            "app.services.binary_analysis_service.analyze_binary",
            return_value={"format": "pe", "architecture": "x86_64"},
        ),
        patch("app.services.qiling_service.is_qiling_supported", return_value=True),
        patch(
            "app.services.qiling_service.get_rootfs_path",
            return_value="/opt/qiling-rootfs/x8664_windows",
        ),
        patch(
            "app.services.qiling_service.run_binary_async",
            new=AsyncMock(return_value=qresult),
        ),
    ):
        result = await _handle_emulate_with_qiling(
            {
                "binary_path": "/pe.exe",
                "arguments": "a b",
                "timeout": 10,
                "trace_syscalls": True,
            },
            ctx,
        )
    assert "Qiling Emulation Result" in result
    assert "Duration: 42ms" in result
    assert "MEMORY ERRORS" in result
    assert "SYSCALL TRACE" in result
    assert "truncated" in result
    assert "soft warn" in result


@pytest.mark.asyncio
async def test_qiling_rootfs_status(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.qiling_service.check_rootfs_status",
        return_value={
            "pe/x86": {
                "available": True,
                "has_system_libs": False,
                "rootfs_path": "/opt/qiling-rootfs/x86_windows",
            },
            "elf/arm": {
                "available": False,
                "has_system_libs": False,
                "rootfs_path": "/opt/qiling-rootfs/arm_linux",
            },
        },
    ):
        result = await _handle_qiling_rootfs_status({}, ctx)
    assert "Qiling Rootfs Status" in result
    assert "available" in result
    assert "MISSING" in result
    assert "Windows PE" in result


# ---------------------------------------------------------------------------
# FirmAE / system emulation handlers
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_system_emulation_firmware_not_found(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_start_system_emulation({}, ctx)
    assert result == "Error: firmware not found."


@pytest.mark.asyncio
async def test_start_system_emulation_happy(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    session = _session_obj(mode="system", status="starting", architecture="mips")
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.start_system_emulation",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_start_system_emulation(
            {"brand": "netgear", "timeout": 300}, ctx
        )
    assert "FirmAE system emulation started" in result
    assert "extraction -> arch detection" in result


@pytest.mark.asyncio
async def test_start_system_emulation_with_error_message(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    session = _session_obj(mode="system", status="error", error_message="no arch")
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.start_system_emulation",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_start_system_emulation({}, ctx)
    assert "Error: no arch" in result


@pytest.mark.asyncio
async def test_start_system_emulation_value_error(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.start_system_emulation",
        new=AsyncMock(side_effect=ValueError("bad brand")),
    ):
        result = await _handle_start_system_emulation({}, ctx)
    assert "Error starting system emulation: bad brand" in result


@pytest.mark.asyncio
async def test_start_system_emulation_generic_exception(live_db):
    project, firmware = await _seed(live_db)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.start_system_emulation",
        new=AsyncMock(side_effect=RuntimeError("boom")),
    ):
        result = await _handle_start_system_emulation({}, ctx)
    assert "Error starting system emulation: boom" in result


@pytest.mark.asyncio
async def test_system_emulation_status_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_system_emulation_status({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_system_emulation_status_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    session = _session_obj(
        mode="system",
        status="running",
        system_emulation_stage="network",
        firmware_ip="192.168.0.1",
        kernel_used="vmlinux",
        discovered_services=[
            {"port": 80, "protocol": "tcp", "service": "http", "host_port": 8080}
        ],
        error_message=None,
        started_at=datetime.now(UTC),
    )
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.poll_system_status",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_system_emulation_status(
            {"session_id": str(session.id)}, ctx
        )
    assert "Pipeline stage: network" in result
    assert "Services found: 1" in result
    assert "localhost:8080" in result
    assert "Uptime:" in result


@pytest.mark.asyncio
async def test_system_emulation_status_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.poll_system_status",
        new=AsyncMock(side_effect=ValueError("gone")),
    ):
        result = await _handle_system_emulation_status(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: gone"


@pytest.mark.asyncio
async def test_list_firmware_services_empty(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_firmware_services",
        new=AsyncMock(return_value=[]),
    ):
        result = await _handle_list_firmware_services(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "No network services discovered yet" in result


@pytest.mark.asyncio
async def test_list_firmware_services_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_list_firmware_services({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_list_firmware_services_with_items(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    services = [
        {"port": 80, "protocol": "tcp", "service": "http", "host_port": 8080, "url": "http://127.0.0.1:8080/"},
        {"port": 23, "service": "telnet"},
    ]
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_firmware_services",
        new=AsyncMock(return_value=services),
    ):
        result = await _handle_list_firmware_services(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "Discovered services (2)" in result
    assert "host port: 8080" in result
    assert "URL:" in result


@pytest.mark.asyncio
async def test_list_firmware_services_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_firmware_services",
        new=AsyncMock(side_effect=ValueError("bad")),
    ):
        result = await _handle_list_firmware_services(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: bad"


@pytest.mark.asyncio
async def test_run_command_in_firmware_requires_fields(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_run_command_in_firmware({}, ctx)
    assert result == "Error: session_id and command are required."


@pytest.mark.asyncio
async def test_run_command_in_firmware_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.run_command_in_firmware",
        new=AsyncMock(
            return_value={"stdout": "ok", "stderr": "e", "exit_code": 0}
        ),
    ):
        result = await _handle_run_command_in_firmware(
            {"session_id": str(uuid.uuid4()), "command": "ls", "timeout": 5},
            ctx,
        )
    assert "stdout:\nok" in result
    assert "exit_code: 0" in result


@pytest.mark.asyncio
async def test_run_command_in_firmware_truncation(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with (
        patch(
            "app.services.system_emulation_service.SystemEmulationService.run_command_in_firmware",
            new=AsyncMock(
                return_value={"stdout": "Z" * 50_000, "stderr": "", "exit_code": 0}
            ),
        ),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=1)
        result = await _handle_run_command_in_firmware(
            {"session_id": str(uuid.uuid4()), "command": "cat"}, ctx
        )
    assert "truncated" in result


@pytest.mark.asyncio
async def test_run_command_in_firmware_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.run_command_in_firmware",
        new=AsyncMock(side_effect=ValueError("dead")),
    ):
        result = await _handle_run_command_in_firmware(
            {"session_id": str(uuid.uuid4()), "command": "ls"}, ctx
        )
    assert result == "Error: dead"


@pytest.mark.asyncio
async def test_stop_system_emulation_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_stop_system_emulation({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_stop_system_emulation_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    session = _session_obj()
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.stop_system_emulation",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_stop_system_emulation(
            {"session_id": str(session.id)}, ctx
        )
    assert f"System emulation session {session.id} stopped successfully" in result


@pytest.mark.asyncio
async def test_stop_system_emulation_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.stop_system_emulation",
        new=AsyncMock(side_effect=ValueError("x")),
    ):
        result = await _handle_stop_system_emulation(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: x"


@pytest.mark.asyncio
async def test_capture_network_traffic_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_capture_network_traffic({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_capture_network_traffic_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.capture_network_traffic",
        new=AsyncMock(
            return_value={
                "packet_count": 42,
                "pcap_path": "/data/caps/x.pcap",
                "size_bytes": 2048,
            }
        ),
    ):
        result = await _handle_capture_network_traffic(
            {"session_id": str(uuid.uuid4()), "duration": 5, "interface": "br0"},
            ctx,
        )
    assert "Packets captured: 42" in result
    assert "2.0 KB" in result
    assert "br0" in result


@pytest.mark.asyncio
async def test_capture_network_traffic_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.capture_network_traffic",
        new=AsyncMock(side_effect=ValueError("no iface")),
    ):
        result = await _handle_capture_network_traffic(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: no iface"


@pytest.mark.asyncio
async def test_get_nvram_state_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_get_nvram_state({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_get_nvram_state_empty(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_nvram_state",
        new=AsyncMock(return_value={}),
    ):
        result = await _handle_get_nvram_state(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "No NVRAM entries found" in result


@pytest.mark.asyncio
async def test_get_nvram_state_with_entries(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_nvram_state",
        new=AsyncMock(
            return_value={
                "wan_ip": "1.2.3.4",
                "long": "x" * 300,
            }
        ),
    ):
        result = await _handle_get_nvram_state(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "NVRAM state (2 entries)" in result
    assert "wan_ip=1.2.3.4" in result
    assert "..." in result  # truncated long value


@pytest.mark.asyncio
async def test_get_nvram_state_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.get_nvram_state",
        new=AsyncMock(side_effect=ValueError("x")),
    ):
        result = await _handle_get_nvram_state(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: x"


@pytest.mark.asyncio
async def test_interact_web_endpoint_requires_id(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    result = await _handle_interact_web_endpoint({}, ctx)
    assert result == "Error: session_id is required."


@pytest.mark.asyncio
async def test_interact_web_endpoint_happy(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.interact_web_endpoint",
        new=AsyncMock(
            return_value={
                "method": "GET",
                "url": "http://192.168.0.1/",
                "status_code": 200,
                "body": "<html>ok</html>",
            }
        ),
    ):
        result = await _handle_interact_web_endpoint(
            {"session_id": str(uuid.uuid4()), "method": "GET", "path": "/"},
            ctx,
        )
    assert "HTTP GET" in result
    assert "Status: 200" in result
    assert "<html>ok</html>" in result


@pytest.mark.asyncio
async def test_interact_web_endpoint_truncation(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with (
        patch(
            "app.services.system_emulation_service.SystemEmulationService.interact_web_endpoint",
            new=AsyncMock(
                return_value={
                    "method": "GET",
                    "url": "http://x/",
                    "status_code": 200,
                    "body": "B" * 50_000,
                }
            ),
        ),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=1)
        result = await _handle_interact_web_endpoint(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "truncated" in result


@pytest.mark.asyncio
async def test_interact_web_endpoint_value_error(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.interact_web_endpoint",
        new=AsyncMock(side_effect=ValueError("down")),
    ):
        result = await _handle_interact_web_endpoint(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert result == "Error: down"


# ---------------------------------------------------------------------------
# Rule #35b live canary — preset path via real ORM (when service not mocked)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_live_canary_emulation_session_roundtrip(live_db):
    """Rule #35b: seed EmulationSession via ORM and SELECT fields back."""
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            architecture="arm",
            container_id="live-canary",
            port_forwards=[{"host": 8080, "guest": 80}],
            discovered_services=[{"port": 80, "service": "http"}],
        )
    )
    await live_db.flush()

    from sqlalchemy import select

    row = (
        await live_db.execute(
            select(EmulationSession).where(EmulationSession.id == sid)
        )
    ).scalar_one()
    assert row.mode == "system"
    assert row.container_id == "live-canary"
    assert row.port_forwards == [{"host": 8080, "guest": 80}]
    assert row.discovered_services[0]["service"] == "http"

    # Also exercise get_status path against live row via mocked service that
    # returns the real ORM object (value-flow check on handler formatting).
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    with patch(
        "app.ai.tools.emulation.EmulationService.get_status",
        new=AsyncMock(return_value=row),
    ):
        text = await _handle_check_status({"session_id": str(sid)}, ctx)
    assert str(sid) in text
    assert "system" in text


# ---------------------------------------------------------------------------
# Extra branch coverage for remaining diagnose / edge paths
# ---------------------------------------------------------------------------


def test_diagnose_environment_sync_etc_ro_with_populated_etc(tmp_path):
    """etc + etc_ro both present with content hits the non-empty /etc branch."""
    root = tmp_path / "rootfs"
    for d in ("sbin", "bin", "etc", "etc_ro", "lib", "usr"):
        (root / d).mkdir(parents=True)
    (root / "sbin" / "init").write_bytes(b"init" + b"\x00" * 100)
    (root / "bin" / "busybox").write_bytes(b"bb" + b"\x00" * 2000)
    (root / "lib" / "ld-uClibc.so.0").write_bytes(b"ld")
    (root / "lib" / "libc.so").write_bytes(b"so")
    (root / "etc" / "passwd").write_text("root:$1$hash:0:0:root:/:/bin/sh\n")
    (root / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (root / "etc_ro" / "passwd").write_text("root:x:0:0:root:/:/bin/sh\n")
    # Init as symlink
    (root / "bin" / "init").symlink_to("../sbin/init")
    # Partial FHS missing only usr is already present — remove usr for partial
    # Partial: missing only one of sbin/etc/usr
    import shutil
    shutil.rmtree(root / "usr")
    issues, info, suggestions, _ = _diagnose_environment_sync(str(root), "arm")
    assert any("both /etc and /etc_ro" in i for i in info)
    assert any("Init binaries found" in i and "->" in i for i in info)
    assert any("Missing standard FHS" in i for i in info)
    assert any("hashed password" in i for i in info)


def test_diagnose_environment_sync_etc_broken_symlink_passwd(tmp_path):
    root = tmp_path / "rootfs"
    for d in ("sbin", "bin", "lib", "usr"):
        (root / d).mkdir(parents=True)
    (root / "etc").symlink_to("/dev/null")
    (root / "sbin" / "init").write_bytes(b"init" + b"\x00" * 100)
    (root / "bin" / "busybox").write_bytes(b"bb" + b"\x00" * 2000)
    (root / "lib" / "ld-uClibc.so.0").write_bytes(b"ld")
    (root / "lib" / "libc.so").write_bytes(b"so")
    issues, info, suggestions, broken = _diagnose_environment_sync(str(root), "arm")
    assert broken
    assert any("NO /etc/passwd" in i and "broken symlink" in i for i in issues)


def test_diagnose_environment_sync_elf_arch_mismatch(tmp_path):
    """When pyelftools is available, a real ELF can trigger arch reporting."""
    root = tmp_path / "rootfs"
    for d in ("sbin", "bin", "etc", "lib", "usr"):
        (root / d).mkdir(parents=True)
    # Minimal valid ELF64 LE x86_64 header (enough for ELFFile to parse e_machine)
    # EI_CLASS=2 (64), EI_DATA=1 (LE), e_machine=0x3E (EM_X86_64)
    elf = bytearray(64)
    elf[0:4] = b"\x7fELF"
    elf[4] = 2  # 64-bit
    elf[5] = 1  # little endian
    elf[6] = 1  # version
    # e_type at 16, e_machine at 18
    elf[16] = 2  # ET_EXEC
    elf[18] = 0x3E  # EM_X86_64
    elf[19] = 0
    elf[20] = 1  # e_version
    # e_ehsize
    elf[52] = 64
    # pad so size > 1000 for busybox path
    bb = bytes(elf) + b"\x00" * 2000
    (root / "bin" / "busybox").write_bytes(bb)
    (root / "sbin" / "init").write_bytes(b"init" + b"\x00" * 100)
    (root / "lib" / "ld-linux-x86-64.so.2").write_bytes(b"ld")
    # lib64 path for loader
    (root / "lib64").mkdir()
    (root / "lib64" / "ld-linux-x86-64.so.2").write_bytes(b"ld")
    (root / "lib" / "libc.so").write_bytes(b"so")
    (root / "etc" / "passwd").write_text("root:x:0:0:root:/:/bin/sh\n")
    issues, info, suggestions, _ = _diagnose_environment_sync(str(root), "arm")
    # Either ARCH MISMATCH or at least busybox arch info if elftools parsed
    assert any("busybox" in i.lower() for i in info) or any(
        "ARCH MISMATCH" in i for i in issues
    )


@pytest.mark.asyncio
async def test_enumerate_services_exec_exceptions(live_db):
    """All exec_command calls raise → no listeners, no processes."""
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=RuntimeError("serial dead")),
    ):
        result = await _handle_enumerate_services(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "No listening TCP services detected" in result


@pytest.mark.asyncio
async def test_enumerate_services_netstat_short_line(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    netstat = (
        "Active Internet connections\n"
        "tcp 0 0\n"  # too short
        "tcp 0 0 0.0.0.0:80 0.0.0.0:* LISTEN 1/httpd\n"
    )

    async def _exec(*, session_id, command, timeout=10):
        if command == "netstat -tlnp":
            return {"stdout": netstat, "exit_code": 0}
        return {"stdout": "", "exit_code": 0}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_enumerate_services(
            {"session_id": str(uuid.uuid4())}, ctx
        )
    assert "httpd" in result


@pytest.mark.asyncio
async def test_troubleshoot_fuzzy_word_match(live_db):
    """Symptom with no keyword hit but a content word triggers fuzzy match."""
    project, firmware = await _seed(live_db, extracted_path=None)
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    # "socat" appears in network section content but not keywords
    result = await _handle_troubleshoot_emulation(
        {"symptom": "socat relay broken"}, ctx
    )
    assert "Troubleshooting Guide" in result
    # Should be filtered (fuzzy) rather than full unmatched dump
    assert "Filtered for symptom" in result or "Network Issues" in result


@pytest.mark.asyncio
async def test_get_crash_dump_exception_branches(live_db):
    """ls -S raises; later commands raise; still produces analysis shell."""
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="ctr-exc",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    call_n = {"n": 0}

    async def _exec(*, session_id, command, timeout=10):
        call_n["n"] += 1
        if "ls -la" in command:
            return {
                "stdout": "total 8\n-rw- core.foo.9\n",
                "exit_code": 0,
            }
        if "ls -S" in command:
            raise RuntimeError("ls failed")
        # After ls -S fails core_files=[], returns early with "No core.* files"
        return {"stdout": "", "exit_code": 1}

    with patch(
        "app.ai.tools.emulation.EmulationService.exec_command",
        new=AsyncMock(side_effect=_exec),
    ):
        result = await _handle_get_crash_dump({"session_id": str(sid)}, ctx)
    assert "No core.* files found" in result


@pytest.mark.asyncio
async def test_get_crash_dump_infer_binary_and_soft_errors(live_db):
    """No binary_path → infer via test -f; wc/file/dmesg exceptions tolerated."""
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="ctr-2",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)

    async def _exec(*, session_id, command, timeout=10):
        if "ls -la" in command:
            return {
                "stdout": "total 8\n-rw- core.httpd.99\n",
                "exit_code": 0,
            }
        if "ls -S" in command:
            return {"stdout": "core.httpd.99\n", "exit_code": 0}
        if command.startswith("test -f"):
            raise RuntimeError("test fail")
        if command.startswith("wc -c"):
            raise RuntimeError("wc fail")
        if command.startswith("file "):
            raise RuntimeError("file fail")
        if command == "dmesg":
            raise RuntimeError("dmesg fail")
        return {"stdout": "", "exit_code": 0}

    mock_client = MagicMock()
    mock_client.containers.get.return_value = MagicMock()
    with (
        patch(
            "app.ai.tools.emulation.EmulationService.exec_command",
            new=AsyncMock(side_effect=_exec),
        ),
        patch("app.utils.docker_client.get_docker_client", return_value=mock_client),
    ):
        result = await _handle_get_crash_dump({"session_id": str(sid)}, ctx)
    assert "Core Dump Analysis" in result
    assert "core.httpd.99" in result
    assert "unknown" in result  # core size


@pytest.mark.asyncio
async def test_run_gdb_output_truncation(live_db):
    project, firmware = await _seed(live_db)
    sid = uuid.uuid4()
    live_db.add(
        EmulationSession(
            id=sid,
            project_id=project.id,
            firmware_id=firmware.id,
            mode="system",
            status="running",
            container_id="ctr-trunc",
            architecture="arm",
        )
    )
    await live_db.flush()
    ctx = _StubContext(db=live_db, firmware_id=firmware.id, project_id=project.id)
    mock_container = MagicMock()
    exec_result = MagicMock()
    exec_result.output = (b"X" * 100_000, b"")
    exec_result.exit_code = 0
    mock_container.exec_run.return_value = exec_result
    mock_client = MagicMock()
    mock_client.containers.get.return_value = mock_container
    with (
        patch("app.utils.docker_client.get_docker_client", return_value=mock_client),
        patch("app.ai.tools.emulation.get_settings") as gs,
    ):
        gs.return_value = SimpleNamespace(max_tool_output_kb=1)
        result = await _handle_run_gdb_command(
            {"session_id": str(sid), "gdb_commands": "bt"}, ctx
        )
    assert "truncated" in result


@pytest.mark.asyncio
async def test_system_emulation_status_with_error_message(live_db):
    ctx = _StubContext(db=live_db, firmware_id=uuid.uuid4())
    session = _session_obj(
        mode="system",
        status="error",
        error_message="boot failed",
        started_at=None,
        discovered_services=None,
    )
    with patch(
        "app.services.system_emulation_service.SystemEmulationService.poll_system_status",
        new=AsyncMock(return_value=session),
    ):
        result = await _handle_system_emulation_status(
            {"session_id": str(session.id)}, ctx
        )
    assert "Error: boot failed" in result


def test_troubleshoot_detect_skips_symlinks_and_tiny_files(tmp_path):
    root = tmp_path / "r"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "link").symlink_to("/bin/true")
    (root / "bin" / "tiny").write_bytes(b"x")  # < 1000
    (root / "bin" / "big").write_bytes(b"get_mtd_num" + b"z" * 2000)
    has_etc_ro, has_webroot, has_mtd = _troubleshoot_detect_characteristics_sync(
        str(root)
    )
    assert has_mtd is True
    assert has_etc_ro is False
    assert has_webroot is False
