"""Phase ι.B.E contract tests: linux_systemd MCP tools (SECOND LINUX).

Per Rule #35b: live canaries via make_live_db. Tests verify that the
MCP tools return the actual persisted shape from the ι.B.A table, not
just that .add() was called.

Mirrors test_linux_journald_tools.py shape — 5 per-firmware tools
(list / lookup / search / status / trigger) + 1 cross-firmware
aggregation tool with contract assertions across happy-path + 404 +
409 + filter shapes + supply-chain signal aggregation.

Includes coverage for the FIRST-of-kind
lookup_systemd_unit_across_firmwares tool — cross-firmware aggregation
within a project AND globally; supply_chain_signal emission on
match_count >= 2.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.linux_systemd import (
    _handle_list_systemd_units,
    _handle_lookup_systemd_unit,
    _handle_lookup_systemd_unit_across_firmwares,
    _handle_search_systemd_units,
    _handle_systemd_walk_status,
    _handle_trigger_systemd_walk,
    register_linux_systemd_tools,
)
from app.models import Firmware, LinuxSystemdUnit, Project
from app.services.jsonb_normalizers import (
    _stamp_linux_systemd_units_anomaly_flags,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the systemd MCP handlers."""

    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None


def _make_firmware(
    project_id: uuid.UUID, name: str, sha_seed: str
) -> Firmware:
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


def _make_systemd_unit(
    firmware_id: uuid.UUID,
    *,
    unit_name: str = "sshd",
    unit_type: str = "service",
    unit_path: str | None = None,
    description: str | None = "OpenSSH server",
    exec_start: str | None = "/usr/sbin/sshd -D",
    user: str | None = "sshd",
    working_directory: str | None = None,
    wanted_by: list[str] | None = None,
    enabled: bool = True,
    anomaly_flags_override: dict | None = None,
) -> LinuxSystemdUnit:
    default_flags = {
        "suspicious_path": False,
        "suspicious_unit_name": False,
        "socket_unusual_port": False,
        "root_minimal_deps": False,
        "disabled_but_present": False,
        "enabled_outside_standard": False,
        "obfuscated_exec": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    return LinuxSystemdUnit(
        firmware_id=firmware_id,
        unit_path=(
            unit_path
            or f"/etc/systemd/system/{unit_name}.{unit_type}"
        ),
        unit_type=unit_type,
        unit_name=unit_name,
        description=description,
        exec_start=exec_start,
        exec_start_pre=None,
        exec_stop=None,
        user=user,
        working_directory=working_directory,
        wanted_by=wanted_by or ["multi-user.target"],
        required_by=None,
        requires=None,
        after=None,
        before=None,
        enabled=enabled,
        triggers=None,
        socket_listen=None,
        anomaly_flags=_stamp_linux_systemd_units_anomaly_flags(
            default_flags
        ),
        unit_raw="[Unit]\nDescription=Test\n",
    )


# ── Registration test ────────────────────────────────────────────────────────


def test_register_linux_systemd_tools_registers_six():
    """register_linux_systemd_tools must register exactly the six
    ι.B.E tools (5 per-firmware + 1 cross-firmware aggregation)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_linux_systemd_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "list_systemd_units" in names
    assert "lookup_systemd_unit" in names
    assert "search_systemd_units" in names
    assert "systemd_walk_status" in names
    assert "trigger_systemd_walk" in names
    assert "lookup_systemd_unit_across_firmwares" in names
    assert len(reg._tools) >= 6


# ── list_systemd_units ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_systemd_units_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="ι.B.E list empty")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "le.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert out["systemd_units"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_list_systemd_units_returns_all_when_no_filters():
    async with make_live_db() as db:
        project = Project(name="ι.B.E list all")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "la.bin", "a")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(firmware.id, unit_name="sshd"))
        db.add(_make_systemd_unit(
            firmware.id, unit_name="cron", unit_type="timer"
        ))
        db.add(_make_systemd_unit(
            firmware.id, unit_name="dbus", unit_type="socket"
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 3
        assert len(out["systemd_units"]) == 3


@pytest.mark.asyncio
async def test_list_systemd_units_filters_by_unit_type():
    async with make_live_db() as db:
        project = Project(name="ι.B.E type filter")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "lt.bin", "t")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(firmware.id, unit_name="a", unit_type="service"))
        db.add(_make_systemd_unit(firmware.id, unit_name="b", unit_type="timer"))
        db.add(_make_systemd_unit(firmware.id, unit_name="c", unit_type="timer"))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units(
            {"unit_type": "timer"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 2


@pytest.mark.asyncio
async def test_list_systemd_units_filters_by_enabled():
    async with make_live_db() as db:
        project = Project(name="ι.B.E enabled filter")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "le.bin", "e")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(firmware.id, unit_name="on", enabled=True))
        db.add(_make_systemd_unit(firmware.id, unit_name="off", enabled=False))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units(
            {"enabled": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["systemd_units"][0]["unit_name"] == "on"


@pytest.mark.asyncio
async def test_list_systemd_units_filters_by_anomaly_only():
    """anomaly_only=True surfaces only substantive-anomaly rows
    (excludes disabled_but_present-only)."""
    async with make_live_db() as db:
        project = Project(name="ι.B.E anomaly")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "la.bin", "x")
        db.add(firmware)
        await db.flush()

        # Clean.
        db.add(_make_systemd_unit(firmware.id, unit_name="clean"))
        # Suspicious path (substantive).
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="susp",
            anomaly_flags_override={"suspicious_path": True},
        ))
        # Only disabled_but_present — LOW baseline, excluded.
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="dis",
            enabled=False,
            anomaly_flags_override={"disabled_but_present": True},
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["systemd_units"][0]["unit_name"] == "susp"


@pytest.mark.asyncio
async def test_list_systemd_units_filters_by_anomaly_bit():
    """anomaly_bit filters to a specific bit only."""
    async with make_live_db() as db:
        project = Project(name="ι.B.E anomaly bit")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "lab.bin", "b")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="path",
            anomaly_flags_override={"suspicious_path": True},
        ))
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="exec",
            anomaly_flags_override={"obfuscated_exec": True},
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_systemd_units(
            {"anomaly_bit": "obfuscated_exec"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["systemd_units"][0]["unit_name"] == "exec"


# ── lookup_systemd_unit ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_systemd_unit_missing_unit_id_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_systemd_unit({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_systemd_unit_invalid_uuid_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_systemd_unit(
            {"unit_id": "not-a-uuid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_systemd_unit_not_found_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_systemd_unit(
            {"unit_id": str(uuid.uuid4())}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_systemd_unit_returns_full_detail():
    async with make_live_db() as db:
        project = Project(name="ι.B.E lookup")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "lu.bin", "u")
        db.add(firmware)
        await db.flush()

        unit = _make_systemd_unit(firmware.id, unit_name="sshd")
        db.add(unit)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_lookup_systemd_unit(
            {"unit_id": str(unit.id)}, ctx
        )
        out = json.loads(out_str)
        assert out["unit_name"] == "sshd"
        assert out["exec_start"] == "/usr/sbin/sshd -D"
        # unit_raw should appear in detail view.
        assert "unit_raw" in out


# ── search_systemd_units ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_systemd_units_missing_query_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_search_systemd_units({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_search_systemd_units_finds_by_unit_name():
    async with make_live_db() as db:
        project = Project(name="ι.B.E search")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "se.bin", "z")
        db.add(firmware)
        await db.flush()

        # Override exec_start AND description so "ssh" only matches
        # the sshd unit's name (default description "OpenSSH server"
        # also matches "ssh").
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="sshd",
            exec_start="/bin/sd -D",
            description="Daemon",
        ))
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="cron",
            exec_start="/bin/cron",
            description="Scheduler",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_systemd_units(
            {"query": "ssh"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["matches"][0]["unit_name"] == "sshd"


@pytest.mark.asyncio
async def test_search_systemd_units_finds_by_exec_start():
    async with make_live_db() as db:
        project = Project(name="ι.B.E search exec")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "se2.bin", "y")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="legit",
            exec_start="/usr/sbin/sshd -D",
        ))
        db.add(_make_systemd_unit(
            firmware.id,
            unit_name="evil",
            exec_start="/tmp/payload.sh",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_systemd_units(
            {"query": "/tmp/"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["matches"][0]["unit_name"] == "evil"


# ── systemd_walk_status ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_systemd_walk_status_firmware_not_found_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_systemd_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_systemd_walk_status_returns_status_for_idle_firmware():
    async with make_live_db() as db:
        project = Project(name="ι.B.E status")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "st.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_systemd_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["firmware_id"] == str(firmware.id)
        assert out["status"] == "idle"


# ── trigger_systemd_walk ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_systemd_walk_firmware_not_found_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_trigger_systemd_walk({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_trigger_systemd_walk_returns_409_when_queued():
    """Rule #33 .a idempotency: status='queued' triggers conflict=True."""
    async with make_live_db() as db:
        project = Project(name="ι.B.E trigger 409")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "tr.bin", "q")
        firmware.systemd_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_systemd_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_systemd_walk_returns_409_when_running():
    async with make_live_db() as db:
        project = Project(name="ι.B.E trigger running")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trr.bin", "r")
        firmware.systemd_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_systemd_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "running"


# ── lookup_systemd_unit_across_firmwares (CROSS-FIRMWARE) ───────────────────


@pytest.mark.asyncio
async def test_lookup_across_missing_unit_name_returns_error():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_across_no_matches_returns_zero():
    async with make_live_db() as db:
        project = Project(name="ι.B.E xfirm zero")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "xz.bin", "0")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {"unit_name": "ghost", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 0
        assert "message" in out


@pytest.mark.asyncio
async def test_lookup_across_finds_unit_in_single_firmware():
    async with make_live_db() as db:
        project = Project(name="ι.B.E xfirm single")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "xs.bin", "1")
        db.add(firmware)
        await db.flush()

        db.add(_make_systemd_unit(firmware.id, unit_name="sshd"))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {"unit_name": "sshd", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1
        assert out["matches"][0]["unit_name"] == "sshd"
        # Single match — no supply_chain_signal yet.
        assert "supply_chain_signal" not in out


@pytest.mark.asyncio
async def test_lookup_across_emits_supply_chain_signal_when_multi_firmware():
    """CROSS-FIRMWARE AGGREGATION — match_count >= 2 emits the
    supply_chain_signal field. This is the wairz competitive
    differentiator: identifying same vendor-pushed unit across
    multiple firmware captures."""
    async with make_live_db() as db:
        project = Project(name="ι.B.E xfirm supply")
        db.add(project)
        await db.flush()

        # Three firmwares all carrying sshd.service.
        for i in range(3):
            firmware = _make_firmware(
                project.id, f"fw{i}.bin", chr(0x41 + i)
            )
            db.add(firmware)
            await db.flush()
            db.add(_make_systemd_unit(firmware.id, unit_name="sshd"))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {"unit_name": "sshd", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 3
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_lookup_across_filters_by_exec_substring():
    """Cross-firmware aggregation narrows on exec_substring."""
    async with make_live_db() as db:
        project = Project(name="ι.B.E xfirm exec filter")
        db.add(project)
        await db.flush()

        fw_legit = _make_firmware(project.id, "legit.bin", "L")
        db.add(fw_legit)
        await db.flush()
        db.add(_make_systemd_unit(
            fw_legit.id,
            unit_name="sshd",
            exec_start="/usr/sbin/sshd -D",
        ))

        fw_evil = _make_firmware(project.id, "evil.bin", "E")
        db.add(fw_evil)
        await db.flush()
        db.add(_make_systemd_unit(
            fw_evil.id,
            unit_name="sshd",
            exec_start="/tmp/sshd-backdoor",
        ))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=fw_evil.id, project_id=project.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {
                "unit_name": "sshd",
                "exec_substring": "/tmp/",
                "scope": "project",
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1
        assert out["matches"][0]["firmware_original_filename"] == "evil.bin"


@pytest.mark.asyncio
async def test_lookup_across_global_scope_spans_projects():
    """scope='global' searches every project, not just the active one."""
    async with make_live_db() as db:
        p1 = Project(name="ι.B.E xfirm proj A")
        p2 = Project(name="ι.B.E xfirm proj B")
        db.add_all([p1, p2])
        await db.flush()

        fw1 = _make_firmware(p1.id, "p1.bin", "1")
        fw2 = _make_firmware(p2.id, "p2.bin", "2")
        db.add_all([fw1, fw2])
        await db.flush()

        db.add(_make_systemd_unit(fw1.id, unit_name="custom-evil"))
        db.add(_make_systemd_unit(fw2.id, unit_name="custom-evil"))
        await db.commit()

        # Run with project=p1 context, scope=global should still find both.
        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=p1.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {"unit_name": "custom-evil", "scope": "global"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 2


@pytest.mark.asyncio
async def test_lookup_across_project_scope_excludes_other_projects():
    """scope='project' (default) excludes other projects."""
    async with make_live_db() as db:
        p1 = Project(name="ι.B.E xfirm proj scope A")
        p2 = Project(name="ι.B.E xfirm proj scope B")
        db.add_all([p1, p2])
        await db.flush()

        fw1 = _make_firmware(p1.id, "p1.bin", "1")
        fw2 = _make_firmware(p2.id, "p2.bin", "2")
        db.add_all([fw1, fw2])
        await db.flush()

        db.add(_make_systemd_unit(fw1.id, unit_name="custom-evil"))
        db.add(_make_systemd_unit(fw2.id, unit_name="custom-evil"))
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=p1.id
        )
        out_str = await _handle_lookup_systemd_unit_across_firmwares(
            {"unit_name": "custom-evil", "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        # Only p1's firmware matches.
        assert out["match_count"] == 1
