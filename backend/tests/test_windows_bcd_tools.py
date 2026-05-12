"""Phase θ.A.F contract tests: windows_bcd MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search MCP tool returns the actual persisted shape from the θ.A.A
table, not just that .add() was called.

Mirrors test_windows_mft_tools.py shape — 3 MCP tools (search /
status / trigger) with ≥10 contract assertions across happy-path +
404 + 409 + filter shapes.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_bcd import (
    _handle_bcd_walk_status,
    _handle_search_bcd_entries,
    _handle_trigger_bcd_walk,
    register_windows_bcd_tools,
)
from app.models import Firmware, Project, WindowsBcdEntry
from app.services.jsonb_normalizers import (
    _stamp_windows_bcd_entries_anomaly_flags,
    _stamp_windows_bcd_entries_custom_elements,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the BCD
    handlers actually use."""

    db: AsyncSession
    firmware_id: uuid.UUID


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


def _make_bcd_entry(
    firmware_id: uuid.UUID,
    *,
    object_guid: str,
    description: str | None = "Windows 10",
    image_path: str | None = "\\Windows\\System32\\winload.efi",
    testsigning: bool | None = False,
    no_integrity_checks: bool | None = False,
    nx_policy: int | None = 0,
    anomaly_flags_override: dict | None = None,
) -> WindowsBcdEntry:
    default_flags = {
        "suspicious_path": False,
        "non_microsoft_description": False,
        "testsigning_enabled": bool(testsigning),
        "no_integrity_checks": bool(no_integrity_checks),
        "nx_disabled": (nx_policy == 2),
        "is_default_boot": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    return WindowsBcdEntry(
        firmware_id=firmware_id,
        source_path="Boot/BCD",
        object_guid=object_guid,
        object_type=0x10200003,
        description=description,
        image_path=image_path,
        testsigning=testsigning,
        no_integrity_checks=no_integrity_checks,
        nx_policy=nx_policy,
        custom_elements=_stamp_windows_bcd_entries_custom_elements([]),
        anomaly_flags=_stamp_windows_bcd_entries_anomaly_flags(default_flags),
    )


# ── Registration test ────────────────────────────────────────────────────────


def test_register_windows_bcd_tools_registers_three():
    """register_windows_bcd_tools must register exactly the three
    θ.A.F tools (search / status / trigger)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_bcd_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_bcd_entries" in names
    assert "bcd_walk_status" in names
    assert "trigger_bcd_walk" in names
    assert len(reg._tools) >= 3


# ── search_bcd_entries ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_bcd_entries_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search empty")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert out["bcd_entries"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_search_bcd_entries_returns_all_when_no_filters():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search all")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-all.bin", "a")
        db.add(firmware)
        await db.flush()

        # Seed 3 entries
        for i, guid in enumerate([
            "{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            "{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}",
            "{deadbeef-1234-5678-9abc-def012345678}",
        ]):
            db.add(_make_bcd_entry(
                firmware.id,
                object_guid=guid,
                description=f"Entry {i}",
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 3
        assert len(out["bcd_entries"]) == 3


@pytest.mark.asyncio
async def test_search_bcd_entries_filters_by_testsigning_only():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search testsigning")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-ts.bin", "t")
        db.add(firmware)
        await db.flush()

        # Two clean entries + one testsigning
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{clean-1}",
            description="Clean A",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{clean-2}",
            description="Clean B",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{bootkit}",
            description="Bootkit",
            testsigning=True,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"testsigning_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["bcd_entries"][0]["object_guid"] == "{bootkit}"


@pytest.mark.asyncio
async def test_search_bcd_entries_filters_by_anomaly_only():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search anomaly")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-an.bin", "x")
        db.add(firmware)
        await db.flush()

        # One clean, one with anomaly
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{clean}",
            description="Windows 10",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{evil}",
            description="Adversary",
            anomaly_flags_override={
                "suspicious_path": True,
                "non_microsoft_description": True,
            },
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["bcd_entries"][0]["object_guid"] == "{evil}"


@pytest.mark.asyncio
async def test_search_bcd_entries_filters_by_suspicious_path_only():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search susp-path")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-sp.bin", "p")
        db.add(firmware)
        await db.flush()

        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{clean}",
            description="Windows",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{evil}",
            description="Adversary",
            anomaly_flags_override={"suspicious_path": True},
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"suspicious_path_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["bcd_entries"][0]["object_guid"] == "{evil}"


@pytest.mark.asyncio
async def test_search_bcd_entries_filters_by_guid_prefix():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search guid")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-guid.bin", "g")
        db.add(firmware)
        await db.flush()

        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{9dea862c-5cdd-4e70-acc1-f32b344d4795}",
            description="Boot Manager",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{a5a30fa2-3d06-4e9f-b5f4-a01df9d1fcba}",
            description="Global Settings",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"guid_prefix": "{9dea"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1


@pytest.mark.asyncio
async def test_search_bcd_entries_filters_by_description_substring():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search desc")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-desc.bin", "d")
        db.add(firmware)
        await db.flush()

        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{a}",
            description="Windows 10",
        ))
        db.add(_make_bcd_entry(
            firmware.id,
            object_guid="{b}",
            description="Ubuntu 22.04",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"description_substring": "Ubuntu"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["bcd_entries"][0]["object_guid"] == "{b}"


@pytest.mark.asyncio
async def test_search_bcd_entries_paginates():
    async with make_live_db() as db:
        project = Project(name="θ.A.F search paginate")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-pg.bin", "q")
        db.add(firmware)
        await db.flush()

        # Seed 10 entries — paginate by 3
        for i in range(10):
            db.add(_make_bcd_entry(
                firmware.id,
                object_guid=f"{{guid-{i:02d}}}",
                description=f"Entry {i}",
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"limit": 3, "offset": 0}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 10
        assert len(out["bcd_entries"]) == 3
        assert out["limit"] == 3
        assert out["offset"] == 0


# ── bcd_walk_status ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_bcd_walk_status_idle_initial_state():
    async with make_live_db() as db:
        project = Project(name="θ.A.F status idle")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "status-idle.bin", "i")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_bcd_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["status"] == "idle"
        assert out["started_at"] is None
        assert out["finished_at"] is None
        assert out["error"] is None
        assert out["result"] is None


@pytest.mark.asyncio
async def test_bcd_walk_status_404_for_nonexistent_firmware():
    async with make_live_db() as db:
        project = Project(name="θ.A.F status 404")
        db.add(project)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_bcd_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── trigger_bcd_walk ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_bcd_walk_queues_when_idle():
    async with make_live_db() as db:
        project = Project(name="θ.A.F trigger queue")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-q.bin", "u")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        from unittest.mock import patch

        # Patch asyncio.create_task to prevent the background task
        # actually spawning (which would try to open an
        # async_session_factory connection to a non-existent test DB).
        with patch("asyncio.create_task") as mock_task:
            out_str = await _handle_trigger_bcd_walk({}, ctx)
            out = json.loads(out_str)
            assert out["scheduled"] is True
            assert out["status"] == "queued"
            mock_task.assert_called_once()


@pytest.mark.asyncio
async def test_trigger_bcd_walk_409_when_running():
    async with make_live_db() as db:
        project = Project(name="θ.A.F trigger conflict")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-c.bin", "v")
        firmware.bcd_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_bcd_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_bcd_walk_409_when_queued():
    async with make_live_db() as db:
        project = Project(name="θ.A.F trigger queued")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trigger-qc.bin", "w")
        firmware.bcd_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_bcd_walk({}, ctx)
        out = json.loads(out_str)
        assert out["conflict"] is True
        assert out["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_bcd_walk_404_for_nonexistent_firmware():
    async with make_live_db() as db:
        project = Project(name="θ.A.F trigger 404")
        db.add(project)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_trigger_bcd_walk({}, ctx)
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── Output truncation contract ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_bcd_entries_truncates_oversize_output():
    """Many entries with long descriptions → output should be truncated
    to under 30KB."""
    async with make_live_db() as db:
        project = Project(name="θ.A.F truncate")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "trunc.bin", "z")
        db.add(firmware)
        await db.flush()

        # Seed 500 entries with maxed-out descriptions
        for i in range(200):
            db.add(_make_bcd_entry(
                firmware.id,
                object_guid=f"{{trunc-test-{i:04d}}}",
                description="X" * 400,  # near max description length
                image_path="\\" + "\\".join(["dir"] * 50) + "\\f.efi",
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_bcd_entries(
            {"limit": 500}, ctx
        )
        # Output should be <= 30KB
        assert len(out_str.encode("utf-8")) <= 30 * 1024
