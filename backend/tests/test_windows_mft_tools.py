"""Phase η.A.F contract tests: windows_mft MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search MCP tool returns the actual persisted shape from the η.A.A
table, not just that .add() was called.

Mirrors test_windows_lnk_tools.py shape — 3 MCP tools (search /
status / trigger) with ≥10 contract assertions across happy-path +
404 + 409 + filter shapes.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_mft import (
    _handle_mft_walk_status,
    _handle_search_mft_records,
    _handle_trigger_mft_walk,
    register_windows_mft_tools,
)
from app.models import Firmware, Project, WindowsMftRecord
from app.services.jsonb_normalizers import (
    _stamp_windows_mft_records_ads_streams,
    _stamp_windows_mft_records_target_metadata,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the MFT
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


def _make_mft_record(
    firmware_id: uuid.UUID,
    *,
    segment_number: int,
    filename: str,
    in_use: bool = True,
    is_directory: bool = False,
    full_path: str | None = None,
    si_mod_ns: int | None = 132_500_000_000_000_000,
    fn_mod_ns: int | None = 132_000_000_000_000_000,
    ads_streams: list[dict] | None = None,
) -> WindowsMftRecord:
    return WindowsMftRecord(
        firmware_id=firmware_id,
        source_path="images/disk.raw",
        segment_number=segment_number,
        in_use=in_use,
        is_directory=is_directory,
        full_path=full_path or f"Windows\\System32\\{filename}",
        filename=filename,
        file_size=4096,
        si_creation_ns=132_000_000_000_000_000,
        si_last_modification_ns=si_mod_ns,
        si_last_change_ns=132_500_000_000_000_000,
        si_last_access_ns=133_000_000_000_000_000,
        fn_creation_ns=132_000_000_000_000_000,
        fn_last_modification_ns=fn_mod_ns,
        fn_last_change_ns=132_000_000_000_000_000,
        fn_last_access_ns=132_000_000_000_000_000,
        ads_streams=(
            _stamp_windows_mft_records_ads_streams(ads_streams)
            if ads_streams
            else []
        ),
        target_metadata=_stamp_windows_mft_records_target_metadata({}),
    )


# ── Registration test ───────────────────────────────────────────────────────


def test_register_windows_mft_tools_registers_three():
    """register_windows_mft_tools must register exactly the three η.A.F
    tools (search / status / trigger)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_mft_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "search_mft_records" in names
    assert "mft_walk_status" in names
    assert "trigger_mft_walk" in names
    assert len(reg._tools) >= 3


def test_register_windows_mft_tools_includes_cross_firmware_lookup():
    """Rule #44 acceptance — register_windows_mft_tools registers
    lookup_mft_record_across_firmwares alongside the per-firmware tools.
    Issue #15 backfill for η.A walker."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_windows_mft_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "lookup_mft_record_across_firmwares" in names


# ── search_mft_records ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_mft_records_empty_returns_zero_total():
    async with make_live_db() as db:
        project = Project(name="η.A.F search empty")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-empty.bin", "s")
        db.add(firmware)
        await db.commit()

        result = await _handle_search_mft_records(
            {}, _StubContext(db=db, firmware_id=firmware.id)
        )
        out = json.loads(result)
        assert out["total_count"] == 0
        assert out["mft_records"] == []
        assert "message" in out


@pytest.mark.asyncio
async def test_search_mft_records_returns_persisted_rows_with_canonical_shape():
    """Rule #35b: persist rows + invoke search → response carries
    every flat column + JSONB shape from the persisted row."""
    async with make_live_db() as db:
        project = Project(name="η.A.F search shape")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "search-shape.bin", "s")
        db.add(firmware)
        await db.flush()

        db.add(_make_mft_record(
            firmware.id,
            segment_number=42,
            filename="cmd.exe",
            ads_streams=[
                {"name": "Zone.Identifier", "size": 130, "data_size": 130},
            ],
        ))
        await db.commit()

        result = await _handle_search_mft_records(
            {}, _StubContext(db=db, firmware_id=firmware.id)
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert len(out["mft_records"]) == 1
        rec = out["mft_records"][0]
        assert rec["filename"] == "cmd.exe"
        assert rec["segment_number"] == 42
        assert rec["in_use"] is True
        # JSONB normalizer round-trip
        assert isinstance(rec["ads_streams"], list)
        assert rec["ads_streams"][0]["name"] == "Zone.Identifier"
        # Derived flags
        assert rec["has_hidden_ads"] is False  # Zone.Identifier < 1 KB
        assert rec["has_timestomp"] is False  # SI mtime >= FN mtime


@pytest.mark.asyncio
async def test_search_mft_records_filename_prefix_filter():
    async with make_live_db() as db:
        project = Project(name="η.A.F filename filter")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "filt.bin", "f")
        db.add(firmware)
        await db.flush()

        for idx, name in enumerate(["cmd.exe", "powershell.exe", "notepad.exe"]):
            db.add(_make_mft_record(
                firmware.id, segment_number=100 + idx, filename=name
            ))
        await db.commit()

        result = await _handle_search_mft_records(
            {"filename_prefix": "cmd"},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["mft_records"][0]["filename"] == "cmd.exe"


@pytest.mark.asyncio
async def test_search_mft_records_has_ads_only_filter():
    """has_ads_only must filter to records with ADS size > 1 KB
    (Zone.Identifier ~130 B is below the threshold and excluded)."""
    async with make_live_db() as db:
        project = Project(name="η.A.F has_ads")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "ads.bin", "a")
        db.add(firmware)
        await db.flush()

        # Healthy file — no ADS.
        db.add(_make_mft_record(
            firmware.id, segment_number=200, filename="healthy.exe",
        ))
        # File with benign Zone.Identifier (excluded by threshold).
        db.add(_make_mft_record(
            firmware.id, segment_number=201, filename="downloaded.exe",
            ads_streams=[{"name": "Zone.Identifier", "size": 130, "data_size": 130}],
        ))
        # File with hidden ADS payload.
        db.add(_make_mft_record(
            firmware.id, segment_number=202, filename="evil.exe",
            ads_streams=[{"name": "hidden", "size": 32 * 1024, "data_size": 32 * 1024}],
        ))
        await db.commit()

        result = await _handle_search_mft_records(
            {"has_ads_only": True},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["mft_records"][0]["filename"] == "evil.exe"
        assert out["mft_records"][0]["has_hidden_ads"] is True


@pytest.mark.asyncio
async def test_search_mft_records_has_timestomp_only_filter():
    """has_timestomp_only must filter to records with $SI mtime <
    $FN mtime."""
    async with make_live_db() as db:
        project = Project(name="η.A.F has_timestomp")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "ts.bin", "t")
        db.add(firmware)
        await db.flush()

        # Healthy: SI mtime > FN mtime.
        db.add(_make_mft_record(
            firmware.id, segment_number=300, filename="healthy.exe",
            si_mod_ns=132_500_000_000_000_000,
            fn_mod_ns=132_000_000_000_000_000,
        ))
        # Timestomp: SI mtime < FN mtime.
        db.add(_make_mft_record(
            firmware.id, segment_number=301, filename="dropper.exe",
            si_mod_ns=131_500_000_000_000_000,
            fn_mod_ns=132_900_000_000_000_000,
        ))
        await db.commit()

        result = await _handle_search_mft_records(
            {"has_timestomp_only": True},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["mft_records"][0]["filename"] == "dropper.exe"
        assert out["mft_records"][0]["has_timestomp"] is True


@pytest.mark.asyncio
async def test_search_mft_records_deleted_only_filter():
    """deleted_only must filter to in_use=False rows."""
    async with make_live_db() as db:
        project = Project(name="η.A.F deleted")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "del.bin", "d")
        db.add(firmware)
        await db.flush()

        db.add(_make_mft_record(
            firmware.id, segment_number=400, filename="alive.exe",
            in_use=True,
        ))
        db.add(_make_mft_record(
            firmware.id, segment_number=401, filename="ghost.exe",
            in_use=False,
        ))
        await db.commit()

        result = await _handle_search_mft_records(
            {"deleted_only": True},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["mft_records"][0]["filename"] == "ghost.exe"
        assert out["mft_records"][0]["in_use"] is False


@pytest.mark.asyncio
async def test_search_mft_records_pagination():
    """offset / limit pagination + total_count."""
    async with make_live_db() as db:
        project = Project(name="η.A.F pagination")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "page.bin", "p")
        db.add(firmware)
        await db.flush()

        for i in range(5):
            db.add(_make_mft_record(
                firmware.id,
                segment_number=500 + i,
                filename=f"file{i}.exe",
            ))
        await db.commit()

        # Limit 2, offset 0 → first 2 (newest first by fn_creation_ns).
        result = await _handle_search_mft_records(
            {"limit": 2, "offset": 0},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert out["total_count"] == 5
        assert len(out["mft_records"]) == 2

        # Offset 4 → tail.
        result = await _handle_search_mft_records(
            {"limit": 50, "offset": 4},
            _StubContext(db=db, firmware_id=firmware.id),
        )
        out = json.loads(result)
        assert len(out["mft_records"]) == 1


# ── mft_walk_status ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_mft_walk_status_idle_baseline():
    async with make_live_db() as db:
        project = Project(name="η.A.F status idle")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "status-idle.bin", "i")
        db.add(firmware)
        await db.commit()

        result = await _handle_mft_walk_status(
            {}, _StubContext(db=db, firmware_id=firmware.id)
        )
        out = json.loads(result)
        assert out["status"] == "idle"
        assert out["started_at"] is None
        assert out["finished_at"] is None


@pytest.mark.asyncio
async def test_mft_walk_status_404_on_missing_firmware():
    async with make_live_db() as db:
        result = await _handle_mft_walk_status(
            {}, _StubContext(db=db, firmware_id=uuid.uuid4())
        )
        out = json.loads(result)
        assert "error" in out
        assert "not found" in out["error"]


# ── trigger_mft_walk ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_mft_walk_404_on_missing_firmware():
    async with make_live_db() as db:
        result = await _handle_trigger_mft_walk(
            {}, _StubContext(db=db, firmware_id=uuid.uuid4())
        )
        out = json.loads(result)
        assert "error" in out


@pytest.mark.asyncio
async def test_trigger_mft_walk_409_on_in_flight_status():
    """Idempotent POST contract — running status → conflict response."""
    async with make_live_db() as db:
        project = Project(name="η.A.F 409 inflight")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "conf.bin", "c")
        # Pretend a previous walk is running.
        firmware.mft_walk_status = "running"
        db.add(firmware)
        await db.commit()

        result = await _handle_trigger_mft_walk(
            {}, _StubContext(db=db, firmware_id=firmware.id)
        )
        out = json.loads(result)
        assert out.get("conflict") is True
        assert out["status"] == "running"
        assert "already running" in out["message"]
