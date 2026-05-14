"""Phase θ.E.F contract tests: windows_mbr_vbr MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
list/lookup MCP tools return the actual persisted shape from the
θ.E.A windows_mbr_vbr_sectors table.

2 MCP tools (list / lookup) with contract assertions across
happy-path + filter shapes + cross-firmware aggregation. Mirrors
test_windows_esp_tools.py / test_windows_wmi_tools.py shape.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_mbr_vbr import (
    _handle_list_mbr_vbr_sectors,
    _handle_lookup_mbr_vbr_sector,
    register_windows_mbr_vbr_tools,
)
from app.models import Firmware, Project, WindowsMbrVbrSector
from app.services.jsonb_normalizers import (
    _stamp_windows_mbr_vbr_sectors_anomaly_flags,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    MBR/VBR handlers actually use."""

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


def _make_sector(
    firmware_id: uuid.UUID,
    *,
    file_path: str,
    sector_offset: int = 0,
    sector_kind: str = "mbr",
    sector_sha256: str | None = None,
    bootcode_signature_match: str | None = None,
    known_bootkit_match: str | None = None,
    fingerprint_sha256: str | None = None,
    non_zero_padding: bool = False,
    non_standard_jmp: bool = False,
) -> WindowsMbrVbrSector:
    sector_sha256 = sector_sha256 or ("a" * 64)
    return WindowsMbrVbrSector(
        firmware_id=firmware_id,
        file_path=file_path,
        sector_offset=sector_offset,
        sector_kind=sector_kind,
        sector_sha256=sector_sha256,
        sector_size=512,
        bootcode_signature_match=bootcode_signature_match,
        known_bootkit_match=known_bootkit_match,
        anomaly_flags=_stamp_windows_mbr_vbr_sectors_anomaly_flags({
            "non_zero_padding": non_zero_padding,
            "non_standard_jmp": non_standard_jmp,
            "is_mbr": sector_kind == "mbr",
            "is_vbr": sector_kind.startswith("vbr_"),
        }),
        fingerprint_sha256=fingerprint_sha256,
    )


# ── list_mbr_vbr_sectors ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_returns_persisted_sectors():
    """Happy path — list returns persisted rows for the active firmware."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F list canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "l")
        db.add(firmware)
        await db.flush()

        sector = _make_sector(
            firmware.id,
            file_path="windows.img",
            sector_kind="mbr",
            bootcode_signature_match="windows_10_mbr",
            fingerprint_sha256="1" * 64,
        )
        db.add(sector)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors({}, ctx)
        out = json.loads(result)

        assert out["firmware_id"] == str(firmware.id)
        assert out["total_count"] == 1
        assert out["returned"] == 1
        assert len(out["entries"]) == 1
        e = out["entries"][0]
        assert e["file_path"] == "windows.img"
        assert e["sector_kind"] == "mbr"
        assert e["bootcode_signature_match"] == "windows_10_mbr"
        assert e["known_bootkit_match"] is None
        assert e["fingerprint_sha256"] == "1" * 64


@pytest.mark.asyncio
async def test_list_empty_firmware_returns_zero():
    """Firmware with no sectors → total_count=0 + message."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "e")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors({}, ctx)
        out = json.loads(result)
        assert out["total_count"] == 0
        assert out["returned"] == 0
        assert "message" in out


@pytest.mark.asyncio
async def test_list_filter_by_sector_kind():
    """sector_kind filter returns only matching rows."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F kind-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "k")
        db.add(firmware)
        await db.flush()

        db.add(_make_sector(
            firmware.id, file_path="a.img",
            sector_kind="mbr", sector_sha256="2" * 64,
        ))
        db.add(_make_sector(
            firmware.id, file_path="a.img", sector_offset=1_048_576,
            sector_kind="vbr_ntfs", sector_sha256="3" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors(
            {"sector_kind": "vbr_ntfs"}, ctx
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["entries"][0]["sector_kind"] == "vbr_ntfs"


@pytest.mark.asyncio
async def test_list_filter_by_bootkit_only():
    """bootkit_only=True returns only entries with known_bootkit_match."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F bootkit-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "b")
        db.add(firmware)
        await db.flush()

        db.add(_make_sector(
            firmware.id, file_path="clean.img",
            sector_kind="mbr", sector_sha256="4" * 64,
            bootcode_signature_match="windows_10_mbr",
        ))
        db.add(_make_sector(
            firmware.id, file_path="infected.img",
            sector_kind="mbr", sector_sha256="5" * 64,
            known_bootkit_match="petya_mbr",
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors(
            {"bootkit_only": True}, ctx
        )
        out = json.loads(result)
        assert out["total_count"] == 1
        assert out["entries"][0]["known_bootkit_match"] == "petya_mbr"


@pytest.mark.asyncio
async def test_list_filter_by_anomaly_only():
    """anomaly_only=True post-filters returned rows to those with at
    least one anomaly flag raised OR known_bootkit_match."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F anomaly-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "a")
        db.add(firmware)
        await db.flush()

        # Clean MBR — no anomalies.
        db.add(_make_sector(
            firmware.id, file_path="clean.img",
            sector_kind="mbr", sector_sha256="6" * 64,
            bootcode_signature_match="windows_10_mbr",
        ))
        # MBR with non_standard_jmp anomaly.
        db.add(_make_sector(
            firmware.id, file_path="suspect.img",
            sector_kind="mbr", sector_sha256="7" * 64,
            non_standard_jmp=True,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(result)
        # Post-filter applies in-memory after the SQL fetch — total_count
        # reflects unfiltered count; returned reflects post-filter.
        assert out["returned"] == 1
        assert out["entries"][0]["file_path"] == "suspect.img"


@pytest.mark.asyncio
async def test_list_pagination():
    """limit + offset pagination works."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F pagination canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "p")
        db.add(firmware)
        await db.flush()

        for i in range(5):
            db.add(_make_sector(
                firmware.id,
                file_path=f"disk_{i}.img",
                sector_kind="mbr",
                sector_sha256=f"{i}" * 64,
            ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_list_mbr_vbr_sectors(
            {"limit": 2, "offset": 1}, ctx
        )
        out = json.loads(result)
        assert out["total_count"] == 5
        assert out["returned"] == 2
        assert out["offset"] == 1
        assert out["limit"] == 2


# ── lookup_mbr_vbr_sector ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_no_filters_returns_error():
    """No filter args → error."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F lookup no-args canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "n")
        db.add(firmware)
        await db.flush()
        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_lookup_mbr_vbr_sector({}, ctx)
        out = json.loads(result)
        assert "error" in out
        assert "fingerprint_sha256" in out["error"]


@pytest.mark.asyncio
async def test_lookup_by_fingerprint_aggregates_cross_firmware():
    """Same fingerprint across two firmware → 2 matches, 2 distinct
    firmware."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F lookup fingerprint canary")
        db.add(project)
        await db.flush()
        fw_a = _make_firmware(project.id, "infected_a.img", "x")
        fw_b = _make_firmware(project.id, "infected_b.img", "y")
        db.add_all([fw_a, fw_b])
        await db.flush()

        shared_fp = "deadbeef" * 8
        for fw in (fw_a, fw_b):
            db.add(_make_sector(
                fw.id,
                file_path=fw.original_filename,
                sector_kind="mbr",
                sector_sha256="cafe" * 16,
                known_bootkit_match="petya_mbr",
                fingerprint_sha256=shared_fp,
            ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=fw_a.id)
        result = await _handle_lookup_mbr_vbr_sector(
            {"fingerprint_sha256": shared_fp}, ctx
        )
        out = json.loads(result)
        assert out["total_matches"] == 2
        assert out["distinct_firmware_count"] == 2
        firmware_ids = {m["firmware_id"] for m in out["matches"]}
        assert firmware_ids == {str(fw_a.id), str(fw_b.id)}
        assert all(
            m["known_bootkit_match"] == "petya_mbr"
            for m in out["matches"]
        )


@pytest.mark.asyncio
async def test_lookup_by_sector_sha256_returns_match():
    """Lookup by raw sector hash returns the matching row."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F lookup sha canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "h")
        db.add(firmware)
        await db.flush()

        target_sha = "cafedeadbeef" + "0" * 52
        db.add(_make_sector(
            firmware.id,
            file_path="disk.img",
            sector_kind="mbr",
            sector_sha256=target_sha,
            known_bootkit_match="tdl4_mbr",
            fingerprint_sha256="z" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_lookup_mbr_vbr_sector(
            {"sector_sha256": target_sha}, ctx
        )
        out = json.loads(result)
        assert out["total_matches"] == 1
        assert out["matches"][0]["sector_sha256"] == target_sha
        assert out["matches"][0]["known_bootkit_match"] == "tdl4_mbr"


@pytest.mark.asyncio
async def test_lookup_by_bootkit_name():
    """Lookup by known_bootkit_match string finds all matches."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F lookup bootkit-name canary")
        db.add(project)
        await db.flush()
        fw = _make_firmware(project.id, "fw.bin", "j")
        db.add(fw)
        await db.flush()

        db.add(_make_sector(
            fw.id, file_path="petya1.img", sector_kind="mbr",
            sector_sha256="1" * 64, known_bootkit_match="petya_mbr",
            fingerprint_sha256="a" * 64,
        ))
        db.add(_make_sector(
            fw.id, file_path="petya2.img", sector_kind="mbr",
            sector_sha256="2" * 64, known_bootkit_match="petya_mbr",
            fingerprint_sha256="b" * 64,
        ))
        db.add(_make_sector(
            fw.id, file_path="tdl4.img", sector_kind="mbr",
            sector_sha256="3" * 64, known_bootkit_match="tdl4_mbr",
            fingerprint_sha256="c" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=fw.id)
        result = await _handle_lookup_mbr_vbr_sector(
            {"known_bootkit_match": "petya_mbr"}, ctx
        )
        out = json.loads(result)
        assert out["total_matches"] == 2
        assert all(
            m["known_bootkit_match"] == "petya_mbr"
            for m in out["matches"]
        )


@pytest.mark.asyncio
async def test_lookup_no_results_returns_message():
    """Filter that matches nothing → 0 results + message."""
    async with make_live_db() as db:
        project = Project(name="θ.E.F lookup empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "0")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        result = await _handle_lookup_mbr_vbr_sector(
            {"fingerprint_sha256": "ff" * 32}, ctx
        )
        out = json.loads(result)
        assert out["total_matches"] == 0
        assert "message" in out


# ── Registration shape ──────────────────────────────────────────────────────


def test_register_windows_mbr_vbr_tools_registers_three():
    """register_windows_mbr_vbr_tools registers exactly 3 tools."""
    registry = ToolRegistry()
    register_windows_mbr_vbr_tools(registry)
    names = set(registry._tools.keys())
    assert names == {
        "list_mbr_vbr_sectors",
        "lookup_mbr_vbr_sector",
        "lookup_mbr_vbr_sector_across_firmwares",
    }


def test_register_windows_mbr_vbr_tools_includes_cross_firmware_lookup():
    """Rule #44 acceptance — register_windows_mbr_vbr_tools registers
    lookup_mbr_vbr_sector_across_firmwares alongside the per-firmware
    tools. Issue #15 backfill for θ.E walker (canonical-shape companion
    to the pre-existing lookup_mbr_vbr_sector)."""
    registry = ToolRegistry()
    register_windows_mbr_vbr_tools(registry)
    names = set(registry._tools.keys())
    assert "lookup_mbr_vbr_sector_across_firmwares" in names
