"""Phase θ.C.F contract tests: windows_esp MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that the
search/status/trigger/lookup MCP tools return the actual persisted
shape from the θ.C.A windows_esp_entries table.

4 MCP tools (search / status / trigger / lookup) with contract
assertions across happy-path + 404 + 409 + filter shapes + cross-
firmware aggregation. Mirrors test_windows_wmi_tools.py /
test_windows_bcd_tools.py shape.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_esp import (
    _handle_esp_walk_status,
    _handle_lookup_esp_chain,
    _handle_search_esp_entries,
    _handle_trigger_esp_walk,
    register_windows_esp_tools,
)
from app.models import Firmware, Project, WindowsEspEntry
from app.services.jsonb_normalizers import (
    _stamp_windows_esp_entries_anomaly_flags,
    _stamp_windows_esp_entries_authenticode_chain,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    ESP handlers actually use."""

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


def _make_esp_entry(
    firmware_id: uuid.UUID,
    *,
    file_path: str,
    file_sha256: str,
    file_size: int = 1_000_000,
    authenticode_state: str = "unsigned",
    fingerprint_sha256: str | None = None,
    is_unsigned: bool = True,
    is_known_bootloader_path: bool = True,
    is_vendor_path: bool = False,
    is_revoked: bool = False,
    signer_subject: str | None = None,
) -> WindowsEspEntry:
    return WindowsEspEntry(
        firmware_id=firmware_id,
        file_path=file_path,
        file_sha256=file_sha256,
        file_size=file_size,
        authenticode_state=authenticode_state,
        authenticode_chain=_stamp_windows_esp_entries_authenticode_chain({
            "signed": not is_unsigned,
            "chain_status": (
                "unknown" if is_unsigned else (
                    "revoked" if is_revoked else "valid_now"
                )
            ),
            "signer_subject": signer_subject,
            "signatures_count": 0 if is_unsigned else 1,
        }),
        dbx_revocation_match=None,
        anomaly_flags=_stamp_windows_esp_entries_anomaly_flags({
            "is_unsigned": is_unsigned,
            "is_revoked": is_revoked,
            "is_known_bootloader_path": is_known_bootloader_path,
            "is_vendor_path": is_vendor_path,
            "is_non_microsoft_signer": False,
        }),
        fingerprint_sha256=fingerprint_sha256,
    )


# ── search_esp_entries ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_esp_entries_returns_persisted_rows():
    async with make_live_db() as db:
        project = Project(name="θ.C.F search canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw.bin", "s")
        db.add(firmware)
        await db.flush()

        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="a" * 64,
            authenticode_state="unsigned",
        ))
        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="b" * 64,
            authenticode_state="signed_valid",
            is_unsigned=False,
            signer_subject="CN=Microsoft Corporation UEFI CA 2011",
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_esp_entries({}, ctx)
        data = json.loads(out)
        assert data["total_count"] == 2
        assert len(data["esp_entries"]) == 2
        paths = {e["file_path"] for e in data["esp_entries"]}
        assert paths == {
            "EFI/Boot/bootx64.efi",
            "EFI/Microsoft/Boot/bootmgfw.efi",
        }


@pytest.mark.asyncio
async def test_search_esp_entries_unsigned_only_filter():
    async with make_live_db() as db:
        project = Project(name="θ.C.F unsigned-only canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "u")
        db.add(firmware)
        await db.flush()

        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="a" * 64,
            authenticode_state="unsigned",
        ))
        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Microsoft/Boot/bootmgfw.efi",
            file_sha256="b" * 64,
            authenticode_state="signed_valid",
            is_unsigned=False,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_esp_entries(
            {"unsigned_only": True}, ctx
        )
        data = json.loads(out)
        assert data["total_count"] == 1
        assert data["esp_entries"][0]["file_path"] == (
            "EFI/Boot/bootx64.efi"
        )


@pytest.mark.asyncio
async def test_search_esp_entries_known_bootloader_only_filter():
    async with make_live_db() as db:
        project = Project(name="θ.C.F known-bootloader canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "k")
        db.add(firmware)
        await db.flush()

        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="a" * 64,
            is_known_bootloader_path=True,
        ))
        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Acme/util.efi",
            file_sha256="b" * 64,
            is_known_bootloader_path=False,
            is_vendor_path=True,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_esp_entries(
            {"known_bootloader_only": True}, ctx
        )
        data = json.loads(out)
        assert data["total_count"] == 1
        assert data["esp_entries"][0]["file_path"] == (
            "EFI/Boot/bootx64.efi"
        )


@pytest.mark.asyncio
async def test_search_esp_entries_empty_no_walk():
    async with make_live_db() as db:
        project = Project(name="θ.C.F empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "e")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_search_esp_entries({}, ctx)
        data = json.loads(out)
        assert data["total_count"] == 0
        assert "trigger_esp_walk" in data["message"]


# ── esp_walk_status ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_esp_walk_status_idle():
    async with make_live_db() as db:
        project = Project(name="θ.C.F status-idle canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "i")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_esp_walk_status({}, ctx)
        data = json.loads(out)
        assert data["status"] == "idle"
        assert data["started_at"] is None
        assert data["finished_at"] is None
        assert data["error"] is None
        assert data["result"] is None


@pytest.mark.asyncio
async def test_esp_walk_status_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_esp_walk_status({}, ctx)
        data = json.loads(out)
        assert "not found" in data["error"]


# ── trigger_esp_walk ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_esp_walk_schedules_when_idle(monkeypatch):
    """Idempotent POST — when status=idle, schedules a background
    task and returns scheduled=True."""
    # Patch run_esp_walk_background so the test doesn't try to
    # open a real async_session_factory (no DB available in
    # make_live_db's sandbox for the background runner).
    async def _no_op(firmware_id):
        return None

    import app.services.esp_walker
    monkeypatch.setattr(
        app.services.esp_walker, "run_esp_walk_background", _no_op
    )

    async with make_live_db() as db:
        project = Project(name="θ.C.F trigger canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "t")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_esp_walk({}, ctx)
        data = json.loads(out)
        assert data["scheduled"] is True
        assert data["status"] == "queued"


@pytest.mark.asyncio
async def test_trigger_esp_walk_conflict_when_running(monkeypatch):
    """Idempotent POST — when status=running, returns conflict=True."""
    async def _no_op(firmware_id):
        return None

    import app.services.esp_walker
    monkeypatch.setattr(
        app.services.esp_walker, "run_esp_walk_background", _no_op
    )

    async with make_live_db() as db:
        project = Project(name="θ.C.F conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "c")
        firmware.esp_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_trigger_esp_walk({}, ctx)
        data = json.loads(out)
        assert data["conflict"] is True
        assert data["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_esp_walk_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_esp_walk({}, ctx)
        data = json.loads(out)
        assert "not found" in data["error"]


# ── lookup_esp_chain ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_esp_chain_by_fingerprint_cross_firmware():
    """Cross-firmware aggregation — same fingerprint across two
    firmware images."""
    async with make_live_db() as db:
        project = Project(name="θ.C.F lookup canary")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        fp = "deadbeef" * 8
        for fw in (fw1, fw2):
            db.add(_make_esp_entry(
                fw.id,
                file_path="EFI/Boot/bootx64.efi",
                file_sha256="9" * 64,
                fingerprint_sha256=fp,
            ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=fw1.id)
        out = await _handle_lookup_esp_chain(
            {"fingerprint_sha256": fp}, ctx
        )
        data = json.loads(out)
        assert data["total_matches"] == 2
        assert data["distinct_firmware_count"] == 2


@pytest.mark.asyncio
async def test_lookup_esp_chain_by_file_sha256():
    async with make_live_db() as db:
        project = Project(name="θ.C.F lookup-by-sha canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "fw.bin", "h")
        db.add(firmware)
        await db.flush()

        db.add(_make_esp_entry(
            firmware.id,
            file_path="EFI/Boot/bootx64.efi",
            file_sha256="abc" + "0" * 61,
        ))
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lookup_esp_chain(
            {"file_sha256": "abc" + "0" * 61}, ctx
        )
        data = json.loads(out)
        assert data["total_matches"] == 1


@pytest.mark.asyncio
async def test_lookup_esp_chain_requires_query():
    """At least one of fingerprint / sha256 / path_substring is
    required."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_lookup_esp_chain({}, ctx)
        data = json.loads(out)
        assert "error" in data
        assert "fingerprint" in data["error"]


@pytest.mark.asyncio
async def test_lookup_esp_chain_empty():
    """Unknown fingerprint returns no matches with a message."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out = await _handle_lookup_esp_chain(
            {"fingerprint_sha256": "00" * 32}, ctx
        )
        data = json.loads(out)
        assert data["total_matches"] == 0
        assert data["distinct_firmware_count"] == 0
        assert "message" in data


# ── Registration smoke ──────────────────────────────────────────────────────


def test_register_windows_esp_tools_registers_4():
    """register_windows_esp_tools registers exactly 4 tools."""
    registry = ToolRegistry()
    register_windows_esp_tools(registry)
    names = {t["name"] for t in registry.get_anthropic_tools()}
    assert names == {
        "search_esp_entries",
        "esp_walk_status",
        "trigger_esp_walk",
        "lookup_esp_chain",
    }
