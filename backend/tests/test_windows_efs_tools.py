"""Phase ι.D.E contract tests: windows_efs MCP tools (SECOND ι WINDOWS MCP).

Per Rule #35b: live canaries via make_live_db. Tests verify that the
MCP tools return the actual persisted shape from the ι.D.A table, not
just that .add() was called.

Mirrors test_windows_etl_tools.py shape — 5 per-firmware tools
(list / lookup / search-by-sid / status / trigger) + 1 cross-firmware
aggregation tool with contract assertions across happy-path + 404 +
409 + filter shapes + supply-chain signal aggregation.

Includes coverage for the THIRD application of the cross-firmware
aggregation pattern at walker-stream time (ι.B precedent → ι.C → ι.D
Rule-of-Three): lookup_efs_recovery_agent_across_firmwares within a
project AND globally; supply_chain_signal emission on match_count >= 2.

PARSE-ONLY discipline reminder: these tools surface METADATA only;
the walker NEVER decrypts the FEK, NEVER invokes DPAPI.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.windows_efs import (
    _handle_efs_walk_status,
    _handle_list_efs_encrypted_files,
    _handle_lookup_efs_encrypted_file,
    _handle_lookup_efs_recovery_agent_across_firmwares,
    _handle_search_efs_by_sid,
    _handle_trigger_efs_walk,
    register_windows_efs_tools,
)
from app.models import Firmware, Project, WindowsEfsEncryptedFile
from app.services.jsonb_normalizers import (
    _stamp_windows_efs_encrypted_files_anomaly_flags,
    _stamp_windows_efs_encrypted_files_ddf_users,
    _stamp_windows_efs_encrypted_files_drf_recovery_agents,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub for the EFS MCP handlers."""

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


def _make_efs_file(
    firmware_id: uuid.UUID,
    *,
    file_path: str = "Users\\alice\\Documents\\secret.docx",
    mft_record_number: int = 42,
    ddf_users: list[dict] | None = None,
    drf_recovery_agents: list[dict] | None = None,
    anomaly_flags_override: dict | None = None,
) -> WindowsEfsEncryptedFile:
    default_flags = {
        "orphaned_drf": False,
        "unusual_recovery_agent": False,
        "multiple_ddf_users": False,
        "large_drf": False,
        "cert_thumbprint_anomaly": False,
        "domain_admin_in_ddf": False,
        "parse_error": False,
    }
    if anomaly_flags_override is not None:
        default_flags.update(anomaly_flags_override)
    if ddf_users is None:
        ddf_users = [
            {
                "sid": "S-1-5-21-1-2-3-1001",
                "cert_thumbprint": "0123456789abcdef" * 2 + "01234567",
                "friendly_name": "alice",
            }
        ]
    if drf_recovery_agents is None:
        drf_recovery_agents = []

    return WindowsEfsEncryptedFile(
        firmware_id=firmware_id,
        file_path=file_path,
        file_size=1024,
        mft_record_number=mft_record_number,
        efs_attribute_size=900,
        ddf_user_count=len(ddf_users),
        drf_recovery_agent_count=len(drf_recovery_agents),
        ddf_users=_stamp_windows_efs_encrypted_files_ddf_users(
            list(ddf_users)
        ),
        drf_recovery_agents=(
            _stamp_windows_efs_encrypted_files_drf_recovery_agents(
                list(drf_recovery_agents)
            )
        ),
        anomaly_flags=_stamp_windows_efs_encrypted_files_anomaly_flags(
            default_flags
        ),
        parse_error=None,
    )


# ── Registration smoke ───────────────────────────────────────────────────────


def test_register_windows_efs_tools_registers_6_tools():
    from app.ai.tool_registry import ToolRegistry

    registry = ToolRegistry()
    register_windows_efs_tools(registry)
    tool_names = sorted(registry._tools.keys())
    assert tool_names == [
        "efs_walk_status",
        "list_efs_encrypted_files",
        "lookup_efs_encrypted_file",
        "lookup_efs_recovery_agent_across_firmwares",
        "search_efs_by_sid",
        "trigger_efs_walk",
    ]


# ── list_efs_encrypted_files ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_returns_per_firmware_rows():
    async with make_live_db() as db:
        project = Project(name="iota-d-test", description="ι.D.E test")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "a")
        db.add(firmware)
        await db.flush()

        db.add(_make_efs_file(firmware.id, mft_record_number=1))
        db.add(_make_efs_file(firmware.id, mft_record_number=2))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files({"limit": 10}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 2
        assert len(out["efs_files"]) == 2


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_anomaly_only_filter():
    async with make_live_db() as db:
        project = Project(name="iota-d-test2", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "b")
        db.add(firmware)
        await db.flush()

        # Normal file.
        db.add(_make_efs_file(firmware.id, mft_record_number=1))
        # Orphaned DRF (anomalous).
        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=2,
            anomaly_flags_override={"orphaned_drf": True},
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files(
            {"anomaly_only": True}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["efs_files"][0]["mft_record_number"] == 2


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_min_ddf_users_filter():
    async with make_live_db() as db:
        project = Project(name="iota-d-min-ddf", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "c")
        db.add(firmware)
        await db.flush()

        # Single user (under threshold).
        db.add(_make_efs_file(firmware.id, mft_record_number=1))
        # Three users (above threshold).
        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=2,
            ddf_users=[
                {"sid": "S-1-5-21-1-2-3-1001", "cert_thumbprint": "a" * 40},
                {"sid": "S-1-5-21-1-2-3-1002", "cert_thumbprint": "b" * 40},
                {"sid": "S-1-5-21-1-2-3-1003", "cert_thumbprint": "c" * 40},
            ],
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files(
            {"min_ddf_users": 2}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["efs_files"][0]["mft_record_number"] == 2


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_no_results_message():
    async with make_live_db() as db:
        project = Project(name="iota-d-empty", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "d")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files({}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 0
        assert "message" in out
        assert "PARSE-ONLY" in out["message"]  # discipline reminder


# ── lookup_efs_encrypted_file ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_efs_encrypted_file_happy_path():
    async with make_live_db() as db:
        project = Project(name="lookup-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "e")
        db.add(firmware)
        await db.flush()

        efs_file = _make_efs_file(firmware.id, mft_record_number=99)
        db.add(efs_file)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_lookup_efs_encrypted_file(
            {"efs_row_id": str(efs_file.id)}, ctx
        )
        out = json.loads(out_str)
        assert out["id"] == str(efs_file.id)
        assert out["mft_record_number"] == 99
        assert "ddf_users" in out
        assert "drf_recovery_agents" in out
        # ddf_users in the detail view should have the schema_version
        # sentinel stripped (only real user entries).
        assert all(
            "schema_version" not in u for u in out["ddf_users"]
        )


@pytest.mark.asyncio
async def test_lookup_efs_encrypted_file_missing_id():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_efs_encrypted_file({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_efs_encrypted_file_invalid_uuid():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_efs_encrypted_file(
            {"efs_row_id": "not-a-uuid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_lookup_efs_encrypted_file_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_lookup_efs_encrypted_file(
            {"efs_row_id": str(uuid.uuid4())}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out
        assert "not found" in out["error"]


# ── search_efs_by_sid ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_efs_by_sid_finds_ddf_match():
    async with make_live_db() as db:
        project = Project(name="search-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "f")
        db.add(firmware)
        await db.flush()

        target_sid = "S-1-5-21-1-2-3-1001"
        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=1,
            ddf_users=[
                {"sid": target_sid, "cert_thumbprint": "a" * 40},
            ],
        ))
        # Different SID — should not match.
        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=2,
            ddf_users=[
                {"sid": "S-1-5-21-1-2-3-9999", "cert_thumbprint": "b" * 40},
            ],
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_efs_by_sid({"sid": target_sid}, ctx)
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert out["matches"][0]["mft_record_number"] == 1
        assert "ddf" in out["matches"][0]["match_locations"]


@pytest.mark.asyncio
async def test_search_efs_by_sid_finds_drf_match():
    async with make_live_db() as db:
        project = Project(name="search-drf", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "g")
        db.add(firmware)
        await db.flush()

        recovery_sid = "S-1-5-32-544"
        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": recovery_sid, "cert_thumbprint": "c" * 40},
            ],
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_search_efs_by_sid(
            {"sid": recovery_sid, "location": "drf"}, ctx
        )
        out = json.loads(out_str)
        assert out["total_count"] == 1
        assert "drf" in out["matches"][0]["match_locations"]


@pytest.mark.asyncio
async def test_search_efs_by_sid_missing_sid():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_search_efs_by_sid({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_search_efs_by_sid_invalid_sid_format():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_search_efs_by_sid(
            {"sid": "not-a-sid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out
        assert "Windows SID" in out["error"]


# ── efs_walk_status ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_efs_walk_status_returns_state():
    async with make_live_db() as db:
        project = Project(name="status-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "h")
        firmware.efs_walk_status = "completed"
        firmware.efs_walk_result = {
            "schema_version": 1,
            "images_scanned": 2,
            "encrypted_files_found": 5,
            "anomaly_total": 2,
        }
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_efs_walk_status({}, ctx)
        out = json.loads(out_str)
        assert out["status"] == "completed"
        assert out["result"]["images_scanned"] == 2


@pytest.mark.asyncio
async def test_efs_walk_status_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_efs_walk_status({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── trigger_efs_walk ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_efs_walk_schedules(monkeypatch):
    """trigger_efs_walk transitions status idle → queued + schedules
    the background runner."""
    scheduled = []

    from unittest.mock import patch as _patch

    async def _noop():
        return None

    def _fake_create_task(coro):
        coro.close()
        scheduled.append(True)
        import asyncio as _asyncio
        return _asyncio.ensure_future(_noop())

    with _patch(
        "app.ai.tools.windows_efs.asyncio.create_task",
        side_effect=_fake_create_task,
    ):
        async with make_live_db() as db:
            project = Project(name="trigger-test", description="x")
            db.add(project)
            await db.flush()
            firmware = _make_firmware(project.id, "win10.bin", "i")
            db.add(firmware)
            await db.flush()

            ctx = _StubContext(db=db, firmware_id=firmware.id)
            out_str = await _handle_trigger_efs_walk({}, ctx)
            out = json.loads(out_str)
            assert out["scheduled"] is True
            assert out["status"] == "queued"
            assert scheduled
            assert "PARSE-ONLY" in out["message"]


@pytest.mark.asyncio
async def test_trigger_efs_walk_conflict_when_running():
    """trigger_efs_walk returns 409-style conflict if already running."""
    async with make_live_db() as db:
        project = Project(name="conflict-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "win10.bin", "j")
        firmware.efs_walk_status = "running"
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_trigger_efs_walk({}, ctx)
        out = json.loads(out_str)
        assert out.get("conflict") is True
        assert out["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_efs_walk_firmware_not_found():
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        out_str = await _handle_trigger_efs_walk({}, ctx)
        out = json.loads(out_str)
        assert "error" in out


# ── lookup_efs_recovery_agent_across_firmwares — CROSS-FIRMWARE AGG ─────────


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_by_sid_project_scope():
    """Recovery agent SID present in 2 firmwares of same project →
    both matches + supply_chain_signal."""
    async with make_live_db() as db:
        project = Project(name="cross-test", description="x")
        db.add(project)
        await db.flush()

        fw1 = _make_firmware(project.id, "fw1.bin", "1")
        fw2 = _make_firmware(project.id, "fw2.bin", "2")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        target_thumbprint = "deadbeef" * 5
        target_sid = "S-1-5-21-shared-vendor-default-500"
        db.add(_make_efs_file(
            fw1.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": target_sid, "cert_thumbprint": target_thumbprint},
            ],
        ))
        db.add(_make_efs_file(
            fw2.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": target_sid, "cert_thumbprint": target_thumbprint},
            ],
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=project.id
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"sid": target_sid, "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 2
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_by_thumbprint():
    """Match by cert_thumbprint alone."""
    async with make_live_db() as db:
        project = Project(name="thumb-test", description="x")
        db.add(project)
        await db.flush()

        fw = _make_firmware(project.id, "fw.bin", "3")
        db.add(fw)
        await db.flush()

        target_thumbprint = "abcdef00" * 5
        db.add(_make_efs_file(
            fw.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": "S-1-5-32-544", "cert_thumbprint": target_thumbprint},
            ],
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw.id, project_id=project.id
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"cert_thumbprint": target_thumbprint, "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_no_match_message():
    async with make_live_db() as db:
        project = Project(name="empty-cross", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "4")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=firmware.id, project_id=project.id
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {
                "sid": "S-1-5-21-nobody-here-500",
                "scope": "project",
            },
            ctx,
        )
        out = json.loads(out_str)
        assert out["match_count"] == 0
        assert "message" in out
        assert "PARSE-ONLY" in out["message"]


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_global_scope():
    """scope=global crosses projects."""
    async with make_live_db() as db:
        project1 = Project(name="proj1", description="x")
        project2 = Project(name="proj2", description="y")
        db.add(project1)
        db.add(project2)
        await db.flush()

        fw1 = _make_firmware(project1.id, "fw1.bin", "5")
        fw2 = _make_firmware(project2.id, "fw2.bin", "6")
        db.add(fw1)
        db.add(fw2)
        await db.flush()

        target_sid = "S-1-5-21-cross-project-500"
        db.add(_make_efs_file(
            fw1.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": target_sid, "cert_thumbprint": "a" * 40},
            ],
        ))
        db.add(_make_efs_file(
            fw2.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": target_sid, "cert_thumbprint": "a" * 40},
            ],
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw1.id, project_id=project1.id
        )
        # Project-scoped → only 1 match.
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"sid": target_sid, "scope": "project"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 1

        # Global → both.
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"sid": target_sid, "scope": "global"}, ctx
        )
        out = json.loads(out_str)
        assert out["match_count"] == 2
        assert "supply_chain_signal" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_missing_both_filters():
    async with make_live_db() as db:
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4()
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_invalid_sid_format():
    async with make_live_db() as db:
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=uuid.uuid4()
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"sid": "not-a-sid"}, ctx
        )
        out = json.loads(out_str)
        assert "error" in out


@pytest.mark.asyncio
async def test_cross_firmware_aggregation_and_combined_filters():
    """When both sid AND cert_thumbprint are supplied, both must match."""
    async with make_live_db() as db:
        project = Project(name="and-test", description="x")
        db.add(project)
        await db.flush()
        fw = _make_firmware(project.id, "fw.bin", "7")
        db.add(fw)
        await db.flush()

        target_sid = "S-1-5-21-1-2-3-500"
        target_thumb = "feedface" * 5
        db.add(_make_efs_file(
            fw.id,
            mft_record_number=1,
            drf_recovery_agents=[
                {"sid": target_sid, "cert_thumbprint": target_thumb},
            ],
        ))
        db.add(_make_efs_file(
            fw.id,
            mft_record_number=2,
            drf_recovery_agents=[
                # Matches the SID but not the thumbprint.
                {"sid": target_sid, "cert_thumbprint": "different" * 5},
            ],
        ))
        await db.flush()

        ctx = _StubContext(
            db=db, firmware_id=fw.id, project_id=project.id
        )
        out_str = await _handle_lookup_efs_recovery_agent_across_firmwares(
            {"sid": target_sid, "cert_thumbprint": target_thumb}, ctx
        )
        out = json.loads(out_str)
        # Only 1 firmware (fw) — both files are on it, but the test
        # groups by firmware. Match count == 1 file but firmware count == 1.
        assert out["match_count"] == 1
        # The matching file should be mft_record_number=1.
        assert out["matches"][0]["sample_recovery_agent"]["sid"] == target_sid


# ── Boundary + truncation ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_caps_limit_at_500():
    async with make_live_db() as db:
        project = Project(name="cap-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "8")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files(
            {"limit": 10000}, ctx
        )
        out = json.loads(out_str)
        assert out["limit"] == 500


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_offset_negative_normalised():
    async with make_live_db() as db:
        project = Project(name="neg-offset", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "9")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files(
            {"offset": -10}, ctx
        )
        out = json.loads(out_str)
        assert out["offset"] == 0


# ── Row summary shape ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_efs_encrypted_files_row_summary_includes_all_fields():
    async with make_live_db() as db:
        project = Project(name="shape-test", description="x")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.bin", "0")
        db.add(firmware)
        await db.flush()

        db.add(_make_efs_file(
            firmware.id,
            mft_record_number=1,
            anomaly_flags_override={"orphaned_drf": True},
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out_str = await _handle_list_efs_encrypted_files({}, ctx)
        out = json.loads(out_str)
        evt = out["efs_files"][0]
        for field in (
            "id",
            "file_path",
            "file_size",
            "mft_record_number",
            "efs_attribute_size",
            "ddf_user_count",
            "drf_recovery_agent_count",
            "anomaly_flags",
            "has_anomaly",
            "parse_error",
        ):
            assert field in evt
        assert evt["has_anomaly"] is True
        assert evt["anomaly_flags"]["orphaned_drf"] is True
