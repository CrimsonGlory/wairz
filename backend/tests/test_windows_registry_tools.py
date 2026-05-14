"""Phase γ.6 — windows_registry MCP tool tests.

Tests every handler in ``app.ai.tools.windows_registry`` via a stubbed
ToolContext + the live SQLite session from ``tests._live_db.make_live_db``.
Covers:

- list_hives — empty / one-hive / multi-hive shapes.
- walk_hive — re-walks a hive on disk via patched regipy.
- get_run_keys — filtered by hive_path AND across all hives.
- scan_persistence — surfaces every persistence-relevant subkey.
- dump_subkey — case-insensitive lookup; missing path branch.
- diff_hives — lhs_only / rhs_only / both_changed shapes.
- trigger_registry_hive_walk — Rule #33 .a 409-on-conflict.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from unittest.mock import patch

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_registry import (
    _handle_diff_hives,
    _handle_dump_subkey,
    _handle_get_run_keys,
    _handle_list_hives,
    _handle_scan_persistence,
    _handle_trigger_walk,
    _handle_walk_hive,
    register_windows_registry_tools,
)
from app.models import (
    Firmware,
    HardwareFirmwareBlob,
    Project,
    WindowsRegistryExtract,
)
from app.services.jsonb_normalizers import (
    _stamp_windows_registry_extracts_parsed_tree,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub. resolve_path is a no-op pass-through
    so the walk_hive handler can be exercised without a real
    extraction root."""
    extracted_path: str
    db: object
    firmware_id: uuid.UUID = field(default_factory=uuid.uuid4)

    def resolve_path(self, p: str) -> str:
        return p


# ── Fixture builders ────────────────────────────────────────────────────────


async def _seed_firmware_with_hives(db) -> tuple[Firmware, list[WindowsRegistryExtract]]:
    """Seed a Project + Firmware + 2 HardwareFirmwareBlob (registry_hive)
    + 2 WindowsRegistryExtract rows (SOFTWARE + SYSTEM with one
    persistence subkey each)."""
    project = Project(name="γ.6-test")
    db.add(project)
    await db.flush()

    fw = Firmware(
        project_id=project.id,
        sha256="0" * 64,
        extracted_path="/tmp/test-extracted",
    )
    db.add(fw)
    await db.flush()

    sw_blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/System32/config/SOFTWARE",
        blob_sha256="a" * 64,
        file_size=1024,
        category="registry_hive",
        format="regf_hive",
        detection_source="registry_hive_walker",
    )
    sys_blob = HardwareFirmwareBlob(
        firmware_id=fw.id,
        blob_path="Windows/System32/config/SYSTEM",
        blob_sha256="b" * 64,
        file_size=1024,
        category="registry_hive",
        format="regf_hive",
        detection_source="registry_hive_walker",
    )
    db.add_all([sw_blob, sys_blob])
    await db.flush()

    sw_tree = _stamp_windows_registry_extracts_parsed_tree({
        "hive_type": "SOFTWARE",
        "walk_complete": True,
        "depth_limit": 5,
        "key_count": 2,
        "value_count": 2,
        "truncated": False,
        "errors": [],
        "subkeys": [
            {
                "path": "\\Microsoft\\Windows\\CurrentVersion\\Run",
                "values": [
                    {"name": "OneDrive", "type": "REG_SZ", "data": "C:\\OneDrive.exe"},
                ],
            },
            {
                "path": "\\Microsoft\\Some\\Other\\Key",
                "values": [
                    {"name": "Foo", "type": "REG_SZ", "data": "bar"},
                ],
            },
        ],
    })
    sys_tree = _stamp_windows_registry_extracts_parsed_tree({
        "hive_type": "SYSTEM",
        "walk_complete": True,
        "depth_limit": 5,
        "key_count": 1,
        "value_count": 1,
        "truncated": False,
        "errors": [],
        "subkeys": [
            {
                "path": "\\CurrentControlSet\\Services\\spooler",
                "values": [
                    {"name": "ImagePath", "type": "REG_EXPAND_SZ",
                     "data": "%SystemRoot%\\System32\\spoolsv.exe"},
                ],
            },
        ],
    })

    sw_extract = WindowsRegistryExtract(
        blob_id=sw_blob.id,
        hive_path="Windows/System32/config/SOFTWARE",
        hive_type="SOFTWARE",
        key_count=2,
        value_count=2,
        walk_status="completed",
        parsed_tree=sw_tree,
    )
    sys_extract = WindowsRegistryExtract(
        blob_id=sys_blob.id,
        hive_path="Windows/System32/config/SYSTEM",
        hive_type="SYSTEM",
        key_count=1,
        value_count=1,
        walk_status="completed",
        parsed_tree=sys_tree,
    )
    db.add_all([sw_extract, sys_extract])
    await db.flush()
    return fw, [sw_extract, sys_extract]


# ── list_hives ──────────────────────────────────────────────────────────────


async def test_list_hives_returns_persisted_rows(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_list_hives({}, ctx)
        payload = json.loads(out)

        assert payload["firmware_id"] == str(fw.id)
        assert len(payload["hives"]) == 2
        names = sorted(h["hive_type"] for h in payload["hives"])
        assert names == ["SOFTWARE", "SYSTEM"]
        # Walk metadata propagates.
        sw = next(h for h in payload["hives"] if h["hive_type"] == "SOFTWARE")
        assert sw["key_count"] == 2
        assert sw["walk_status"] == "completed"


async def test_list_hives_empty_when_no_extracts(tmp_path) -> None:
    async with make_live_db() as db:
        project = Project(name="empty")
        db.add(project)
        await db.flush()
        fw = Firmware(project_id=project.id, sha256="0" * 64)
        db.add(fw)
        await db.flush()
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_list_hives({}, ctx)
        assert json.loads(out)["hives"] == []


# ── get_run_keys ────────────────────────────────────────────────────────────


async def test_get_run_keys_filters_to_run_subkeys_across_all_hives(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_run_keys({}, ctx)
        payload = json.loads(out)

        # Only the SOFTWARE hive has a Run subkey; SYSTEM has services
        # which is persistence but NOT Run.
        assert len(payload["hives"]) == 1
        sw = payload["hives"][0]
        assert sw["hive_type"] == "SOFTWARE"
        assert any("Run" in (k.get("path") or "") for k in sw["run_keys"])


async def test_get_run_keys_filters_by_hive_path(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_run_keys(
            {"hive_path": "Windows/System32/config/SOFTWARE"}, ctx
        )
        payload = json.loads(out)
        assert len(payload["hives"]) == 1
        assert payload["hives"][0]["hive_type"] == "SOFTWARE"


async def test_get_run_keys_unknown_hive_returns_error(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_get_run_keys({"hive_path": "no/such/hive"}, ctx)
        assert "Error" in out
        assert "no walked hive" in out


# ── scan_persistence ────────────────────────────────────────────────────────


async def test_scan_persistence_surfaces_run_and_services(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_scan_persistence({}, ctx)
        payload = json.loads(out)

        # Run key in SOFTWARE + Services key in SYSTEM = 2 entries.
        assert payload["entry_count"] == 2
        paths = sorted(e["subkey_path"].lower() for e in payload["persistence_entries"])
        assert any("currentversion\\run" in p for p in paths)
        assert any("services\\spooler" in p for p in paths)


# ── dump_subkey ─────────────────────────────────────────────────────────────


async def test_dump_subkey_returns_values_at_path(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        # Case-insensitive + leading-backslash-optional.
        out = await _handle_dump_subkey(
            {
                "hive_path": "Windows/System32/config/SOFTWARE",
                "subkey_path": "microsoft\\windows\\currentversion\\run",
            },
            ctx,
        )
        payload = json.loads(out)
        assert any(v["name"] == "OneDrive" for v in payload["values"])


async def test_dump_subkey_missing_subkey_returns_none(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()

        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_dump_subkey(
            {
                "hive_path": "Windows/System32/config/SOFTWARE",
                "subkey_path": "Not/An/Existing/Key",
            },
            ctx,
        )
        payload = json.loads(out)
        assert payload["values"] is None
        assert "depth/key cap" in payload["note"]


async def test_dump_subkey_requires_both_params(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_dump_subkey({"hive_path": "x"}, ctx)
        assert "Error" in out
        out = await _handle_dump_subkey({"subkey_path": "x"}, ctx)
        assert "Error" in out


# ── diff_hives ──────────────────────────────────────────────────────────────


async def test_diff_hives_returns_difference(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)

        out = await _handle_diff_hives(
            {
                "lhs_hive_path": "Windows/System32/config/SOFTWARE",
                "rhs_hive_path": "Windows/System32/config/SYSTEM",
            },
            ctx,
        )
        payload = json.loads(out)
        # SOFTWARE has Run + Other; SYSTEM has Services\spooler. No overlap.
        assert payload["summary"]["lhs_only_count"] == 2
        assert payload["summary"]["rhs_only_count"] == 1
        assert payload["summary"]["both_changed_count"] == 0


async def test_diff_hives_unknown_hive_errors(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)
        out = await _handle_diff_hives(
            {"lhs_hive_path": "no/such", "rhs_hive_path": "Windows/System32/config/SYSTEM"},
            ctx,
        )
        assert "Error" in out


# ── walk_hive ───────────────────────────────────────────────────────────────


async def test_walk_hive_invokes_walker(tmp_path) -> None:
    """Patches walk_hive_path to confirm the handler delegates with
    the resolved path. Synthetic regf-magic-prefixed file makes the
    mock target a real OS path."""
    p = tmp_path / "SOFTWARE"
    p.write_bytes(b"regf" + b"\x00" * 64)

    async with make_live_db() as db:
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=uuid.uuid4())

        with patch(
            "app.services.registry_hive_walker.walk_hive_path",
            return_value={
                "hive_type": "SOFTWARE",
                "walk_complete": True,
                "subkeys": [],
                "errors": [],
            },
        ) as mock_walker:
            out = await _handle_walk_hive({"path": str(p)}, ctx)
        payload = json.loads(out)
        assert payload["hive_type"] == "SOFTWARE"
        assert mock_walker.called


async def test_walk_hive_requires_path_param(tmp_path) -> None:
    async with make_live_db() as db:
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=uuid.uuid4())
        out = await _handle_walk_hive({}, ctx)
        assert "Error" in out


# ── trigger_registry_hive_walk (Rule #33 .a) ────────────────────────────────


async def test_trigger_walk_queues_when_idle(tmp_path) -> None:
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)

        captured: list = []

        def _capture(coro):
            captured.append(coro)
            # Close the coroutine so it doesn't issue a warning at GC.
            coro.close()
            return None

        with patch(
            "app.ai.tools.windows_registry.asyncio.create_task",
            side_effect=_capture,
        ):
            out = await _handle_trigger_walk({}, ctx)

        payload = json.loads(out)
        assert payload["status"] == "queued"
        # Verify the firmware row's status transitioned.
        await db.refresh(fw)
        assert fw.registry_hive_walk_status == "queued"
        assert len(captured) == 1


async def test_trigger_walk_409s_when_already_queued(tmp_path) -> None:
    """Rule #33 .a — idempotent POST. If already queued/running, return
    the current status without spawning a duplicate."""
    async with make_live_db() as db:
        fw, _ = await _seed_firmware_with_hives(db)
        fw.registry_hive_walk_status = "running"
        await db.commit()
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=fw.id)

        captured: list = []

        def _capture(coro):
            captured.append(coro)
            coro.close()
            return None

        with patch(
            "app.ai.tools.windows_registry.asyncio.create_task",
            side_effect=_capture,
        ):
            out = await _handle_trigger_walk({}, ctx)
        payload = json.loads(out)
        assert payload["status"] == "running"
        assert "already running" in payload["message"]
        # No new task spawned.
        assert captured == []


async def test_trigger_walk_unknown_firmware_errors(tmp_path) -> None:
    async with make_live_db() as db:
        ctx = _StubContext(extracted_path=str(tmp_path), db=db, firmware_id=uuid.uuid4())
        out = await _handle_trigger_walk({}, ctx)
        assert "Error" in out
        assert "not found" in out


# ── Registration smoke ──────────────────────────────────────────────────────


def test_register_adds_eight_tools() -> None:
    reg = ToolRegistry()
    register_windows_registry_tools(reg)
    names = {t["name"] for t in reg.get_anthropic_tools()}
    assert names == {
        "list_hives",
        "walk_hive",
        "get_run_keys",
        "scan_persistence",
        "dump_subkey",
        "diff_hives",
        "trigger_registry_hive_walk",
        "lookup_registry_extract_across_firmwares",
    }


def test_register_windows_registry_tools_includes_cross_firmware_lookup():
    """Rule #44 acceptance — register_windows_registry_tools registers
    lookup_registry_extract_across_firmwares alongside the per-firmware
    tools. Issue #15 backfill for γ.4 walker."""
    reg = ToolRegistry()
    register_windows_registry_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "lookup_registry_extract_across_firmwares" in names
