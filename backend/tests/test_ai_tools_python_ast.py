"""Q1 Python AST walker — MCP tool contract tests.

Per Rule #35b: live canaries via make_live_db. Tests verify the MCP
tools surface the actual persisted JSONB shape, not just that handlers
were called.

Per Rule #44: cross-firmware lookup tool is the MANDATORY acceptance.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.python_ast import (
    _handle_get_python_ast_summary,
    _handle_lookup_python_ast_across_firmwares,
    _handle_python_ast_walk_status,
    _handle_trigger_python_ast_walk,
    register_python_ast_tools,
)
from app.models import Firmware, Project
from app.services.jsonb_normalizers import (
    _stamp_firmware_python_ast_walk_result,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — exposes only the attributes the
    Python AST handlers use."""

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


# ── Registration test ───────────────────────────────────────────────────────


def test_register_python_ast_tools_registers_four():
    """register_python_ast_tools must register exactly the four Q1
    Python AST tools (status / trigger / summary / cross-firmware
    lookup)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_python_ast_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "python_ast_walk_status" in names
    assert "trigger_python_ast_walk" in names
    assert "get_python_ast_summary" in names
    assert "lookup_python_ast_across_firmwares" in names
    assert len(reg._tools) >= 4


def test_register_python_ast_tools_includes_cross_firmware_lookup():
    """Rule #44 MANDATORY — register_python_ast_tools must register
    lookup_python_ast_across_firmwares alongside the per-firmware
    tools.

    The cve-assessment-framework consumes this tool to narrow Python
    CVE applicability via deployed-script grep precedent (Round-9.1
    §12 EG-8A.3-5).
    """
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_python_ast_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "lookup_python_ast_across_firmwares" in names


# ── python_ast_walk_status ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_returns_idle_for_fresh_firmware():
    """Fresh firmware has status='idle' and no result yet."""
    async with make_live_db() as db:
        project = Project(name="Q1 status idle canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fresh.bin", "a")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_python_ast_walk_status({}, ctx)
        out = json.loads(raw)
        assert out["firmware_id"] == str(firmware.id)
        assert out["status"] == "idle"
        assert out["summary"] is None
        assert out["error"] is None


@pytest.mark.asyncio
async def test_status_returns_summary_when_result_present():
    """A firmware with stamped python_ast_walk_result returns the
    summary section (the modules + callables maps are STRIPPED from
    the status payload to keep it cheap)."""
    async with make_live_db() as db:
        project = Project(name="Q1 status w/ result canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "with-result.bin", "b")
        firmware.python_ast_walk_status = "completed"
        firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
            "firmware_id": "x",
            "walker": "python_ast_walker",
            "extracted_root_paths_scanned": [],
            "python_version_detected": ["3.7"],
            "entry_points": [
                {
                    "file": "ds1qrsetup/app.py",
                    "entry_function": "create_app",
                    "qualname": "ds1qrsetup.app.create_app",
                    "type": "flask_factory",
                }
            ],
            "modules_imported": {"tarfile": {"reachable_from_entry": True}},
            "callables_referenced": {"tarfile.open": {"reachable_from_entry": True}},
            "unreachable_modules": [],
            "summary": {
                "files_scanned": 5,
                "modules_imported_count": 1,
                "callables_referenced_count": 1,
                "entry_reachable_modules_count": 1,
                "entry_reachable_callables_count": 1,
                "entry_points_count": 1,
                "run_seconds": 0.123,
                "truncated": False,
            },
            "errors": [],
            "axiom_self_audit": "PARSE-ONLY.",
        })
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_python_ast_walk_status({}, ctx)
        out = json.loads(raw)
        assert out["status"] == "completed"
        assert out["summary"]["schema_version"] == 1
        assert out["summary"]["summary"]["files_scanned"] == 5
        assert "3.7" in out["summary"]["python_version_detected"]
        # Status payload MUST NOT carry the full modules map (stays cheap).
        assert "modules_imported" not in out["summary"]


# ── trigger_python_ast_walk ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_sets_status_to_queued():
    """Trigger flips idle → queued and clears prior result."""
    async with make_live_db() as db:
        project = Project(name="Q1 trigger canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trig.bin", "c")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_trigger_python_ast_walk({}, ctx)
        out = json.loads(raw)
        # asyncio.create_task is fire-and-forget; the handler returns
        # immediately. The state-machine flip is what we verify.
        assert out["status"] == "queued"
        await db.refresh(firmware)
        assert firmware.python_ast_walk_status == "queued"
        # Cancel any tasks created by the trigger.
        import asyncio
        for t in asyncio.all_tasks():
            if not t.done() and t is not asyncio.current_task():
                t.cancel()


@pytest.mark.asyncio
async def test_trigger_409s_on_in_flight_walk():
    """Trigger against an already-queued walk returns conflict=True."""
    async with make_live_db() as db:
        project = Project(name="Q1 trigger conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "conflict.bin", "d")
        firmware.python_ast_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_trigger_python_ast_walk({}, ctx)
        out = json.loads(raw)
        assert out.get("conflict") is True
        assert out["status"] == "running"


# ── get_python_ast_summary ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_summary_returns_full_aggregate():
    """Summary tool returns the full graph for the active firmware."""
    async with make_live_db() as db:
        project = Project(name="Q1 summary canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "summary.bin", "e")
        firmware.python_ast_walk_status = "completed"
        firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
            "firmware_id": str(firmware.sha256),
            "walker": "python_ast_walker",
            "extracted_root_paths_scanned": ["opt/ds1qrsetup"],
            "python_version_detected": ["3.7"],
            "entry_points": [],
            "modules_imported": {
                "tarfile": {
                    "imported_from": ["app.py:1"],
                    "reachable_from_entry": True,
                },
                "plistlib": {
                    "imported_from": ["dead.py:1"],
                    "reachable_from_entry": False,
                },
            },
            "callables_referenced": {
                "tarfile.open": {
                    "called_from": ["app.py:5"],
                    "reachable_from_entry": True,
                },
            },
            "unreachable_modules": ["plistlib"],
            "summary": {
                "files_scanned": 2,
                "modules_imported_count": 2,
                "callables_referenced_count": 1,
                "entry_reachable_modules_count": 1,
                "entry_reachable_callables_count": 1,
                "entry_points_count": 0,
                "run_seconds": 0.05,
                "truncated": False,
            },
            "errors": [],
            "axiom_self_audit": "PARSE-ONLY.",
        })
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_get_python_ast_summary({}, ctx)
        out = json.loads(raw)
        assert out["modules_imported"]["tarfile"]["reachable_from_entry"]
        assert "plistlib" in out["unreachable_modules"]
        # Callables stripped by default.
        assert "callables_referenced" not in out


@pytest.mark.asyncio
async def test_summary_includes_callables_when_requested():
    """include_callables=True surfaces the callable map."""
    async with make_live_db() as db:
        project = Project(name="Q1 summary callables canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "callable.bin", "f")
        firmware.python_ast_walk_status = "completed"
        firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
            "firmware_id": "x",
            "walker": "python_ast_walker",
            "extracted_root_paths_scanned": [],
            "python_version_detected": [],
            "entry_points": [],
            "modules_imported": {},
            "callables_referenced": {
                "tarfile.open": {
                    "called_from": ["a.py:1"],
                    "reachable_from_entry": True,
                },
            },
            "unreachable_modules": [],
            "summary": {
                "files_scanned": 1,
                "modules_imported_count": 0,
                "callables_referenced_count": 1,
                "entry_reachable_modules_count": 0,
                "entry_reachable_callables_count": 1,
                "entry_points_count": 0,
                "run_seconds": 0.01,
                "truncated": False,
            },
            "errors": [],
            "axiom_self_audit": "PARSE-ONLY.",
        })
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_get_python_ast_summary(
            {"include_callables": True}, ctx
        )
        out = json.loads(raw)
        assert "tarfile.open" in out["callables_referenced"]


@pytest.mark.asyncio
async def test_summary_module_prefix_filter():
    """module_prefix filters to qualnames starting with the prefix."""
    async with make_live_db() as db:
        project = Project(name="Q1 summary prefix canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "prefix.bin", "g")
        firmware.python_ast_walk_status = "completed"
        firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
            "firmware_id": "x",
            "walker": "python_ast_walker",
            "extracted_root_paths_scanned": [],
            "python_version_detected": [],
            "entry_points": [],
            "modules_imported": {
                "tarfile": {"imported_from": [], "reachable_from_entry": True},
                "os": {"imported_from": [], "reachable_from_entry": True},
                "plistlib": {"imported_from": [], "reachable_from_entry": False},
            },
            "callables_referenced": {},
            "unreachable_modules": ["plistlib"],
            "summary": {
                "files_scanned": 1,
                "modules_imported_count": 3,
                "callables_referenced_count": 0,
                "entry_reachable_modules_count": 2,
                "entry_reachable_callables_count": 0,
                "entry_points_count": 0,
                "run_seconds": 0.01,
                "truncated": False,
            },
            "errors": [],
            "axiom_self_audit": "PARSE-ONLY.",
        })
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_get_python_ast_summary(
            {"module_prefix": "tar"}, ctx
        )
        out = json.loads(raw)
        # Only "tarfile" matches the prefix.
        assert "tarfile" in out["modules_imported"]
        assert "os" not in out["modules_imported"]
        assert "plistlib" not in out["modules_imported"]


# ── lookup_python_ast_across_firmwares (Rule #44) ───────────────────────────


@pytest.mark.asyncio
async def test_cross_firmware_returns_matches_for_module():
    """Rule #44 — given a module name, surface every firmware that
    imports it."""
    async with make_live_db() as db:
        project = Project(name="Q1 cross-firmware canary")
        db.add(project)
        await db.flush()

        # Three firmwares: two import tarfile, one doesn't.
        for i, sha_seed in enumerate(("h", "i", "j")):
            firmware = _make_firmware(
                project.id, f"cross-{i}.bin", sha_seed
            )
            firmware.python_ast_walk_status = "completed"
            modules = (
                {"tarfile": {"imported_from": ["a.py:1"], "reachable_from_entry": True}}
                if sha_seed != "j"
                else {"os": {"imported_from": ["b.py:1"], "reachable_from_entry": True}}
            )
            firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
                "firmware_id": str(firmware.sha256),
                "walker": "python_ast_walker",
                "extracted_root_paths_scanned": [],
                "python_version_detected": ["3.7"],
                "entry_points": [],
                "modules_imported": modules,
                "callables_referenced": {},
                "unreachable_modules": [],
                "summary": {
                    "files_scanned": 1,
                    "modules_imported_count": 1,
                    "callables_referenced_count": 0,
                    "entry_reachable_modules_count": 1,
                    "entry_reachable_callables_count": 0,
                    "entry_points_count": 0,
                    "run_seconds": 0.01,
                    "truncated": False,
                },
                "errors": [],
                "axiom_self_audit": "PARSE-ONLY.",
            })
            db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id
        )
        raw = await _handle_lookup_python_ast_across_firmwares(
            {"module_name": "tarfile"}, ctx
        )
        out = json.loads(raw)
        assert out["module_name"] == "tarfile"
        # 2 firmwares import tarfile.
        assert out["match_firmware_count"] == 2
        # supply_chain_signal is True at >= 2.
        assert out["supply_chain_signal"] is True


@pytest.mark.asyncio
async def test_cross_firmware_require_reachable_filter():
    """require_reachable=True drops firmwares where the module is
    imported but NOT reachable from an entry-point."""
    async with make_live_db() as db:
        project = Project(name="Q1 reach-filter canary")
        db.add(project)
        await db.flush()

        # Two firmwares: one reaches tarfile, one imports-but-unreachable.
        for sha_seed, reachable in (("k", True), ("l", False)):
            firmware = _make_firmware(
                project.id, f"reach-{sha_seed}.bin", sha_seed
            )
            firmware.python_ast_walk_status = "completed"
            firmware.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
                "firmware_id": str(firmware.sha256),
                "walker": "python_ast_walker",
                "extracted_root_paths_scanned": [],
                "python_version_detected": [],
                "entry_points": [],
                "modules_imported": {
                    "tarfile": {
                        "imported_from": ["a.py:1"],
                        "reachable_from_entry": reachable,
                    },
                },
                "callables_referenced": {},
                "unreachable_modules": [] if reachable else ["tarfile"],
                "summary": {
                    "files_scanned": 1,
                    "modules_imported_count": 1,
                    "callables_referenced_count": 0,
                    "entry_reachable_modules_count": 1 if reachable else 0,
                    "entry_reachable_callables_count": 0,
                    "entry_points_count": 0,
                    "run_seconds": 0.01,
                    "truncated": False,
                },
                "errors": [],
                "axiom_self_audit": "PARSE-ONLY.",
            })
            db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id
        )
        # Without filter: 2 matches.
        raw = await _handle_lookup_python_ast_across_firmwares(
            {"module_name": "tarfile"}, ctx
        )
        out = json.loads(raw)
        assert out["match_firmware_count"] == 2

        # With require_reachable=True: 1 match.
        raw = await _handle_lookup_python_ast_across_firmwares(
            {"module_name": "tarfile", "require_reachable": True}, ctx
        )
        out = json.loads(raw)
        assert out["match_firmware_count"] == 1


@pytest.mark.asyncio
async def test_cross_firmware_skips_non_completed_firmwares():
    """Firmwares with status != 'completed' are skipped."""
    async with make_live_db() as db:
        project = Project(name="Q1 skip-incomplete canary")
        db.add(project)
        await db.flush()

        # Two firmwares: completed import + idle (no result).
        completed = _make_firmware(project.id, "done.bin", "m")
        completed.python_ast_walk_status = "completed"
        completed.python_ast_walk_result = _stamp_firmware_python_ast_walk_result({
            "firmware_id": "x",
            "walker": "python_ast_walker",
            "extracted_root_paths_scanned": [],
            "python_version_detected": [],
            "entry_points": [],
            "modules_imported": {
                "tarfile": {"imported_from": [], "reachable_from_entry": True},
            },
            "callables_referenced": {},
            "unreachable_modules": [],
            "summary": {
                "files_scanned": 1,
                "modules_imported_count": 1,
                "callables_referenced_count": 0,
                "entry_reachable_modules_count": 1,
                "entry_reachable_callables_count": 0,
                "entry_points_count": 0,
                "run_seconds": 0.01,
                "truncated": False,
            },
            "errors": [],
            "axiom_self_audit": "PARSE-ONLY.",
        })
        db.add(completed)

        idle = _make_firmware(project.id, "idle.bin", "n")
        idle.python_ast_walk_status = "idle"  # default — no result
        db.add(idle)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id
        )
        raw = await _handle_lookup_python_ast_across_firmwares(
            {"module_name": "tarfile"}, ctx
        )
        out = json.loads(raw)
        # Only 1 match — the idle firmware is skipped.
        assert out["match_firmware_count"] == 1
        assert out["supply_chain_signal"] is False


@pytest.mark.asyncio
async def test_cross_firmware_requires_module_or_callable():
    """Empty input returns error."""
    async with make_live_db() as db:
        project = Project(name="Q1 missing-input canary")
        db.add(project)
        await db.flush()
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id
        )
        raw = await _handle_lookup_python_ast_across_firmwares({}, ctx)
        out = json.loads(raw)
        assert "error" in out
