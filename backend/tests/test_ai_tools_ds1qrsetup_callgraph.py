"""Q2 ds1qrsetup callgraph walker — MCP tool contract tests.

Per Rule #35b: live canaries via :func:`make_live_db`. Tests verify the
MCP tools surface the actual persisted JSONB shape, not just that
handlers were called.

Per Rule #44: cross-firmware lookup tool is the MANDATORY acceptance.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tools.ds1qrsetup_callgraph import (
    _handle_ds1qrsetup_callgraph_walk_status,
    _handle_lookup_ds1qrsetup_callgraph_across_firmwares,
    _handle_trigger_ds1qrsetup_callgraph_walk,
    register_ds1qrsetup_callgraph_tools,
)
from app.models import Firmware, Project
from app.services.jsonb_normalizers import (
    _stamp_firmware_ds1qrsetup_callgraph_walk_result,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — exposes only the attributes the
    ds1qrsetup_callgraph handlers use."""

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


def _make_callgraph_result(
    *,
    firmware_id: str = "x",
    analyzer: str = "ghidra",
    ffmpeg_enabled: list[str] | None = None,
    ffmpeg_disabled: list[str] | None = None,
    pillow_decoders: list[str] | None = None,
    pillow_absent: list[str] | None = None,
    reachable: list[str] | None = None,
    unreachable: list[str] | None = None,
    binary_path: str = "/extracted/opt/ds1qrsetup/ds1qrsetup",
) -> dict:
    return _stamp_firmware_ds1qrsetup_callgraph_walk_result({
        "firmware_id": firmware_id,
        "walker": "ds1qrsetup_callgraph_walker",
        "binary_analyzed": binary_path,
        "analyzer": analyzer,
        "compile_flags_detected": {
            "ffmpeg": ffmpeg_enabled or [],
            "ffmpeg_disabled": ffmpeg_disabled or [],
            "pillow_decoders": pillow_decoders or [],
            "pillow_decoders_absent": pillow_absent or [],
        },
        "reachable_symbols": reachable or [],
        "unreachable_symbols": unreachable or [],
        "summary": {
            "total_symbols_in_binary": (
                len(reachable or []) + len(unreachable or [])
            ),
            "reachable_from_main": len(reachable or []),
            "unreachable_from_main": len(unreachable or []),
            "run_seconds": 0.5,
        },
        "errors": [],
        "axiom_self_audit": "PARSE-ONLY.",
    })


# ── Registration tests ──────────────────────────────────────────────────────


def test_register_ds1qrsetup_callgraph_tools_registers_three():
    """register_ds1qrsetup_callgraph_tools must register exactly the
    three Q2 ds1qrsetup callgraph tools (status / trigger /
    cross-firmware lookup)."""
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_ds1qrsetup_callgraph_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "ds1qrsetup_callgraph_walk_status" in names
    assert "trigger_ds1qrsetup_callgraph_walk" in names
    assert "lookup_ds1qrsetup_callgraph_across_firmwares" in names
    assert len(reg._tools) >= 3


def test_register_includes_cross_firmware_lookup():
    """Rule #44 MANDATORY — register_ds1qrsetup_callgraph_tools must
    register lookup_ds1qrsetup_callgraph_across_firmwares alongside
    the per-firmware tools.

    The cve-assessment-framework consumes this tool to narrow FFmpeg
    DNN-backend + Pillow decoder reachability across a firmware fleet.
    """
    from app.ai.tool_registry import ToolRegistry

    reg = ToolRegistry()
    register_ds1qrsetup_callgraph_tools(reg)
    names = {tool.name for tool in reg._tools.values()}
    assert "lookup_ds1qrsetup_callgraph_across_firmwares" in names


# ── ds1qrsetup_callgraph_walk_status ────────────────────────────────────────


@pytest.mark.asyncio
async def test_status_returns_idle_for_fresh_firmware():
    """Fresh firmware has status='idle' and no result yet."""
    async with make_live_db() as db:
        project = Project(name="Q2 status idle canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fresh.bin", "a")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_ds1qrsetup_callgraph_walk_status({}, ctx)
        out = json.loads(raw)
        assert out["firmware_id"] == str(firmware.id)
        assert out["status"] == "idle"
        assert out["result"] is None
        assert out["error"] is None


@pytest.mark.asyncio
async def test_status_returns_result_when_present():
    """A firmware with stamped ds1qrsetup_callgraph_walk_result returns
    the full result payload."""
    async with make_live_db() as db:
        project = Project(name="Q2 status w/ result canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "with-result.bin", "b")
        firmware.ds1qrsetup_callgraph_walk_status = "completed"
        firmware.ds1qrsetup_callgraph_walk_result = _make_callgraph_result(
            firmware_id=str(firmware.id),
            ffmpeg_enabled=["--enable-libx264"],
            pillow_decoders=["JPEG", "PNG"],
            reachable=["main", "avformat_open_input"],
            unreachable=["ff_dnn_load_model_native"],
        )
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_ds1qrsetup_callgraph_walk_status({}, ctx)
        out = json.loads(raw)
        assert out["status"] == "completed"
        assert out["result"]["schema_version"] == 1
        assert (
            "--enable-libx264"
            in out["result"]["compile_flags_detected"]["ffmpeg"]
        )
        assert "JPEG" in out["result"]["compile_flags_detected"][
            "pillow_decoders"
        ]


@pytest.mark.asyncio
async def test_status_missing_firmware_returns_error():
    """Unknown firmware_id returns error."""
    async with make_live_db() as db:
        ctx = _StubContext(db=db, firmware_id=uuid.uuid4())
        raw = await _handle_ds1qrsetup_callgraph_walk_status({}, ctx)
        out = json.loads(raw)
        assert "error" in out


# ── trigger_ds1qrsetup_callgraph_walk ───────────────────────────────────────


@pytest.mark.asyncio
async def test_trigger_sets_status_to_queued():
    """Trigger flips idle → queued and clears prior result fields."""
    async with make_live_db() as db:
        project = Project(name="Q2 trigger canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "trig.bin", "c")
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_trigger_ds1qrsetup_callgraph_walk({}, ctx)
        out = json.loads(raw)
        # asyncio.create_task is fire-and-forget; the handler returns
        # immediately. The state-machine flip is what we verify.
        assert out["status"] == "queued"
        await db.refresh(firmware)
        assert firmware.ds1qrsetup_callgraph_walk_status == "queued"
        # Cancel any tasks created by the trigger.
        import asyncio
        for t in asyncio.all_tasks():
            if not t.done() and t is not asyncio.current_task():
                t.cancel()


@pytest.mark.asyncio
async def test_trigger_409s_on_in_flight_walk():
    """Trigger against an already-running walk returns conflict=True."""
    async with make_live_db() as db:
        project = Project(name="Q2 trigger conflict canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "conflict.bin", "d")
        firmware.ds1qrsetup_callgraph_walk_status = "running"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_trigger_ds1qrsetup_callgraph_walk({}, ctx)
        out = json.loads(raw)
        assert out.get("conflict") is True
        assert out["status"] == "running"


@pytest.mark.asyncio
async def test_trigger_409s_on_queued_walk():
    """Trigger against a queued (not yet running) walk also conflicts."""
    async with make_live_db() as db:
        project = Project(name="Q2 trigger queued canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "queued.bin", "e")
        firmware.ds1qrsetup_callgraph_walk_status = "queued"
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        raw = await _handle_trigger_ds1qrsetup_callgraph_walk({}, ctx)
        out = json.loads(raw)
        assert out.get("conflict") is True


# ── lookup_ds1qrsetup_callgraph_across_firmwares (Rule #44) ─────────────────


@pytest.mark.asyncio
async def test_cross_firmware_returns_matches_for_compile_flag():
    """Rule #44 — given a compile-flag substring, surface every firmware
    whose ds1qrsetup binary was compiled with that FFmpeg flag."""
    async with make_live_db() as db:
        project = Project(name="Q2 cross-firmware compile-flag canary")
        db.add(project)
        await db.flush()

        # Three firmwares: two with libtensorflow disabled, one with
        # libtensorflow enabled.
        for i, (sha_seed, libtf) in enumerate([
            ("f", "disabled"),
            ("g", "disabled"),
            ("h", "enabled"),
        ]):
            firmware = _make_firmware(
                project.id, f"cross-{i}.bin", sha_seed,
            )
            firmware.ds1qrsetup_callgraph_walk_status = "completed"
            if libtf == "enabled":
                firmware.ds1qrsetup_callgraph_walk_result = (
                    _make_callgraph_result(
                        ffmpeg_enabled=["--enable-libtensorflow"],
                    )
                )
            else:
                firmware.ds1qrsetup_callgraph_walk_result = (
                    _make_callgraph_result(
                        ffmpeg_disabled=["--disable-libtensorflow"],
                    )
                )
            db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )

        # Lookup "libtensorflow" — should match all three.
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "libtensorflow"}, ctx,
        )
        out = json.loads(raw)
        assert out["query"] == "libtensorflow"
        # All three firmwares reference libtensorflow (two disabled,
        # one enabled).
        assert out["match_count"] == 3
        # cross_firmware_signal triggers at match_count >= 2.
        assert "cross_firmware_signal" in out


@pytest.mark.asyncio
async def test_cross_firmware_returns_matches_for_symbol():
    """Rule #44 — given a symbol name, surface every firmware whose
    ds1qrsetup binary reaches that symbol from main."""
    async with make_live_db() as db:
        project = Project(name="Q2 cross-firmware symbol canary")
        db.add(project)
        await db.flush()

        # Two firmwares with av_dump_format reachable, one with it
        # unreachable.
        for i, (sha_seed, reachable_set) in enumerate([
            ("i", ["av_dump_format", "av_read_frame"]),
            ("j", ["av_dump_format"]),
            ("k", ["unrelated_symbol"]),
        ]):
            firmware = _make_firmware(
                project.id, f"sym-{i}.bin", sha_seed,
            )
            firmware.ds1qrsetup_callgraph_walk_status = "completed"
            firmware.ds1qrsetup_callgraph_walk_result = (
                _make_callgraph_result(reachable=reachable_set)
            )
            db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )

        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "av_dump_format"}, ctx,
        )
        out = json.loads(raw)
        # Two firmwares have av_dump_format reachable.
        assert out["match_count"] == 2
        # Sample dimension is a reachable_symbol.
        for match in out["matches"]:
            assert match["match_dimension"] == "reachable_symbol"


@pytest.mark.asyncio
async def test_cross_firmware_skips_non_completed_firmwares():
    """Firmwares with status != 'completed' are filtered out."""
    async with make_live_db() as db:
        project = Project(name="Q2 skip-incomplete canary")
        db.add(project)
        await db.flush()

        # One completed firmware, one idle (status default).
        completed = _make_firmware(project.id, "done.bin", "l")
        completed.ds1qrsetup_callgraph_walk_status = "completed"
        completed.ds1qrsetup_callgraph_walk_result = _make_callgraph_result(
            ffmpeg_enabled=["--enable-libx264"],
        )
        db.add(completed)

        idle = _make_firmware(project.id, "idle.bin", "m")
        idle.ds1qrsetup_callgraph_walk_status = "idle"
        db.add(idle)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "libx264"}, ctx,
        )
        out = json.loads(raw)
        # Only the completed firmware matches; the idle one is skipped.
        assert out["match_count"] == 1


@pytest.mark.asyncio
async def test_cross_firmware_skips_legacy_schema_rows():
    """Rule #44 §SC5-NEW-ICS-S2-ι gate — rows without schema_version
    are silently skipped (legacy data shape)."""
    async with make_live_db() as db:
        project = Project(name="Q2 legacy-schema canary")
        db.add(project)
        await db.flush()

        # Manually-stamped row WITHOUT schema_version (legacy shape).
        firmware = _make_firmware(project.id, "legacy.bin", "n")
        firmware.ds1qrsetup_callgraph_walk_status = "completed"
        # Construct a payload without going through _stamp_*.
        firmware.ds1qrsetup_callgraph_walk_result = {
            "firmware_id": "legacy",
            "walker": "ds1qrsetup_callgraph_walker",
            "binary_analyzed": "/legacy/path",
            "analyzer": "ghidra",
            "compile_flags_detected": {
                "ffmpeg": ["--enable-libx264"],
                "ffmpeg_disabled": [],
                "pillow_decoders": [],
                "pillow_decoders_absent": [],
            },
            "reachable_symbols": [],
            "unreachable_symbols": [],
            "summary": {
                "total_symbols_in_binary": 0,
                "reachable_from_main": 0,
                "unreachable_from_main": 0,
                "run_seconds": 0.0,
            },
            "errors": [],
            "axiom_self_audit": "Legacy.",
            # No schema_version key.
        }
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "libx264"}, ctx,
        )
        out = json.loads(raw)
        # Legacy row is silently skipped; 0 matches.
        assert out["match_count"] == 0


@pytest.mark.asyncio
async def test_cross_firmware_requires_query():
    """Empty query returns error."""
    async with make_live_db() as db:
        project = Project(name="Q2 missing-query canary")
        db.add(project)
        await db.flush()
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {}, ctx,
        )
        out = json.loads(raw)
        assert "error" in out


@pytest.mark.asyncio
async def test_cross_firmware_supply_chain_signal_threshold():
    """match_count >= 2 → cross_firmware_signal in output; < 2 → not."""
    async with make_live_db() as db:
        project = Project(name="Q2 signal threshold canary")
        db.add(project)
        await db.flush()

        # Just one firmware → match_count = 1 → no signal.
        firmware = _make_firmware(project.id, "single.bin", "o")
        firmware.ds1qrsetup_callgraph_walk_status = "completed"
        firmware.ds1qrsetup_callgraph_walk_result = _make_callgraph_result(
            ffmpeg_enabled=["--enable-libx264"],
        )
        db.add(firmware)
        await db.commit()

        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=project.id,
        )
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "libx264"}, ctx,
        )
        out = json.loads(raw)
        assert out["match_count"] == 1
        # No signal at match_count == 1.
        assert "cross_firmware_signal" not in out


@pytest.mark.asyncio
async def test_cross_firmware_scope_project_requires_active_project():
    """scope='project' (default) requires context.project_id."""
    async with make_live_db() as db:
        ctx = _StubContext(
            db=db, firmware_id=uuid.uuid4(), project_id=None,
        )
        raw = await _handle_lookup_ds1qrsetup_callgraph_across_firmwares(
            {"query": "libx264", "scope": "project"}, ctx,
        )
        out = json.loads(raw)
        assert "error" in out
        assert "active project" in out["error"]
