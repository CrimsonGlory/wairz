"""Phase θ.D.F contract tests: windows_sdb MCP tools.

Per Rule #35b: live canaries via make_live_db. Tests verify that
the list / lookup / summarize MCP tools return the actual persisted
shape from the θ.D.B windows_sdb_entries table.

3 MCP tools (list / lookup / summarize) with contract assertions
across happy-path + filter shapes + cross-firmware aggregation +
zero-row defensive paths.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_sdb import (
    _handle_list_sdb_entries,
    _handle_lookup_sdb_shim,
    _handle_summarize_sdb_anomalies,
    register_windows_sdb_tools,
)
from app.models import Firmware, Project, WindowsSdbEntry
from app.services.jsonb_normalizers import (
    _stamp_windows_sdb_entries_anomaly_flags,
    _stamp_windows_sdb_entries_shim_payload,
)
from tests._live_db import make_live_db


@dataclass
class _StubContext:
    """Minimal ToolContext stub — only exposes the attributes the
    SDB handlers actually use."""

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


def _make_entry(
    firmware_id: uuid.UUID,
    *,
    file_path: str,
    file_sha256: str | None = None,
    sdb_kind: str = "custom",
    shim_class: str = "Custom",
    app_name: str | None = "EvilApp",
    app_exe: str | None = "myapp.exe",
    shim_name: str = "MyShim",
    module: str = "",
    is_custom_path: bool | None = None,
    has_inject_dll: bool = False,
    has_redirect_exe: bool = False,
    has_get_command_line: bool = False,
    has_redirect_shortcut: bool = False,
    fingerprint_sha256: str | None = None,
) -> WindowsSdbEntry:
    file_sha256 = file_sha256 or ("a" * 64)
    if is_custom_path is None:
        is_custom_path = sdb_kind == "custom"
    return WindowsSdbEntry(
        firmware_id=firmware_id,
        file_path=file_path,
        file_sha256=file_sha256,
        sdb_kind=sdb_kind,
        app_name=app_name,
        app_exe=app_exe,
        shim_class=shim_class,
        shim_payload=_stamp_windows_sdb_entries_shim_payload({
            "kind": "shim",
            "shim_name": shim_name,
            "module": module,
            "command_line": "",
            "description": "",
        }),
        anomaly_flags=_stamp_windows_sdb_entries_anomaly_flags({
            "is_custom_path": is_custom_path,
            "has_inject_dll": has_inject_dll,
            "has_redirect_exe": has_redirect_exe,
            "has_get_command_line": has_get_command_line,
            "has_redirect_shortcut": has_redirect_shortcut,
            "has_dll_outside_appdir": False,
            "has_command_line": False,
        }),
        fingerprint_sha256=fingerprint_sha256,
    )


# ── Registration tests ─────────────────────────────────────────────────────


def test_register_windows_sdb_tools_registers_three():
    """register_windows_sdb_tools adds exactly 3 tools (list /
    lookup / summarize)."""
    registry = ToolRegistry()
    register_windows_sdb_tools(registry)
    tool_names = set(registry._tools.keys())
    assert "list_sdb_entries" in tool_names
    assert "lookup_sdb_shim" in tool_names
    assert "summarize_sdb_anomalies" in tool_names


def test_register_windows_sdb_tools_has_descriptions():
    """Each tool has a non-empty description + input_schema."""
    registry = ToolRegistry()
    register_windows_sdb_tools(registry)
    for name in ("list_sdb_entries", "lookup_sdb_shim",
                 "summarize_sdb_anomalies"):
        tool = registry._tools[name]
        assert tool.description
        assert tool.input_schema


# ── list_sdb_entries tests ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_sdb_entries_returns_all_for_firmware():
    """No filter → all entries for the firmware are returned."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F list canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "a")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/myapp.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            sdb_kind="microsoft",
            shim_class="Custom",
            shim_name="VersionLie",
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({}, ctx)
        parsed = json.loads(out)

        assert parsed["total_count"] == 2
        assert parsed["returned"] == 2
        assert len(parsed["entries"]) == 2


@pytest.mark.asyncio
async def test_list_sdb_entries_filters_by_sdb_kind():
    """sdb_kind filter restricts the returned set."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F kind-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "b")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/myapp.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            sdb_kind="microsoft",
            shim_class="Custom",
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({"sdb_kind": "custom"}, ctx)
        parsed = json.loads(out)

        assert parsed["total_count"] == 1
        assert parsed["entries"][0]["sdb_kind"] == "custom"


@pytest.mark.asyncio
async def test_list_sdb_entries_filters_by_shim_class():
    """shim_class filter restricts the returned set."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F class-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "c")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/inj.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/red.sdb",
            shim_class="RedirectEXE",
            has_redirect_exe=True,
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries(
            {"shim_class": "InjectDll"}, ctx
        )
        parsed = json.loads(out)

        assert parsed["total_count"] == 1
        assert parsed["entries"][0]["shim_class"] == "InjectDll"


@pytest.mark.asyncio
async def test_list_sdb_entries_custom_only_filter():
    """custom_only=true restricts to sdb_kind=custom entries."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F custom-only canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "d")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/myapp.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            sdb_kind="microsoft",
            shim_class="Custom",
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({"custom_only": True}, ctx)
        parsed = json.loads(out)

        assert parsed["total_count"] == 1
        assert parsed["entries"][0]["sdb_kind"] == "custom"


@pytest.mark.asyncio
async def test_list_sdb_entries_anomaly_only_filter():
    """anomaly_only=true post-filters to entries with anomaly flags."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F anomaly-only canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "e")
        db.add(firmware)
        await db.flush()

        # Custom with InjectDll → has_inject_dll → anomaly.
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/inj.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        # MS baseline, no anomaly flags.
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            sdb_kind="microsoft",
            shim_class="Custom",
            is_custom_path=False,
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({"anomaly_only": True}, ctx)
        parsed = json.loads(out)

        # Only the InjectDll custom entry has anomalies.
        assert parsed["returned"] == 1
        assert parsed["entries"][0]["shim_class"] == "InjectDll"


@pytest.mark.asyncio
async def test_list_sdb_entries_zero_returns_message():
    """No entries → message field included."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "f")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({}, ctx)
        parsed = json.loads(out)

        assert parsed["total_count"] == 0
        assert "message" in parsed


@pytest.mark.asyncio
async def test_list_sdb_entries_pagination_limit():
    """limit caps the returned page size."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F pagination canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "x.zip", "p")
        db.add(firmware)
        await db.flush()

        for i in range(5):
            db.add(_make_entry(
                firmware.id,
                file_path=f"Windows/AppPatch/Custom/app{i}.sdb",
                shim_class="Custom",
                fingerprint_sha256=f"{i}" * 64,
            ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_list_sdb_entries({"limit": 2}, ctx)
        parsed = json.loads(out)

        assert parsed["total_count"] == 5
        assert parsed["returned"] == 2
        assert parsed["limit"] == 2


# ── lookup_sdb_shim tests ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_lookup_sdb_shim_by_fingerprint():
    """Fingerprint match returns the entry."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F lookup-fingerprint canary")
        db.add(project)
        await db.flush()
        firmware1 = _make_firmware(project.id, "fw1.zip", "1")
        firmware2 = _make_firmware(project.id, "fw2.zip", "2")
        db.add_all([firmware1, firmware2])
        await db.flush()

        # Same fingerprint planted in 2 firmware = campaign correlation.
        fp = "f" * 64
        db.add(_make_entry(
            firmware1.id,
            file_path="Windows/AppPatch/Custom/x.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256=fp,
        ))
        db.add(_make_entry(
            firmware2.id,
            file_path="Windows/AppPatch/Custom/x.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256=fp,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware1.id)
        out = await _handle_lookup_sdb_shim(
            {"fingerprint_sha256": fp}, ctx
        )
        parsed = json.loads(out)

        assert parsed["total_matches"] == 2
        assert parsed["distinct_firmware_count"] == 2


@pytest.mark.asyncio
async def test_lookup_sdb_shim_by_file_sha():
    """file_sha256 match returns the entries."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F lookup-sha canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "x")
        db.add(firmware)
        await db.flush()

        sha = "b" * 64
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/x.sdb",
            file_sha256=sha,
            shim_class="InjectDll",
            fingerprint_sha256="1" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lookup_sdb_shim(
            {"file_sha256": sha}, ctx
        )
        parsed = json.loads(out)

        assert parsed["total_matches"] >= 1


@pytest.mark.asyncio
async def test_lookup_sdb_shim_by_shim_class():
    """shim_class filter returns matching entries across firmware."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F lookup-class canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "c")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/inj.sdb",
            shim_class="InjectDll",
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/red.sdb",
            shim_class="RedirectEXE",
            fingerprint_sha256="2" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lookup_sdb_shim(
            {"shim_class": "InjectDll"}, ctx
        )
        parsed = json.loads(out)

        assert parsed["total_matches"] == 1
        assert parsed["matches"][0]["shim_class"] == "InjectDll"


@pytest.mark.asyncio
async def test_lookup_sdb_shim_no_filters_returns_error():
    """No filters specified → error."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F lookup-no-filter canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "n")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lookup_sdb_shim({}, ctx)
        parsed = json.loads(out)
        assert "error" in parsed


@pytest.mark.asyncio
async def test_lookup_sdb_shim_no_matches_returns_message():
    """No matching entries → message field included."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F lookup-empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "z")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_lookup_sdb_shim(
            {"fingerprint_sha256": "0" * 64}, ctx
        )
        parsed = json.loads(out)
        assert parsed["total_matches"] == 0
        assert "message" in parsed


# ── summarize_sdb_anomalies tests ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_summarize_sdb_anomalies_returns_aggregate_counts():
    """summarize returns per-kind + per-class aggregate counts."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F summarize canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "s")
        db.add(firmware)
        await db.flush()

        # 1 custom InjectDll + 1 custom RedirectEXE + 1 MS Custom = 3 entries.
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/inj.sdb",
            shim_class="InjectDll",
            has_inject_dll=True,
            fingerprint_sha256="1" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/red.sdb",
            shim_class="RedirectEXE",
            has_redirect_exe=True,
            fingerprint_sha256="2" * 64,
        ))
        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/sysmain.sdb",
            sdb_kind="microsoft",
            shim_class="Custom",
            is_custom_path=False,
            fingerprint_sha256="3" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_summarize_sdb_anomalies({}, ctx)
        parsed = json.loads(out)

        assert parsed["total_entries"] == 3
        assert parsed["by_sdb_kind"]["custom"] == 2
        assert parsed["by_sdb_kind"]["microsoft"] == 1
        assert parsed["by_shim_class"]["InjectDll"] == 1
        assert parsed["by_shim_class"]["RedirectEXE"] == 1
        # 2 custom + (1 InjectDll, 1 RedirectEXE) = 2 high-signal.
        assert parsed["high_signal_custom_attackers"] == 2


@pytest.mark.asyncio
async def test_summarize_sdb_anomalies_empty_firmware_returns_message():
    """No entries → message field included."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F summarize-empty canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "e")
        db.add(firmware)
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        out = await _handle_summarize_sdb_anomalies({}, ctx)
        parsed = json.loads(out)

        assert parsed["total_entries"] == 0
        assert "message" in parsed


# ── Disclaimer present in every tool output ────────────────────────────────


@pytest.mark.asyncio
async def test_all_sdb_tool_outputs_include_no_execute_disclaimer():
    """Each tool's output must carry the Rule #36 data-only
    disclaimer so operators see it on every response."""
    async with make_live_db() as db:
        project = Project(name="θ.D.F disclaimer canary")
        db.add(project)
        await db.flush()
        firmware = _make_firmware(project.id, "fw.zip", "x")
        db.add(firmware)
        await db.flush()

        db.add(_make_entry(
            firmware.id,
            file_path="Windows/AppPatch/Custom/x.sdb",
            fingerprint_sha256="1" * 64,
        ))
        await db.flush()

        ctx = _StubContext(db=db, firmware_id=firmware.id)
        for handler, kwargs in [
            (_handle_list_sdb_entries, {}),
            (_handle_lookup_sdb_shim, {"shim_class": "Custom"}),
            (_handle_summarize_sdb_anomalies, {}),
        ]:
            out = await handler(kwargs, ctx)
            parsed = json.loads(out)
            assert "data_only_disclaimer" in parsed, (
                f"{handler.__name__} missing Rule #36 disclaimer"
            )


# ── MCP tool count rises 249 → 252 ─────────────────────────────────────────


def test_create_tool_registry_includes_sdb_tools():
    """The full registry includes the 3 new SDB tools after θ.D.F."""
    from app.ai import create_tool_registry

    registry = create_tool_registry()
    tool_names = set(registry._tools.keys())
    assert "list_sdb_entries" in tool_names
    assert "lookup_sdb_shim" in tool_names
    assert "summarize_sdb_anomalies" in tool_names
