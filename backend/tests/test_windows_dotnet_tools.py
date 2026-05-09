"""Phase δ.7: tests for windows_update + windows_storage + windows_dotnet
MCP tool categories.

Covers:

1. **Registration smoke** — all 16 new tools are registered in the
   default registry and bring the count from 197 to 213.
2. **Schema shape** — every tool exposes a JSON-schema input_schema +
   non-empty description (the MCP client requirement).
3. **Tool name uniqueness** — no name collisions with existing tools.

Per-handler unit tests covering each tool's DB / filesystem reads land
when the trigger flows are exercised in δ.9 cut-over real-firmware
canary; this file covers the wire-up surface.
"""
from __future__ import annotations

import pytest

from app.ai import create_tool_registry
from app.ai.tool_registry import ToolRegistry
from app.ai.tools.windows_dotnet import register_windows_dotnet_tools
from app.ai.tools.windows_storage import register_windows_storage_tools
from app.ai.tools.windows_update import register_windows_update_tools

# ─────────────────────────────────────────────────────────────────────────────
# Registry totals
# ─────────────────────────────────────────────────────────────────────────────


def test_registry_tool_count_post_delta():
    """δ.7 brought the registry from 197 (γ end) to 213 — 16 new tools
    across 3 new categories (5+5+6). ε.1.b.4 extended to 219 (windows_event_log).
    Lower-bound assertion accommodates future additions without per-phase
    test churn."""
    reg = create_tool_registry()
    assert len(reg._tools) >= 213


# ─────────────────────────────────────────────────────────────────────────────
# Per-category counts
# ─────────────────────────────────────────────────────────────────────────────


def test_windows_update_registers_5_tools():
    reg = ToolRegistry()
    register_windows_update_tools(reg)
    assert len(reg._tools) == 5
    expected = {
        "list_update_packages",
        "get_package_metadata",
        "get_supersedence_chain",
        "list_kb_files",
        "diff_kb_packages",
    }
    assert set(reg._tools.keys()) == expected


def test_windows_storage_registers_5_tools():
    reg = ToolRegistry()
    register_windows_storage_tools(reg)
    assert len(reg._tools) == 5
    expected = {
        "list_vhdx_partitions",
        "list_bcd_entries",
        "list_esedb_tables",
        "dump_esedb_table",
        "get_storage_summary",
    }
    assert set(reg._tools.keys()) == expected


def test_windows_dotnet_registers_6_tools():
    reg = ToolRegistry()
    register_windows_dotnet_tools(reg)
    assert len(reg._tools) == 6
    expected = {
        "list_dotnet_bundles",
        "get_bundle_metadata",
        "list_extracted_assemblies",
        "get_assembly_il",
        "scan_r2r_stomping",
        "trigger_dotnet_decompile",
    }
    assert set(reg._tools.keys()) == expected


# ─────────────────────────────────────────────────────────────────────────────
# Schema shape — JSON-schema compliance + non-empty descriptions
# ─────────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "register_fn",
    [
        register_windows_update_tools,
        register_windows_storage_tools,
        register_windows_dotnet_tools,
    ],
    ids=lambda f: f.__name__,
)
def test_each_tool_has_jsonschema_input(register_fn):
    """Every registered tool's input_schema must be a JSON-schema-shaped
    dict with type=object — MCP client decodes against this."""
    reg = ToolRegistry()
    register_fn(reg)
    for name, tool in reg._tools.items():
        assert isinstance(tool.input_schema, dict), name
        assert tool.input_schema.get("type") == "object", name
        assert "properties" in tool.input_schema, name


@pytest.mark.parametrize(
    "register_fn",
    [
        register_windows_update_tools,
        register_windows_storage_tools,
        register_windows_dotnet_tools,
    ],
    ids=lambda f: f.__name__,
)
def test_each_tool_has_non_trivial_description(register_fn):
    """Tool descriptions are non-empty + reasonably long — operators read
    these in Claude Code's tool picker."""
    reg = ToolRegistry()
    register_fn(reg)
    for name, tool in reg._tools.items():
        assert tool.description.strip(), name
        # Non-trivial — every δ.7 description is at minimum a sentence.
        assert len(tool.description) > 50, f"{name}: {tool.description}"


# ─────────────────────────────────────────────────────────────────────────────
# No collisions with pre-δ.7 tools
# ─────────────────────────────────────────────────────────────────────────────


def test_new_tool_names_dont_collide_with_existing():
    """δ.7's 16 tool names must be unique within the full registry — a
    collision would cause a silent overwrite."""
    full = create_tool_registry()
    new_names = (
        # windows_update
        {"list_update_packages", "get_package_metadata", "get_supersedence_chain",
         "list_kb_files", "diff_kb_packages"}
        # windows_storage
        | {"list_vhdx_partitions", "list_bcd_entries", "list_esedb_tables",
           "dump_esedb_table", "get_storage_summary"}
        # windows_dotnet
        | {"list_dotnet_bundles", "get_bundle_metadata", "list_extracted_assemblies",
           "get_assembly_il", "scan_r2r_stomping", "trigger_dotnet_decompile"}
    )
    assert len(new_names) == 16
    assert new_names.issubset(set(full._tools.keys()))
