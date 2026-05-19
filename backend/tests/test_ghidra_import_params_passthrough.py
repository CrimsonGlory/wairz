"""Test that ``ghidra_service._build_analyze_command`` honours the
``ghidra_import_params`` dict — the dormant infrastructure unlock
(CLAUDE.md Rule #52 Phase 1 P1.8, 2026-05-19).

Without this passthrough, three MediaTek parsers (mediatek_tinysys, atf,
geniezone) produce ``ghidra_import_params`` JSONB metadata that nobody
reads. The chip-family YAML for TI TMS320F28066 also declares Ghidra
hints. This test pins the flag-passthrough so future refactors don't
silently drop it.
"""
from __future__ import annotations

from app.services.ghidra_service import _build_analyze_command


def test_build_command_without_import_params_unchanged():
    """No ``ghidra_import_params`` → no new flags (backward-compat)."""
    cmd = _build_analyze_command(
        binary_path="/tmp/blob.bin",
        script_name="script.java",
        project_dir="/tmp/proj",
    )
    assert "-processor" not in cmd
    assert "-loader" not in cmd
    assert "-loader-baseAddr" not in cmd


def test_build_command_with_processor_loader_base():
    """All three core params flow through."""
    cmd = _build_analyze_command(
        binary_path="/tmp/blob.bin",
        script_name="script.java",
        project_dir="/tmp/proj",
        ghidra_import_params={
            "processor": "TMS320C28x:LE:32:default",
            "loader": "BinaryLoader",
            "base_addr": 0x3D8000,
        },
    )
    assert "-processor" in cmd
    assert cmd[cmd.index("-processor") + 1] == "TMS320C28x:LE:32:default"
    assert "-loader" in cmd
    assert cmd[cmd.index("-loader") + 1] == "BinaryLoader"
    assert "-loader-baseAddr" in cmd
    assert cmd[cmd.index("-loader-baseAddr") + 1] == "0x3D8000"


def test_build_command_with_offset_length_cspec():
    cmd = _build_analyze_command(
        binary_path="/tmp/blob.bin",
        script_name="script.java",
        project_dir="/tmp/proj",
        ghidra_import_params={
            "processor": "ARM:LE:32:Cortex",
            "load_offset_in_file": 0x1000,
            "load_length": 0x10000,
            "cspec": "default",
        },
    )
    assert cmd[cmd.index("-loader-fileOffset") + 1] == "4096"
    assert cmd[cmd.index("-loader-length") + 1] == "65536"
    assert cmd[cmd.index("-cspec") + 1] == "default"


def test_build_command_ignores_unknown_keys():
    """Future schema additions don't break the build path."""
    cmd = _build_analyze_command(
        binary_path="/tmp/blob.bin",
        script_name="script.java",
        project_dir="/tmp/proj",
        ghidra_import_params={
            "processor": "ARM:LE:32:Cortex",
            "future_key_we_dont_know_yet": "ignored",
            "schema_version": 2,
        },
    )
    assert "-processor" in cmd
    # Unknown keys should not produce flags
    assert "-future_key_we_dont_know_yet" not in cmd
    assert "-schema_version" not in cmd


def test_build_command_empty_params_dict_no_op():
    cmd = _build_analyze_command(
        binary_path="/tmp/blob.bin",
        script_name="script.java",
        project_dir="/tmp/proj",
        ghidra_import_params={},
    )
    assert "-processor" not in cmd
    assert "-loader-baseAddr" not in cmd
