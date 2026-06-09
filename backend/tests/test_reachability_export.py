"""Reachability-export producer-core tests (binary-axis bridge MVP, 2026-06-08).

extract_elf_symbols is exercised against a REAL ELF (the running interpreter); the record
builder is pure. Soundness invariants: deferred axes stay NULL, stripped propagates, non-ELF
degrades to None (never fabricates absence).
"""
from __future__ import annotations

import os
import sys

from app.services.reachability_export import (
    REACHABILITY_EXPORT_SCHEMA_VERSION,
    build_reachability_record,
    extract_elf_symbols,
)


def test_extract_real_elf_has_symbols_and_not_stripped():
    syms = extract_elf_symbols(sys.executable)  # a real, dynamically-linked ELF
    assert syms is not None
    assert syms["format"] == "elf"
    assert syms["arch"] in ("x64", "x86", "ARM", "AArch64", "MIPS", "unknown")
    # a dynamically-linked interpreter imports libc functions -> imported non-empty, not stripped
    assert syms["has_dynsym"] is True
    assert len(syms["imported_symbols"]) > 0
    assert syms["stripped"] is False


def test_extract_non_elf_returns_none(tmp_path):
    f = tmp_path / "not_elf.bin"
    f.write_bytes(os.urandom(2048))
    assert extract_elf_symbols(str(f)) is None
    assert extract_elf_symbols(str(tmp_path / "missing")) is None


def test_build_record_shape_and_deferred_nulls():
    syms = {"defined_symbols": ["dhcp_packet", "main"], "imported_symbols": ["malloc"],
            "stripped": False, "has_symtab": True, "has_dynsym": True, "arch": "arm64", "format": "elf"}
    rec = build_reachability_record(
        "fw-123", "system/usr/sbin/dnsmasq", "a" * 64, syms,
        fingerprints={"tlsh": "T1ABC", "imphash": None},
        link_a={"listener_bound": True, "owning_daemon": "system/usr/sbin/dnsmasq"})
    assert rec["schema_version"] == REACHABILITY_EXPORT_SCHEMA_VERSION
    assert rec["binary_sha256"] == "a" * 64
    assert rec["binary_tlsh"] == "T1ABC"
    assert rec["defined_symbols"] == ["dhcp_packet", "main"]
    assert rec["derivation"] == "symbol_table"
    # DEFERRED axes MUST be explicitly null (never a negative the consumer could misread)
    assert rec["link_b_reachable"] is None
    assert rec["link_c_dataflow_path"] is None
    assert rec["completeness_proof"]["indirect_calls"] is None
    assert rec["confidence_score"] is None
    assert rec["completeness_proof"]["stripped"] is False
    assert rec["completeness_proof"]["analyzer"] == "pyelftools"


def test_build_record_propagates_stripped_and_empty_symbols():
    syms = {"defined_symbols": [], "imported_symbols": [], "stripped": True,
            "has_symtab": False, "has_dynsym": False, "arch": "arm64", "format": "elf"}
    rec = build_reachability_record("fw-1", "bin/busybox", "b" * 64, syms)
    assert rec["completeness_proof"]["stripped"] is True
    assert rec["defined_symbols"] == []
    # a stripped binary's empty defined set must be flagged so the consumer ABSTAINS
    assert rec["completeness_proof"]["has_symtab"] is False
    assert rec["completeness_proof"]["has_dynsym"] is False
    assert rec["link_a"] is None  # no listener supplied
