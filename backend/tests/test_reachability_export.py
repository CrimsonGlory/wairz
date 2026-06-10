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
    _rel_path,
    build_reachability_record,
    extract_elf_symbols,
)


def test_rel_path_detection_root_relative():
    # Prefers os.path.relpath against a detection root (handles scatter-zip / container roots whose
    # paths don't contain '/extracted/').
    roots = ["/data/fw/scatter_out", "/data/fw/scatter_out/sub"]
    assert _rel_path("/data/fw/scatter_out/system/lib/libc.so", roots) == "system/lib/libc.so"
    # longest/first matching root wins in order; a deeper root still relativises correctly
    assert _rel_path("/data/fw/scatter_out/sub/x.so", roots) == "sub/x.so"


def test_rel_path_fallbacks_never_raise():
    # No roots -> /extracted/ split; no marker -> bare path. Never raises (producer must not break).
    assert _rel_path("/x/extracted/a/elf.so", []) == "a/elf.so"
    assert _rel_path("/x/extracted/a/elf.so", None) == "a/elf.so"
    assert _rel_path("/weird/scatter/blob.bin", []) == "/weird/scatter/blob.bin"
    # a root that isn't a prefix is ignored (falls through to /extracted/ then bare)
    assert _rel_path("/other/extracted/z.so", ["/data/root"]) == "z.so"


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


def test_export_records_skips_non_elf_blobs(tmp_path, monkeypatch):
    """export_reachability_records skips blobs whose bytes aren't ELF (extract returns None)."""
    import asyncio
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock
    import app.services.reachability_export as rx

    blobs = [
        SimpleNamespace(blob_path="/x/extracted/a/elf.so", blob_sha256="s1", metadata_={"fingerprints": {"tlsh": "T1AA"}}),
        SimpleNamespace(blob_path="/x/extracted/a/data.bin", blob_sha256="s2", metadata_={}),
    ]
    db = MagicMock()
    # db.get(Firmware, id) is awaited for detection-root resolution; None -> roots=[] -> _rel_path
    # falls back to the /extracted/ split (preserves the relative-path assertion below).
    db.get = AsyncMock(return_value=None)
    result = MagicMock()
    result.scalars.return_value.all.return_value = blobs
    db.execute = AsyncMock(return_value=result)

    def fake_extract(path):
        if path.endswith("elf.so"):
            return {"defined_symbols": ["f"], "imported_symbols": [], "stripped": False,
                    "has_symtab": True, "has_dynsym": False, "arch": "arm64", "format": "elf"}
        return None  # non-ELF -> skipped
    monkeypatch.setattr(rx, "extract_elf_symbols", fake_extract)

    recs = asyncio.run(rx.export_reachability_records("fw-1", db))
    assert len(recs) == 1  # the .bin was skipped
    assert recs[0]["binary_path"] == "a/elf.so"  # detection-root-relative
    assert recs[0]["binary_tlsh"] == "T1AA"      # fingerprints folded from metadata_
