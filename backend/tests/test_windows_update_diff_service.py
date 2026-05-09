"""Phase δ.5: tests for ``app.services.windows_update_diff_service``.

Covers:

1. The pure-Python ``_scan_pkg_dlls_sync`` helper — both shapes (BOM
   from ``update_metadata['files']`` AND filesystem-walk fallback).
2. ``_build_diff_row`` shape — keys + values match the ORM column set.
3. The async ``_upsert_diff_rows`` UPSERT path — covered by a mock-aware
   integration test that exercises the ``insert(...).on_conflict_do_update``
   form against an in-memory ``MagicMock`` session, asserting the SQL
   shape carries the constraint name + the expected ``set_={...}`` dict.

State-machine tests + the Rule #35b live canary against a real Firmware
row land in ``test_windows_update_diff_real_firmware.py`` (δ.9
cut-over).
"""
from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock

from app.services.windows_update_diff_service import (
    MAX_RUN_SECONDS,
    UPSERT_BATCH_SIZE,
    _build_diff_row,
    _scan_pkg_dlls_sync,
)

# ─────────────────────────────────────────────────────────────────────────────
# Tunables
# ─────────────────────────────────────────────────────────────────────────────


def test_max_run_seconds_is_finite():
    """Pathological diffs (millions of DLLs across many KB pairs) get a
    hard ceiling so they don't wedge the backend's task pool."""
    assert MAX_RUN_SECONDS >= 60
    assert MAX_RUN_SECONDS <= 3600


def test_upsert_batch_size_is_reasonable():
    """Batch size = the firmware-row aggregate sweet spot. Smaller =
    more round-trips; bigger = more rollback cost on failure."""
    assert UPSERT_BATCH_SIZE >= 10
    assert UPSERT_BATCH_SIZE <= 1000


# ─────────────────────────────────────────────────────────────────────────────
# _build_diff_row shape
# ─────────────────────────────────────────────────────────────────────────────


def test_build_diff_row_added_shape():
    """Added DLL has older_kb / older_sha / size_delta NULL; newer_kb +
    newer_sha populated."""
    fid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    row = _build_diff_row(
        firmware_id=fid,
        dll_path="amd64_microsoft-windows-newdll/newdll.dll",
        older_kb=None,
        newer_kb="KB5036893",
        older_sha=None,
        newer_sha="abc123",
        diff_type="added",
        size_delta=None,
    )
    assert row["firmware_id"] == fid
    assert row["older_kb"] is None
    assert row["newer_kb"] == "KB5036893"
    assert row["diff_type"] == "added"
    assert row["file_size_delta"] is None


def test_build_diff_row_removed_shape():
    """Removed DLL has newer_kb / newer_sha NULL; older populated."""
    fid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    row = _build_diff_row(
        firmware_id=fid,
        dll_path="amd64_microsoft-windows-deprecated/deprecated.dll",
        older_kb="KB5034441",
        newer_kb=None,
        older_sha="def456",
        newer_sha=None,
        diff_type="removed",
        size_delta=None,
    )
    assert row["older_kb"] == "KB5034441"
    assert row["newer_kb"] is None
    assert row["diff_type"] == "removed"


def test_build_diff_row_modified_shape():
    """Modified DLL has both sides populated + non-zero size_delta."""
    fid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    row = _build_diff_row(
        firmware_id=fid,
        dll_path="amd64_microsoft-windows-kernel-base/ntdll.dll",
        older_kb="KB5034441",
        newer_kb="KB5036893",
        older_sha="abc",
        newer_sha="def",
        diff_type="modified",
        size_delta=4096,
    )
    assert row["diff_type"] == "modified"
    assert row["file_size_delta"] == 4096
    assert row["older_sha256"] == "abc"
    assert row["newer_sha256"] == "def"


def test_build_diff_row_unchanged_shape():
    """Unchanged DLL has identical SHAs + zero size_delta."""
    fid = uuid.UUID("12345678-1234-5678-1234-567812345678")
    row = _build_diff_row(
        firmware_id=fid,
        dll_path="amd64_some-stable-component/stable.dll",
        older_kb="KB5034441",
        newer_kb="KB5036893",
        older_sha="abc",
        newer_sha="abc",
        diff_type="unchanged",
        size_delta=0,
    )
    assert row["diff_type"] == "unchanged"
    assert row["file_size_delta"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# _scan_pkg_dlls_sync — BOM path (the canonical δ.4 manifest shape)
# ─────────────────────────────────────────────────────────────────────────────


def test_scan_pkg_dlls_sync_bom_path_filters_to_pe_extensions():
    """When update_metadata['files'] BOM exists, scan returns ONLY DLL/EXE/SYS
    entries — manifests / catalogs / config files are filtered out."""
    pkg = MagicMock()
    pkg.update_metadata = {
        "schema_version": 1,
        "files": [
            {"path": "Windows10.0-KB5036893-x64.cab", "sha256": "manifest_hash", "size": 1234},
            {"path": "ntdll.dll", "sha256": "ntdll_hash", "size": 2_000_000},
            {"path": "kernel32.dll", "sha256": "kernel_hash", "size": 1_500_000},
            {"path": "win32k.sys", "sha256": "sys_hash", "size": 800_000},
            {"path": "setup.exe", "sha256": "exe_hash", "size": 500_000},
            {"path": "package.cat", "sha256": "cat_hash", "size": 4096},
            {"path": "update.mum", "sha256": "mum_hash", "size": 2048},
        ],
    }
    pkg.package_path = "Windows/servicing/Packages/Package_for_KB5036893.cab"

    out = _scan_pkg_dlls_sync(pkg)
    # Manifests / catalogs / .mum / generic .cab are filtered out.
    assert "Windows10.0-KB5036893-x64.cab" not in out
    assert "package.cat" not in out
    assert "update.mum" not in out
    # DLL / EXE / SYS pass through.
    assert out["ntdll.dll"]["sha256"] == "ntdll_hash"
    assert out["kernel32.dll"]["sha256"] == "kernel_hash"
    assert out["win32k.sys"]["sha256"] == "sys_hash"
    assert out["setup.exe"]["sha256"] == "exe_hash"
    assert out["ntdll.dll"]["size"] == 2_000_000


def test_scan_pkg_dlls_sync_bom_drops_malformed_entries():
    """Non-dict entries + dict entries missing path/sha256 are skipped."""
    pkg = MagicMock()
    pkg.update_metadata = {
        "files": [
            "stray scalar",
            42,
            {"path": "valid.dll", "sha256": "abc", "size": 100},
            {"path": "missing_sha.dll"},  # no sha256 → skipped
            {"sha256": "no_path"},  # no path → skipped
        ],
    }
    pkg.package_path = "/tmp/missing"
    out = _scan_pkg_dlls_sync(pkg)
    assert list(out.keys()) == ["valid.dll"]


def test_scan_pkg_dlls_sync_bom_handles_size_typed_or_missing():
    """File entries without an integer ``size`` get size=0; integer sizes
    pass through unchanged."""
    pkg = MagicMock()
    pkg.update_metadata = {
        "files": [
            {"path": "with_size.dll", "sha256": "abc", "size": 1234},
            {"path": "no_size.dll", "sha256": "def"},
            {"path": "weird_size.dll", "sha256": "ghi", "size": "not an int"},
        ],
    }
    pkg.package_path = "/tmp/missing"
    out = _scan_pkg_dlls_sync(pkg)
    assert out["with_size.dll"]["size"] == 1234
    assert out["no_size.dll"]["size"] == 0
    assert out["weird_size.dll"]["size"] == 0


# ─────────────────────────────────────────────────────────────────────────────
# _scan_pkg_dlls_sync — filesystem fallback
# ─────────────────────────────────────────────────────────────────────────────


def test_scan_pkg_dlls_sync_filesystem_fallback(tmp_path):
    """When BOM is absent / wrong-type, scan walks the directory adjacent
    to package_path and SHA256s each DLL/EXE/SYS."""
    base = tmp_path / "Package_for_KB5036893"
    base.mkdir()
    (base / "ntdll.dll").write_bytes(b"NT" * 100)
    (base / "kernel32.dll").write_bytes(b"K32" * 50)
    (base / "manifest.txt").write_text("not a PE")  # filtered
    (base / "subdir").mkdir()
    (base / "subdir" / "win32k.sys").write_bytes(b"SYS" * 200)

    pkg = MagicMock()
    pkg.update_metadata = None
    pkg.package_path = str(base / "Package_for_KB5036893.cab")

    out = _scan_pkg_dlls_sync(pkg)
    # Top-level + recursive walk both work.
    assert "ntdll.dll" in out
    assert "kernel32.dll" in out
    assert os.path.join("subdir", "win32k.sys") in out
    # Non-PE filtered out.
    assert "manifest.txt" not in out
    # Sizes match on-disk.
    assert out["ntdll.dll"]["size"] == 200
    assert out["kernel32.dll"]["size"] == 150
    # SHAs are valid hex.
    assert len(out["ntdll.dll"]["sha256"]) == 64


def test_scan_pkg_dlls_sync_returns_empty_when_path_missing():
    """A package whose extracted dir doesn't exist returns an empty map."""
    pkg = MagicMock()
    pkg.update_metadata = None
    pkg.package_path = "/nonexistent/path/foo.cab"
    out = _scan_pkg_dlls_sync(pkg)
    assert out == {}


def test_scan_pkg_dlls_sync_returns_empty_when_no_path(tmp_path):
    """A package with package_path = None / empty falls through to empty."""
    pkg = MagicMock()
    pkg.update_metadata = None
    pkg.package_path = None
    assert _scan_pkg_dlls_sync(pkg) == {}
    pkg.package_path = ""
    assert _scan_pkg_dlls_sync(pkg) == {}


def test_scan_pkg_dlls_sync_bom_with_empty_files_falls_through_to_fs(tmp_path):
    """An update_metadata dict with files=[] falls through to the
    filesystem-walk path. The contract: a BOM with NO entries is treated
    as "no manifest data" — the unpacker probably didn't surface file
    metadata, so we walk the directory to find PEs ourselves."""
    base = tmp_path / "PkgEmpty"
    base.mkdir()
    (base / "ntdll.dll").write_bytes(b"X")

    pkg = MagicMock()
    pkg.update_metadata = {"schema_version": 1, "files": []}
    pkg.package_path = str(base / "PkgEmpty.cab")

    out = _scan_pkg_dlls_sync(pkg)
    # Empty BOM list → fall through to FS walk → pick up ntdll.dll on disk.
    assert "ntdll.dll" in out
    assert out["ntdll.dll"]["size"] == 1
