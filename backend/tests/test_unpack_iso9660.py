"""Phase 2 handler 1 contract tests: :func:`unpack_iso9660`.

Six unit tests cover the failure modes (binary missing, timeout,
non-zero exit, no fs_root, fs_root present) plus a Rule #35b live
canary that builds a real ISO 9660 image with mkisofs and extracts
it through the full subprocess path.

The strategy-table assertion lives in test_extraction_pipeline.py
(test_iso_9660_routes_to_unpack_iso9660) so the lockstep between the
worker module and the registry is enforced from the dispatch side.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_iso9660 import (
    _SEVENZ_TIMEOUT_SECONDS,
    unpack_iso9660,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_proc_stub(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> object:
    """Build an awaitable subprocess stub for asyncio.create_subprocess_exec.

    Mimics the surface the worker actually uses: ``await proc.communicate()``
    returning ``(stdout, stderr)``, plus ``proc.returncode`` and
    ``proc.kill()``.
    """
    class _Proc:
        def __init__(self) -> None:
            self.returncode = returncode

        async def communicate(self) -> tuple[bytes, bytes]:
            return stdout, stderr

        def kill(self) -> None:
            pass

    return _Proc()


# ---------------------------------------------------------------------------
# 1. 7z binary missing → clear failure with install hint.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_reports_missing_7z_binary(tmp_path: Path):
    iso = tmp_path / "fake.iso"
    iso.write_bytes(b"\x00" * 1024)

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "7z binary missing" in result.error
    # The unpack_log must carry the install hint so operators can act.
    assert "p7zip-full" in result.unpack_log
    assert "rebuild" in result.unpack_log.lower()


# ---------------------------------------------------------------------------
# 2. 7z extraction timeout → result.error names the timeout ceiling.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_reports_timeout(tmp_path: Path):
    iso = tmp_path / "huge.iso"
    iso.write_bytes(b"\x00" * 1024)

    proc_stub = _make_proc_stub(returncode=0)

    async def _raise_timeout(*_a, **_kw):
        raise TimeoutError

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_stub),
    ), patch(
        "app.workers.unpack_iso9660.asyncio.wait_for",
        side_effect=_raise_timeout,
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_SEVENZ_TIMEOUT_SECONDS}s" in result.error


# ---------------------------------------------------------------------------
# 3. 7z non-zero exit (>=2) → failure with the truncated stderr.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_reports_nonzero_exit(tmp_path: Path):
    iso = tmp_path / "broken.iso"
    iso.write_bytes(b"\x00" * 1024)

    stderr_blob = b"ERROR: Cannot open the file as archive\n"
    proc_stub = _make_proc_stub(returncode=2, stderr=stderr_blob)

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(return_value=proc_stub),
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "exit=2" in result.error
    assert "Cannot open the file as archive" in result.error
    # The full log must also include the exit code header for forensics.
    assert "7z exit=2" in result.unpack_log


# ---------------------------------------------------------------------------
# 4. 7z exit 0 + Unix-style fs_root present → success with extracted_path
#    pointing at the rootfs.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_finds_unix_filesystem_root(tmp_path: Path):
    iso = tmp_path / "linux_recovery.iso"
    iso.write_bytes(b"\x00" * 1024)

    # Pre-populate extraction_dir with a fake rootfs so find_filesystem_root
    # returns a real path. The worker calls shutil.rmtree on extraction_dir
    # before running 7z, so we have to plant the rootfs INSIDE the
    # subprocess stub's communicate() — but communicate() runs as a coroutine
    # that we control, and run_in_executor's lambda runs after. The
    # cleanest pattern: side_effect on create_subprocess_exec writes the
    # fake tree just before returning the proc stub.
    extraction_dir = tmp_path / "extracted"

    def _populate_then_stub(*_a, **_kw):
        # _a contains ("7z", "x", "-y", "-o<extraction_dir>", iso_path).
        # extraction_dir already exists (worker mkdirs it before exec);
        # plant a Linux marker tree.
        for sub in ("etc", "usr", "bin", "lib"):
            os.makedirs(extraction_dir / sub, exist_ok=True)
        (extraction_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        (extraction_dir / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate_then_stub),
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    # extracted_path resolves to a directory that contains etc/.
    assert os.path.isdir(os.path.join(result.extracted_path, "etc"))
    assert "ISO 9660 extraction complete via 7z" in result.unpack_log


# ---------------------------------------------------------------------------
# 5. 7z exit 0 + no Unix-style fs_root → still success, extracted_path
#    falls back to the extraction directory itself.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_no_unix_fs_root_still_success(tmp_path: Path):
    iso = tmp_path / "windows_installer.iso"
    iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    def _populate_windows_layout(*_a, **_kw):
        # Windows installer ISO style: bootmgr + sources/ — no Linux markers.
        (extraction_dir / "bootmgr").write_bytes(b"\x4d\x5a" + b"\x00" * 100)  # MZ
        os.makedirs(extraction_dir / "sources", exist_ok=True)
        (extraction_dir / "sources" / "install.wim").write_bytes(b"MSWIM\x00\x00\x00")
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate_windows_layout),
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    # extracted_path resolves to the extraction directory itself —
    # find_filesystem_root's entry-count fallback returns the dir with
    # the most entries, and for a Windows installer layout that's the
    # extraction root. The file explorer can browse it from there.
    assert result.extracted_path == str(extraction_dir)
    # Architecture detection runs against the resolved fs_root and
    # produces None for a Windows-only tree (no ELF binaries to inspect).
    assert result.architecture is None


# ---------------------------------------------------------------------------
# 5b. find_filesystem_root returns None → else-branch fallback message
#     and extracted_path = extraction_dir.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_falls_back_when_no_filesystem_root(tmp_path: Path):
    """When find_filesystem_root returns None (vendor archive that wraps
    a raw FS image, etc.), the worker still reports success and falls
    back extracted_path = extraction_dir + emits the explanatory log.
    """
    iso = tmp_path / "vendor.iso"
    iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    def _populate(*_a, **_kw):
        (extraction_dir / "vendor.bin").write_bytes(b"\x00" * 1024)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ), patch(
        "app.workers.unpack_iso9660.find_filesystem_root",
        return_value=None,
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert result.extracted_path == str(extraction_dir)
    assert "no Unix-style filesystem root" in result.unpack_log


# ---------------------------------------------------------------------------
# 6. 7z exit 1 (warnings) treated as success.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_treats_exit_1_as_success(tmp_path: Path):
    """7z exit code 1 means non-fatal warnings — extraction completed."""
    iso = tmp_path / "with_warnings.iso"
    iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    def _populate(*_a, **_kw):
        (extraction_dir / "data").write_bytes(b"x" * 1024)
        return _make_proc_stub(returncode=1, stderr=b"WARNING: skipping x\n")

    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        result = await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert result.error is None
    assert "7z exit=1" in result.unpack_log


# ---------------------------------------------------------------------------
# 7. Progress-callback contract — worker reports 10 / 70 / 100 milestones.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_iso9660_invokes_progress_callback(tmp_path: Path):
    iso = tmp_path / "small.iso"
    iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    def _populate(*_a, **_kw):
        (extraction_dir / "etc").mkdir(exist_ok=True)
        (extraction_dir / "usr").mkdir(exist_ok=True)
        (extraction_dir / "bin").mkdir(exist_ok=True)
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_iso9660.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_populate),
    ):
        await unpack_iso9660(
            firmware_path=str(iso),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    # Last call must be the 100% sentinel so the upstream router
    # transitions the firmware row out of the unpacking stage.
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 8. Rule #35b live canary — build a real ISO with mkisofs/genisoimage
#    and extract it through the full 7z subprocess path.
# ---------------------------------------------------------------------------

def _have_iso_creator() -> str | None:
    """Return the name of an available ISO-creation CLI, or None."""
    for name in ("mkisofs", "genisoimage", "xorrisofs"):
        if shutil.which(name):
            return name
    return None


@pytest.mark.asyncio
async def test_unpack_iso9660_live_canary_real_iso(tmp_path: Path):
    """Build a real ISO 9660 image and extract it through the actual 7z CLI.

    Rule #35b live canary — mocks confirm the contract we wrote, this
    test confirms the contract 7z actually has. If 7z's exit semantics
    or its `-o<dir>` flag handling drift on a future container update,
    this canary will catch it before production traffic does.
    """
    iso_creator = _have_iso_creator()
    if not iso_creator:
        pytest.skip(
            "No ISO creation tool available (mkisofs / genisoimage / xorrisofs)",
        )
    if not shutil.which("7z"):
        pytest.skip("7z binary not on PATH")

    src_tree = tmp_path / "iso_src"
    (src_tree / "etc").mkdir(parents=True)
    (src_tree / "bin").mkdir()
    (src_tree / "usr").mkdir()
    (src_tree / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
    (src_tree / "etc" / "hostname").write_text("canary-host\n")
    (src_tree / "bin" / "sh").write_bytes(b"\x7fELF" + b"\x00" * 60)

    iso_path = tmp_path / "canary.iso"
    # -R = Rock Ridge (preserves long names + Unix metadata); -o = output.
    proc = subprocess.run(  # noqa: ASYNC221 — synthetic test-fixture build; sync CLI shell-out is intentional in test setup
        [iso_creator, "-quiet", "-R", "-o", str(iso_path), str(src_tree)],
        capture_output=True,
        timeout=30,
    )
    if proc.returncode != 0 or not iso_path.exists():
        pytest.skip(
            f"{iso_creator} failed (rc={proc.returncode}): "
            f"{proc.stderr.decode(errors='replace')[:200]}",
        )

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_iso9660(
        firmware_path=str(iso_path),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None

    # Value-flow check: every file we put in the source tree must land in
    # the extraction tree. find_filesystem_root may home in on a sub-dir
    # so resolve the canonical extraction_dir for the file-presence check.
    extract_root = result.extraction_dir or result.extracted_path

    # Walk the extracted tree and confirm the planted files exist.
    found_files: set[str] = set()
    for root, _dirs, files in os.walk(extract_root):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), extract_root)
            found_files.add(rel.lower())  # ISO 9660 may lowercase names

    # Rock Ridge preserves case; older ISOs would uppercase. Accept either.
    expected = ("etc/hosts", "etc/hostname", "bin/sh")
    for expected_rel in expected:
        assert any(
            expected_rel == found or expected_rel.upper() == found.upper()
            for found in found_files
        ), f"missing {expected_rel} in extracted tree; have: {sorted(found_files)[:20]}"

    # Architecture detection should resolve when an ELF binary is present
    # and find_filesystem_root locked onto the rootfs.
    if result.extracted_path != str(output_base / "extracted"):
        # fs_root path (not the fallback) — detect_architecture ran.
        # The fake "ELF" we wrote is too small to parse, so architecture
        # may legitimately be None — just assert the field is the
        # documented type (str | None), not that detection succeeded.
        assert result.architecture is None or isinstance(result.architecture, str)
