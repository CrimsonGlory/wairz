"""Phase α handler 4 contract tests: :func:`unpack_msu`.

MSU is a CAB-of-CABs: outer + 1-3 inner CABs + optional PSF deltas.
The contract tests exercise the recursion logic — the worker must
walk the extraction tree for inner *.cab files and recurse one level.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_msu import (
    _MSU_OUTER_TIMEOUT_SECONDS,
    unpack_msu,
)


def _make_proc_stub(returncode, stdout=b"", stderr=b""):
    class _Proc:
        def __init__(self):
            self.returncode = returncode

        async def communicate(self):
            return stdout, stderr

        def kill(self):
            pass

    return _Proc()


# Helper: build a side-effect that returns a sequence of proc stubs in order.
# Each stub corresponds to one cabextract subprocess call; the side-effect
# also runs an optional callback (for populating extracted files).
def _make_sequenced_subprocess(
    procs_with_populators: list[tuple[object, callable]],
):
    """Return a side_effect that yields the i-th stub for the i-th call.

    Each tuple is ``(proc_stub, populate_fn)`` — populate_fn is called
    with the subprocess args BEFORE returning the proc, so the test can
    plant extracted files at the correct path.
    """
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        idx = state["calls"]
        state["calls"] += 1
        if idx >= len(procs_with_populators):
            raise AssertionError(
                f"unexpected subprocess call #{idx}: {args}"
            )
        proc, populator = procs_with_populators[idx]
        if populator is not None:
            populator(args, kwargs)
        return proc

    return _side_effect


@pytest.mark.asyncio
async def test_unpack_msu_reports_missing_cabextract(tmp_path: Path):
    msu = tmp_path / "fake.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "cabextract binary missing" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_msu_reports_outer_failure(tmp_path: Path):
    msu = tmp_path / "broken.msu"
    msu.write_bytes(b"\x00" * 64)

    outer_stub = _make_proc_stub(
        returncode=1,
        stderr=b"outer CAB header corrupt\n",
    )

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(return_value=outer_stub),
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "outer CAB extraction failed" in (result.error or "")
    assert "exit=1" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_msu_reports_outer_timeout(tmp_path: Path):
    msu = tmp_path / "huge.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)

    outer_stub = _make_proc_stub(returncode=0)

    state = {"calls": 0}

    async def _selective_wait_for(coro, timeout=None):  # noqa: ASYNC109 — test helper: monkeypatched asyncio.wait_for signature must mirror upstream timeout= param
        state["calls"] += 1
        coro.close()
        raise TimeoutError

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(return_value=outer_stub),
    ), patch(
        "app.workers.unpack_msu.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert f"outer cabextract timed out after {_MSU_OUTER_TIMEOUT_SECONDS}s" in (
        result.error or ""
    )


@pytest.mark.asyncio
async def test_unpack_msu_recurses_inner_cabs(tmp_path: Path):
    """The recursion contract: outer CAB extracts → walker finds 2 inner
    CABs → recurses each → reports both as extracted in the log.
    """
    msu = tmp_path / "windows10.0-kb1234.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    outer_stub = _make_proc_stub(returncode=0, stdout=b"outer files\n")
    inner1_stub = _make_proc_stub(returncode=0, stdout=b"inner1 files\n")
    inner2_stub = _make_proc_stub(returncode=0, stdout=b"inner2 files\n")

    def _populate_outer(args, _kwargs):
        # outer cabextract args: ("cabextract", "-d", extraction_dir, "-F", "*", msu)
        # Plant 2 inner CABs + an XML metadata file.
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "Windows10.0-KB1234.cab").write_bytes(b"MSCF" + b"\x00" * 64)
        (extraction_dir / "WSUSSCAN.cab").write_bytes(b"MSCF" + b"\x00" * 64)
        (extraction_dir / "Windows10.0-KB1234.xml").write_text(
            '<?xml version="1.0" ?>\n<assembly />\n'
        )

    def _populate_inner(args, _kwargs):
        # Order-robust: dispatch on source CAB name (args[5] in
        # ['cabextract', '-d', dest, '-F', '*', src_cab]). The walker
        # sorts inner CABs alphabetically (WSUSSCAN.cab before
        # Windows10.0-KB1234.cab because uppercase 'S' < lowercase 'i').
        src_cab = args[5]
        dest_dir = args[2]
        os.makedirs(dest_dir, exist_ok=True)
        if "KB1234" in src_cab:
            (Path(dest_dir) / "kernel32.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
            (Path(dest_dir) / "tcpip.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        elif "WSUSSCAN" in src_cab:
            (Path(dest_dir) / "package.xml").write_text("<package />\n")

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_sequenced_subprocess([
            (outer_stub, _populate_outer),
            (inner1_stub, _populate_inner),
            (inner2_stub, _populate_inner),
        ])),
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert "Inner CAB extraction: 2/2 succeeded" in result.unpack_log
    assert "Windows10.0-KB1234.cab" in result.unpack_log
    assert "WSUSSCAN.cab" in result.unpack_log
    # The recursed payloads must actually exist on disk.
    inner1_dir = extraction_dir / "Windows10.0-KB1234.cab_extracted"
    inner2_dir = extraction_dir / "WSUSSCAN.cab_extracted"
    assert (inner1_dir / "kernel32.dll").exists()
    assert (inner1_dir / "tcpip.sys").exists()
    assert (inner2_dir / "package.xml").exists()


@pytest.mark.asyncio
async def test_unpack_msu_reports_partial_inner_failure(tmp_path: Path):
    """An MSU where one inner CAB succeeds and another fails — overall
    success but log warns about the partial failure (typical: WSUSSCAN.cab
    metadata-only payloads sometimes fail clean while the main update CAB
    succeeds).
    """
    msu = tmp_path / "partial.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    outer_stub = _make_proc_stub(returncode=0)
    inner_ok_stub = _make_proc_stub(returncode=0)
    inner_fail_stub = _make_proc_stub(
        returncode=1, stderr=b"WSUSSCAN.cab: metadata-only, no extractable files\n",
    )

    def _populate_outer(_args, _kwargs):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "primary.cab").write_bytes(b"MSCF" + b"\x00" * 64)
        (extraction_dir / "WSUSSCAN.cab").write_bytes(b"MSCF" + b"\x00" * 64)

    def _populate_inner_ok(args, _kwargs):
        dest = args[2]
        os.makedirs(dest, exist_ok=True)
        (Path(dest) / "patched.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 50)

    def _populate_inner_fail(args, _kwargs):
        dest = args[2]
        os.makedirs(dest, exist_ok=True)

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_sequenced_subprocess([
            (outer_stub, _populate_outer),
            (inner_ok_stub, _populate_inner_ok),
            (inner_fail_stub, _populate_inner_fail),
        ])),
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True  # overall success despite inner failure
    assert "Inner CAB extraction: 1/2 succeeded" in result.unpack_log
    assert "WSUSSCAN.cab" in result.unpack_log
    assert "metadata-only" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msu_detects_psf_deltas(tmp_path: Path):
    """An MSU containing PSF Express-install deltas — the worker must
    detect, list, and surface a clear warning about gated extraction.
    """
    msu = tmp_path / "express.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    outer_stub = _make_proc_stub(returncode=0)

    def _populate_outer(_args, _kwargs):
        os.makedirs(extraction_dir, exist_ok=True)
        # No inner CABs — just PSF + metadata (Express updates can ship
        # without the full payload; PSF reconstructs from a baseline).
        (extraction_dir / "express.psf").write_bytes(b"PA30" + b"\x00" * 100)
        (extraction_dir / "express2.psf").write_bytes(b"PA30" + b"\x00" * 100)
        (extraction_dir / "update.xml").write_text("<assembly />\n")

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_sequenced_subprocess([
            (outer_stub, _populate_outer),
        ])),
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "PSF (Patch Storage File / Express install delta) detected" in result.unpack_log
    assert "2 file(s)" in result.unpack_log
    assert "INCLUDE_PSF=1" in result.unpack_log
    assert "express.psf" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msu_lists_metadata_files(tmp_path: Path):
    """An MSU's *.mum / *update.xml / *.cat files must be listed in the log
    so operators can locate them without re-walking the tree."""
    msu = tmp_path / "metadata.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    outer_stub = _make_proc_stub(returncode=0)

    def _populate_outer(_args, _kwargs):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "Windows10.0-KB.mum").write_text("<assembly />\n")
        (extraction_dir / "Windows10.0-KB.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)
        (extraction_dir / "package.xml").write_text("<package />\n")

    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_sequenced_subprocess([
            (outer_stub, _populate_outer),
        ])),
    ):
        result = await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "Update metadata files" in result.unpack_log
    assert "Windows10.0-KB.mum" in result.unpack_log
    assert "Windows10.0-KB.cat" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msu_invokes_progress_callback(tmp_path: Path):
    msu = tmp_path / "tiny.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    outer_stub = _make_proc_stub(returncode=0)

    def _populate(_args, _kwargs):
        os.makedirs(extraction_dir, exist_ok=True)
        (extraction_dir / "tiny.txt").write_text("hi\n")

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_msu.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_sequenced_subprocess([
            (outer_stub, _populate),
        ])),
    ):
        await unpack_msu(
            firmware_path=str(msu),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


@pytest.mark.asyncio
async def test_unpack_msu_live_canary_real_cab_recursion(tmp_path: Path):
    """Rule #35b live canary — synthesise a CAB-of-CAB shape using gcab
    if available. Auto-skip when gcab is missing.
    """
    import shutil as _shutil
    if not _shutil.which("cabextract"):
        pytest.skip("cabextract not on PATH (run via container)")
    if not _shutil.which("gcab"):
        pytest.skip("gcab not on PATH — Phase α.6 Dockerfile pending")

    # Build inner CAB first
    inner_src = tmp_path / "inner_src"
    inner_src.mkdir()
    (inner_src / "kernel32.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    (inner_src / "tcpip.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    inner_cab = tmp_path / "inner.cab"
    proc = subprocess.run(  # noqa: ASYNC221 — synthetic test-fixture build; sync CLI shell-out is intentional in test setup
        ["gcab", "--create", str(inner_cab), "kernel32.dll", "tcpip.sys"],
        cwd=str(inner_src),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.skip(f"gcab inner failed: {proc.stderr.decode()[:200]}")

    # Build outer MSU containing the inner CAB
    outer_src = tmp_path / "outer_src"
    outer_src.mkdir()
    _shutil.copy(inner_cab, outer_src / "inner.cab")
    (outer_src / "Windows10.0-KB.xml").write_text("<assembly />\n")
    msu = tmp_path / "canary.msu"
    proc = subprocess.run(  # noqa: ASYNC221 — synthetic test-fixture build; sync CLI shell-out is intentional in test setup
        ["gcab", "--create", str(msu), "inner.cab", "Windows10.0-KB.xml"],
        cwd=str(outer_src),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0:
        pytest.skip(f"gcab outer failed: {proc.stderr.decode()[:200]}")

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_msu(
        firmware_path=str(msu),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"got error={result.error!r}"
    extract_root = result.extraction_dir or result.extracted_path
    # Inner CAB recursion must have produced kernel32.dll/tcpip.sys.
    inner_dir = Path(extract_root) / "inner.cab_extracted"
    assert (inner_dir / "kernel32.dll").exists()
    assert (inner_dir / "tcpip.sys").exists()
    # Outer XML must also be present.
    assert (Path(extract_root) / "Windows10.0-KB.xml").exists()
    assert "Inner CAB extraction: 1/1 succeeded" in result.unpack_log
