"""Phase 2 handler 2 contract tests: :func:`unpack_wim`.

Covers the failure modes (binary missing, info failure, apply non-
zero exit, apply timeout, apply success with / without a Unix-style
fs_root) plus a Rule #35b live canary that builds a real WIM with
wimlib-imagex itself and extracts it back through the full
subprocess path.

The strategy-table assertion lives in test_extraction_pipeline.py
(``test_wim_archive_routes_to_unpack_wim``) so the lockstep between
the worker module and the registry is enforced from the dispatch
side.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_wim import (
    _DEFAULT_IMAGE_INDEX,
    _WIMLIB_TIMEOUT_SECONDS,
    unpack_wim,
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


def _make_two_phase_subprocess(
    info_proc: object,
    apply_factory,
):
    """Side-effect for create_subprocess_exec that returns info_proc on the
    first call (the ``wimlib-imagex info`` invocation) and the result of
    ``apply_factory(*args, **kwargs)`` on every subsequent call.

    Mirrors the worker's two-step "info then apply" subprocess
    invocation. ``apply_factory`` lets the caller plant a fake
    extraction tree just before returning the apply proc.
    """
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return info_proc
        return apply_factory(*args, **kwargs)

    return _side_effect


# ---------------------------------------------------------------------------
# 1. wimlib-imagex binary missing → clear failure with install hint.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_reports_missing_wimlib_binary(tmp_path: Path):
    wim = tmp_path / "fake.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "wimlib-imagex binary missing" in result.error
    # The unpack_log must carry the install hint so operators can act.
    assert "wimtools" in result.unpack_log
    assert "rebuild" in result.unpack_log.lower()


# ---------------------------------------------------------------------------
# 2. wimlib-imagex info fails → result.error names "WIM archive unreadable".
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_reports_unreadable_archive(tmp_path: Path):
    wim = tmp_path / "broken.wim"
    wim.write_bytes(b"\x00" * 1024)

    info_stub = _make_proc_stub(
        returncode=1,
        stderr=b"ERROR: bad magic / corrupt header\n",
    )

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(return_value=info_stub),
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "WIM archive unreadable" in result.error
    # The forensic log must include the info exit code header.
    assert "wimlib-imagex info exit=1" in result.unpack_log
    assert "bad magic" in result.unpack_log


# ---------------------------------------------------------------------------
# 3. info OK + apply timeout → result.error names the timeout ceiling.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_reports_apply_timeout(tmp_path: Path):
    wim = tmp_path / "huge.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 1\n",
    )
    apply_stub = _make_proc_stub(returncode=0)

    # First wait_for is on info (must succeed). Second is on apply (raise
    # TimeoutError to simulate a stuck apply). Track the call ordinal.
    state = {"calls": 0}

    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        state["calls"] += 1
        if state["calls"] == 1:
            # Info — let it succeed.
            return await real_wait_for(coro, timeout=timeout)
        # Apply — raise.
        # Coro must still be awaited to avoid "coroutine was never awaited"
        # warnings; but we want to surface the TimeoutError instead.
        coro.close()
        raise asyncio.TimeoutError

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, lambda *_a, **_kw: apply_stub,
        )),
    ), patch(
        "app.workers.unpack_wim.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_WIMLIB_TIMEOUT_SECONDS}s" in result.error
    assert "apply" in result.error


# ---------------------------------------------------------------------------
# 4. info OK + apply non-zero exit → failure with truncated stderr.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_reports_apply_nonzero_exit(tmp_path: Path):
    wim = tmp_path / "broken-payload.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 1\n",
    )
    apply_stub = _make_proc_stub(
        returncode=2,
        stderr=b"ERROR: Failed to extract image: corrupt resource\n",
    )

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, lambda *_a, **_kw: apply_stub,
        )),
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "exit=2" in result.error
    assert "corrupt resource" in result.error
    # The full log must also include the exit code header for forensics.
    assert "wimlib-imagex apply exit=2" in result.unpack_log


# ---------------------------------------------------------------------------
# 5. info OK + apply OK + Unix-style fs_root present → success with
#    extracted_path pointing at the rootfs.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_finds_unix_filesystem_root(tmp_path: Path):
    wim = tmp_path / "linux_recovery.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 2\nIndex: 1\nIndex: 2\n",
    )

    def _populate_then_stub(*_a, **_kw):
        # Plant a Linux marker tree so find_filesystem_root locks on.
        for sub in ("etc", "usr", "bin", "lib"):
            os.makedirs(extraction_dir / sub, exist_ok=True)
        (extraction_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        (extraction_dir / "etc" / "passwd").write_text("root:x:0:0::/root:/bin/sh\n")
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate_then_stub,
        )),
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    assert os.path.isdir(os.path.join(result.extracted_path, "etc"))
    assert "WIM extraction complete via wimlib-imagex" in result.unpack_log
    # The image-list output from `info` must land in the log so the
    # operator knows what other indices were available.
    assert "Image Count: 2" in result.unpack_log


# ---------------------------------------------------------------------------
# 6. info OK + apply OK + Windows-style layout (no Unix fs_root) →
#    success with extracted_path falling back to the extraction dir.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_no_unix_fs_root_still_success(tmp_path: Path):
    wim = tmp_path / "windows_install.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 1\n",
    )

    def _populate_windows_layout(*_a, **_kw):
        # Windows install.wim style: Windows/ + Program Files/ — no Linux markers.
        os.makedirs(extraction_dir / "Windows" / "System32", exist_ok=True)
        os.makedirs(extraction_dir / "Program Files", exist_ok=True)
        (extraction_dir / "Windows" / "System32" / "cmd.exe").write_bytes(
            b"\x4d\x5a" + b"\x00" * 100,  # MZ
        )
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate_windows_layout,
        )),
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    # Architecture detection on a Windows-only tree returns None
    # (the fake MZ binary is too small to parse, and no ELFs are
    # present). Just assert the field is the documented type.
    assert result.architecture is None or isinstance(result.architecture, str)


# ---------------------------------------------------------------------------
# 7. find_filesystem_root returns None → else-branch fallback message
#    and extracted_path = extraction_dir.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_falls_back_when_no_filesystem_root(tmp_path: Path):
    """When find_filesystem_root returns None (vendor archive with no
    recognisable root layout), the worker still reports success and
    falls back extracted_path = extraction_dir + emits the explanatory
    log.
    """
    wim = tmp_path / "vendor.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 1\n",
    )

    def _populate(*_a, **_kw):
        (extraction_dir / "vendor.bin").write_bytes(b"\x00" * 1024)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate,
        )),
    ), patch(
        "app.workers.unpack_wim.find_filesystem_root",
        return_value=None,
    ):
        result = await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert result.extracted_path == str(extraction_dir)
    assert "no Unix-style filesystem root" in result.unpack_log


# ---------------------------------------------------------------------------
# 8. Progress-callback contract — worker reports milestones and ends at 100.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_invokes_progress_callback(tmp_path: Path):
    wim = tmp_path / "small.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 1\n",
    )

    def _populate(*_a, **_kw):
        (extraction_dir / "etc").mkdir(exist_ok=True)
        (extraction_dir / "usr").mkdir(exist_ok=True)
        (extraction_dir / "bin").mkdir(exist_ok=True)
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _populate,
        )),
    ):
        await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    # Last call must be the 100% sentinel so the upstream router
    # transitions the firmware row out of the unpacking stage.
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 9. Default image index — worker invokes apply with image "1" by default.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_uses_default_image_index_one(tmp_path: Path):
    """Mechanical check: the apply subprocess receives the image-index
    positional argument set to ``_DEFAULT_IMAGE_INDEX``. Documents the
    implicit "always image 1" contract; if a future change adds an
    image-index parameter, this test catches the silent default change.
    """
    wim = tmp_path / "multi.wim"
    wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    info_stub = _make_proc_stub(
        returncode=0,
        stdout=b"WIM Information:\nImage Count: 3\n",
    )

    captured_args: list[tuple] = []

    def _capture_then_stub(*args, **_kw):
        captured_args.append(args)
        (extraction_dir / "etc").mkdir(exist_ok=True)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_wim.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            info_stub, _capture_then_stub,
        )),
    ):
        await unpack_wim(
            firmware_path=str(wim),
            output_base_dir=str(tmp_path),
        )

    # Apply args: ("wimlib-imagex", "apply", <wim>, "<index>", <dir>, "--unix-data", ...)
    assert len(captured_args) == 1
    apply_args = captured_args[0]
    assert apply_args[0] == "wimlib-imagex"
    assert apply_args[1] == "apply"
    assert apply_args[2] == str(wim)
    assert apply_args[3] == _DEFAULT_IMAGE_INDEX == "1"


# ---------------------------------------------------------------------------
# 10. Rule #35b live canary — build a real WIM with wimlib-imagex itself
#     and extract it through the full subprocess path.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_wim_live_canary_real_wim(tmp_path: Path):
    """Build a real WIM and extract it through the actual wimlib-imagex CLI.

    Rule #35b live canary — mocks confirm the contract we wrote, this
    test confirms the contract wimlib-imagex actually has. If a future
    container update changes wimlib-imagex's exit semantics or the
    `apply` argument shape, this canary catches it before production
    traffic does.
    """
    if not shutil.which("wimlib-imagex"):
        pytest.skip("wimlib-imagex not on PATH (run via container)")

    src_tree = tmp_path / "wim_src"
    (src_tree / "Windows" / "System32").mkdir(parents=True)
    (src_tree / "Windows" / "System32" / "cmd.exe").write_bytes(
        b"\x4d\x5a" + b"\x00" * 100,
    )
    (src_tree / "Windows" / "System32" / "kernel32.dll").write_bytes(
        b"\x4d\x5a" + b"\x00" * 200,
    )
    (src_tree / "Users").mkdir()
    (src_tree / "Users" / "default.txt").write_text("default user profile\n")

    wim_path = tmp_path / "canary.wim"
    proc = subprocess.run(
        [
            "wimlib-imagex", "capture",
            str(src_tree),
            str(wim_path),
            "canary-image",
            "--compress=none",  # fastest path; we're not testing compression
        ],
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0 or not wim_path.exists():
        pytest.skip(
            f"wimlib-imagex capture failed (rc={proc.returncode}): "
            f"{proc.stderr.decode(errors='replace')[:200]}",
        )

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_wim(
        firmware_path=str(wim_path),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None

    # Value-flow check: every file we put in the source tree must land in
    # the extraction tree.
    extract_root = result.extraction_dir or result.extracted_path
    found_files: set[str] = set()
    for root, _dirs, files in os.walk(extract_root):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), extract_root)
            # Normalise path separators for cross-platform comparison.
            found_files.add(rel.replace(os.sep, "/"))

    expected = (
        "Windows/System32/cmd.exe",
        "Windows/System32/kernel32.dll",
        "Users/default.txt",
    )
    for expected_rel in expected:
        assert expected_rel in found_files, (
            f"missing {expected_rel} in extracted tree; "
            f"have: {sorted(found_files)[:20]}"
        )

    # The image-list output from wimlib-imagex info must land in the log.
    assert "wimlib-imagex info exit=0" in result.unpack_log
    assert "wimlib-imagex apply exit=0" in result.unpack_log
    assert "WIM extraction complete via wimlib-imagex (image 1)" in result.unpack_log
