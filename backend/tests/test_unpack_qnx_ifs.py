"""Phase 2 handler 5 contract tests: :func:`unpack_qnx_ifs`.

Covers the soft-fail discipline (binary missing, list timeout, list
non-zero exit, extract timeout, extract non-zero exit) plus the
success path and the live canary skip-on-no-corpus marker.

The strategy-table assertion lives in test_extraction_pipeline.py
(``test_qnx_ifs_routes_to_unpack_qnx_ifs``) so the lockstep between
the worker module and the registry is enforced from the dispatch
side.

Per Rule #30 the subprocess patch target is the worker module's
``asyncio.create_subprocess_exec`` binding (asyncio is imported at
module scope, so the rebind on the worker module IS load-bearing —
matches the unpack_wim test pattern).
"""
from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_qnx_ifs import (
    _IFSDUMP_EXTRACT_TIMEOUT_SECONDS,
    _IFSDUMP_LIST_TIMEOUT_SECONDS,
    unpack_qnx_ifs,
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
    list_proc: object,
    extract_factory,
):
    """Side-effect for create_subprocess_exec that returns list_proc on the
    first call (the ``ifsdump --list`` invocation) and the result of
    ``extract_factory(*args, **kwargs)`` on every subsequent call.

    Mirrors the worker's two-step "list then extract" subprocess
    invocation. ``extract_factory`` lets the caller plant a fake
    extraction tree just before returning the extract proc.
    """
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return list_proc
        return extract_factory(*args, **kwargs)

    return _side_effect


# ---------------------------------------------------------------------------
# 1. ifsdump binary missing → soft-fail with workaround pointer.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_reports_missing_ifsdump_binary(tmp_path: Path):
    ifs = tmp_path / "fake.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "ifsdump binary not available" in result.error
    # The workaround pointer must surface — operators need it for
    # IFS variants ifsdump can't crack (HBCIFS, vendor extensions).
    assert "QNX SDP" in result.unpack_log
    assert "dumpifs" in result.unpack_log


# ---------------------------------------------------------------------------
# 2. ifsdump --list non-zero exit → soft-fail with truncated stderr +
#    workaround pointer.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_reports_unreadable_archive(tmp_path: Path):
    ifs = tmp_path / "broken.ifs"
    ifs.write_bytes(b"\x00" * 1024)

    list_stub = _make_proc_stub(
        returncode=2,
        stderr=b"ERROR: invalid IFS magic / unsupported version\n",
    )

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "list phase exit=2" in result.error
    # Forensic log must include the exit code header + stderr.
    assert "ifsdump --list exit=2" in result.unpack_log
    assert "invalid IFS magic" in result.unpack_log
    # Workaround pointer must surface even on list-phase failures.
    assert "QNX SDP" in result.unpack_log


# ---------------------------------------------------------------------------
# 3. ifsdump --list timeout → soft-fail naming the timeout ceiling.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_reports_list_timeout(tmp_path: Path):
    ifs = tmp_path / "stuck.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    list_stub = _make_proc_stub(returncode=0)

    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        # First wait_for is on list — raise to simulate a stuck listing.
        coro.close()
        raise asyncio.TimeoutError

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ), patch(
        "app.workers.unpack_qnx_ifs.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    # Suppress unused-warning on real_wait_for — kept for parity with the
    # unpack_wim test shape so future test additions can flip it on.
    _ = real_wait_for

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_IFSDUMP_LIST_TIMEOUT_SECONDS}s" in result.error
    assert "--list" in result.error
    assert "QNX SDP" in result.unpack_log


# ---------------------------------------------------------------------------
# 4. ifsdump --extract timeout → soft-fail naming the extract timeout.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_reports_extract_timeout(tmp_path: Path):
    ifs = tmp_path / "huge.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"file inventory:\nfile1\nfile2\n",
    )
    extract_stub = _make_proc_stub(returncode=0)

    state = {"calls": 0}
    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        state["calls"] += 1
        if state["calls"] == 1:
            # List — let it succeed.
            return await real_wait_for(coro, timeout=timeout)
        # Extract — raise.
        coro.close()
        raise asyncio.TimeoutError

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ), patch(
        "app.workers.unpack_qnx_ifs.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_IFSDUMP_EXTRACT_TIMEOUT_SECONDS}s" in result.error
    assert "--extract" in result.error
    assert "QNX SDP" in result.unpack_log


# ---------------------------------------------------------------------------
# 5. list OK + extract non-zero → soft-fail with workaround pointer.
#    Value-flow gate per Rule #35b — ensures the worker DEGRADES to a
#    no_handler-shaped failure rather than half-extracting.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_reports_extract_nonzero_exit(tmp_path: Path):
    ifs = tmp_path / "broken-payload.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"file inventory:\nfile1\n",
    )
    extract_stub = _make_proc_stub(
        returncode=2,
        stderr=b"ERROR: corrupt LZO block at offset 0x1000\n",
    )

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "extract phase exit=2" in result.error
    assert "corrupt LZO block" in result.error
    # Forensic log must include the exit code header for both phases.
    assert "ifsdump --list exit=0" in result.unpack_log
    assert "ifsdump --extract exit=2" in result.unpack_log
    # Workaround pointer surfaces — this is the value-flow contract
    # that distinguishes a soft-fail from a half-extracted state.
    assert "QNX SDP" in result.unpack_log
    assert "dumpifs" in result.unpack_log


# ---------------------------------------------------------------------------
# 6. Success path: list OK + extract OK → success=True, file count
#    populated, unpack_log captures listing AND the PARTIAL capability
#    note.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_success_path(tmp_path: Path):
    ifs = tmp_path / "embedded_qnx.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=(
            b"file inventory:\n"
            b"  /etc/passwd\n"
            b"  /usr/bin/sh\n"
            b"  /lib/libc.so\n"
        ),
    )

    def _populate_then_stub(*_a, **_kw):
        # Plant a Linux-style marker tree so find_filesystem_root locks on.
        # QNX embedded firmware often carries this layout.
        for sub in ("etc", "usr", "bin", "lib"):
            os.makedirs(extraction_dir / sub, exist_ok=True)
        (extraction_dir / "etc" / "passwd").write_text(
            "root:x:0:0::/root:/bin/sh\n",
        )
        (extraction_dir / "etc" / "hosts").write_text("127.0.0.1 localhost\n")
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate_then_stub,
        )),
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    assert os.path.isdir(os.path.join(result.extracted_path, "etc"))
    assert "QNX IFS extraction complete via ifsdump" in result.unpack_log
    # The list output from ifsdump --list must land in the log so the
    # operator sees the file inventory.
    assert "file inventory" in result.unpack_log
    assert "/etc/passwd" in result.unpack_log
    # The PARTIAL capability note is appended to successful extractions
    # so operators see the caveat alongside the success message.
    assert "Capability note:" in result.unpack_log
    assert "Listing-only" in result.unpack_log


# ---------------------------------------------------------------------------
# 7. Success with no Unix-style fs_root → still success=True,
#    extracted_path falls back to the extraction_dir, log carries the
#    fallback note.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_no_unix_fs_root_still_success(tmp_path: Path):
    ifs = tmp_path / "vendor_automotive.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"file inventory:\n  /vendor/proprietary.bin\n",
    )

    def _populate_vendor_layout(*_a, **_kw):
        # No Unix markers — vendor automotive layout (proprietary
        # partition names, no etc/usr/bin).
        (extraction_dir / "vendor").mkdir(exist_ok=True)
        (extraction_dir / "vendor" / "proprietary.bin").write_bytes(
            b"\x00" * 256,
        )
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate_vendor_layout,
        )),
    ), patch(
        "app.workers.unpack_qnx_ifs.find_filesystem_root",
        return_value=None,
    ):
        result = await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert result.extracted_path == str(extraction_dir)
    assert "no Unix-style filesystem root" in result.unpack_log
    assert "vendor-specific layouts" in result.unpack_log


# ---------------------------------------------------------------------------
# 8. Progress-callback contract — worker reports milestones and ends at 100.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_invokes_progress_callback(tmp_path: Path):
    ifs = tmp_path / "small.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"file inventory:\nfile1\n",
    )

    def _populate(*_a, **_kw):
        (extraction_dir / "etc").mkdir(exist_ok=True)
        (extraction_dir / "usr").mkdir(exist_ok=True)
        (extraction_dir / "bin").mkdir(exist_ok=True)
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    # Last call must be the 100% sentinel so the upstream router
    # transitions the firmware row out of the unpacking stage.
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 9. Default flag-shape contract: ifsdump receives "--list" then
#    "-d <dir> --extract <ifs>" — locks the verified upstream CLI.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_qnx_ifs_uses_verified_cli_flags(tmp_path: Path):
    """Mechanical check: subprocess call args match the upstream
    jtang613/qnx_dumpers README. If a future ifsdump release renames a
    flag, this test catches the breakage before production traffic does
    (companion to Rule #6 — verify flags before hardcoding).
    """
    ifs = tmp_path / "flag-check.ifs"
    ifs.write_bytes(b"\xeb\x7e\xff\x7e" + b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"file inventory:\nfile1\n",
    )

    captured: list[tuple] = []

    def _capture_then_stub(*args, **_kw):
        captured.append(args)
        (extraction_dir / "etc").mkdir(exist_ok=True)
        return _make_proc_stub(returncode=0)

    captured_list_args: list[tuple] = []

    def _capture_list_too(*args, **kwargs):
        captured_list_args.append(args)
        # Emulate the original two-phase side-effect: first call
        # returns list_stub, subsequent return _capture_then_stub
        # output.
        if len(captured_list_args) == 1:
            return list_stub
        return _capture_then_stub(*args, **kwargs)

    with patch(
        "app.workers.unpack_qnx_ifs.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_capture_list_too),
    ):
        await unpack_qnx_ifs(
            firmware_path=str(ifs),
            output_base_dir=str(tmp_path),
        )

    # Expect 2 subprocess calls: list then extract.
    assert len(captured_list_args) == 2

    # List args: ("ifsdump", "--list", <ifs_path>)
    list_args = captured_list_args[0]
    assert list_args[0] == "ifsdump"
    assert list_args[1] == "--list"
    assert list_args[2] == str(ifs)

    # Extract args: ("ifsdump", "-d", <dir>, "--extract", <ifs_path>)
    extract_args = captured_list_args[1]
    assert extract_args[0] == "ifsdump"
    assert "-d" in extract_args
    assert "--extract" in extract_args
    # The extraction directory and ifs path must both be passed.
    assert any(a == str(extraction_dir) for a in extract_args)
    assert any(a == str(ifs) for a in extract_args)


# ---------------------------------------------------------------------------
# 10. Rule #35b live canary — SKIPPED (no public QNX IFS test corpus
#     available at handler-ship time). Tracked in
#     .planning/intake/qnx-ifs-test-corpus-2026-05-07.md.
# ---------------------------------------------------------------------------

@pytest.mark.skip(
    reason=(
        "No QNX IFS test corpus available at Phase 2 handler 5 ship "
        "time. See .planning/intake/qnx-ifs-test-corpus-2026-05-07.md "
        "for sourcing notes (BMW HU NBT EVO, Audi MMI, public test "
        "images, OpenQNX archives, automotive ECU dumps)."
    ),
)
def test_unpack_qnx_ifs_live_canary_real_ifs():
    """Build / source a real QNX .ifs and round-trip through the actual
    ifsdump CLI.

    Rule #35b live canary — mocks confirm the contract we wrote, this
    test confirms the contract ifsdump actually has. Skipped until a
    fixture .ifs lands at backend/tests/fixtures/qnx_ifs/. When
    enabled, this test should:

      1. Read backend/tests/fixtures/qnx_ifs/sample.ifs (skip if missing).
      2. Call unpack_qnx_ifs(firmware_path, output_base_dir).
      3. Assert result.success is True.
      4. Walk result.extracted_path / result.extraction_dir; assert
         the expected files for that fixture exist.
      5. Assert "ifsdump --list exit=0" + "ifsdump --extract exit=0"
         in result.unpack_log.

    Mirrors the test_unpack_wim_live_canary_real_wim shape but builds
    from a fixture rather than capture-then-extract because no
    ``ifscapture`` tool exists for round-trip verification.
    """
