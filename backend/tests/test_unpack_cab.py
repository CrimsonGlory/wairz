"""Phase α handler 1 contract tests: :func:`unpack_cab`.

Covers the failure modes (binary missing, list failure, extract non-
zero exit, extract timeout, success with / without a Unix-style
fs_root) plus a Rule #35b live canary that builds a real CAB with
``gcab`` and extracts it back through the full subprocess path.

The strategy-table assertion lives in
``test_extraction_pipeline.py`` (``test_windows_cab_routes_to_unpack_cab``)
so the lockstep between the worker module and the registry is enforced
from the dispatch side (Phase α.3 commit).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_cab import (
    _CABEXTRACT_TIMEOUT_SECONDS,
    unpack_cab,
)

# ---------------------------------------------------------------------------
# Helpers (mirror test_unpack_wim.py)
# ---------------------------------------------------------------------------


def _make_proc_stub(returncode: int, stdout: bytes = b"", stderr: bytes = b"") -> object:
    """Build an awaitable subprocess stub for asyncio.create_subprocess_exec.

    Mimics the surface the worker actually uses: ``await proc.communicate()``
    returning ``(stdout, stderr)``, plus ``proc.returncode`` and ``proc.kill()``.
    """
    class _Proc:
        def __init__(self) -> None:
            self.returncode = returncode

        async def communicate(self) -> tuple[bytes, bytes]:
            return stdout, stderr

        def kill(self) -> None:
            pass

    return _Proc()


def _make_two_phase_subprocess(list_proc: object, extract_factory):
    """Side-effect for create_subprocess_exec returning list_proc on the
    first call (the ``cabextract --list`` invocation) and the result of
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
# 1. cabextract binary missing → clear failure with install hint.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_reports_missing_binary(tmp_path: Path):
    cab = tmp_path / "fake.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 64)

    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "cabextract binary missing" in result.error
    # The unpack_log must carry the install hint so operators can act.
    assert "cabextract" in result.unpack_log
    assert "rebuild" in result.unpack_log.lower()


# ---------------------------------------------------------------------------
# 2. cabextract --list fails → result.error names "CAB archive unreadable".
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_reports_unreadable_archive(tmp_path: Path):
    cab = tmp_path / "broken.cab"
    cab.write_bytes(b"\x00" * 64)

    list_stub = _make_proc_stub(
        returncode=1,
        stderr=b"corrupted CAB header / not a valid cabinet\n",
    )

    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ):
        result = await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "CAB archive unreadable" in result.error
    assert "cabextract --list exit=1" in result.unpack_log
    assert "corrupted" in result.unpack_log


# ---------------------------------------------------------------------------
# 3. list OK + extract timeout → result.error names the timeout ceiling.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_reports_extract_timeout(tmp_path: Path):
    cab = tmp_path / "huge.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 64)

    list_stub = _make_proc_stub(returncode=0, stdout=b"big.dat\n")
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
        raise TimeoutError

    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ), patch(
        "app.workers.unpack_cab.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert f"timed out after {_CABEXTRACT_TIMEOUT_SECONDS}s" in result.error


# ---------------------------------------------------------------------------
# 4. list OK + extract non-zero exit → failure with truncated stderr.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_reports_extract_nonzero_exit(tmp_path: Path):
    cab = tmp_path / "bad-payload.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 64)

    list_stub = _make_proc_stub(returncode=0, stdout=b"vendor.dll\nvendor.sys\n")
    extract_stub = _make_proc_stub(
        returncode=1,
        stderr=b"failed to extract: corrupt LZX block\n",
    )

    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ):
        result = await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert result.error is not None
    assert "exit=1" in result.error
    assert "corrupt LZX" in result.error
    assert "cabextract exit=1" in result.unpack_log


# ---------------------------------------------------------------------------
# 5. list OK + extract OK + flat Windows-style payload → success with
#    extracted_path = extraction_dir + the explanatory log message.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_succeeds_with_flat_payload(tmp_path: Path):
    cab = tmp_path / "drv.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"vendor.sys\nvendor.inf\nvendor.cat\n",
    )

    def _populate(*_a, **_kw):
        # Flat driver-package payload (typical CAB shape).
        (extraction_dir / "vendor.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        (extraction_dir / "vendor.inf").write_text(
            "[Version]\nSignature=\"$Windows NT$\"\nClass=Net\n"
        )
        (extraction_dir / "vendor.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        result = await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    assert result.extraction_dir == str(extraction_dir)
    assert "CAB extraction complete via cabextract" in result.unpack_log
    # The list output must land in the log so the operator knows what
    # was advertised in the CAB index vs what actually extracted.
    assert "vendor.sys" in result.unpack_log
    # The extracted files must actually exist on disk.
    assert (extraction_dir / "vendor.sys").exists()
    assert (extraction_dir / "vendor.inf").exists()
    assert (extraction_dir / "vendor.cat").exists()


# ---------------------------------------------------------------------------
# 6. Progress-callback contract — worker reports milestones and ends at 100.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_invokes_progress_callback(tmp_path: Path):
    cab = tmp_path / "small.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(returncode=0, stdout=b"a.txt\n")

    def _populate(*_a, **_kw):
        (extraction_dir / "a.txt").write_text("hi\n")
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_cab.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        await unpack_cab(
            firmware_path=str(cab),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 7. Rule #35b live canary — build a real CAB with gcab and extract
#    it through the actual cabextract CLI.
#
# Skipped when gcab is not on PATH (typical on a fresh dev box; the
# container ships gcab as part of the `glib2.0-bin` apt block in Phase
# α.6 — until that lands, the canary auto-skips).
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unpack_cab_live_canary_real_cab(tmp_path: Path):
    """Build a real CAB and extract it through the actual cabextract CLI.

    Rule #35b live canary — mocks confirm the contract we wrote, this
    test confirms the contract cabextract actually has. Value-flow check:
    every file we put in the source tree must land in the extraction tree.
    """
    if not shutil.which("cabextract"):
        pytest.skip("cabextract not on PATH (run via container)")
    if not shutil.which("gcab"):
        pytest.skip("gcab not on PATH — cannot synthesise a test CAB")

    src_tree = tmp_path / "cab_src"
    src_tree.mkdir()
    (src_tree / "vendor.inf").write_text(
        "[Version]\nSignature=\"$Windows NT$\"\nClass=Net\n"
    )
    (src_tree / "vendor.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 200)
    (src_tree / "vendor.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)

    cab_path = tmp_path / "canary.cab"
    proc = subprocess.run(
        ["gcab", "--create", str(cab_path),
         "vendor.inf", "vendor.sys", "vendor.cat"],
        cwd=str(src_tree),
        capture_output=True,
        timeout=60,
    )
    if proc.returncode != 0 or not cab_path.exists():
        pytest.skip(
            f"gcab create failed (rc={proc.returncode}): "
            f"{proc.stderr.decode(errors='replace')[:200]}",
        )

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_cab(
        firmware_path=str(cab_path),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    extract_root = result.extraction_dir or result.extracted_path

    # Value-flow check: every file we put in the source tree must land
    # in the extraction tree.
    found_files: set[str] = set()
    for root, _dirs, files in os.walk(extract_root):
        for name in files:
            rel = os.path.relpath(os.path.join(root, name), extract_root)
            found_files.add(rel.replace(os.sep, "/"))

    expected = ("vendor.inf", "vendor.sys", "vendor.cat")
    for expected_rel in expected:
        assert expected_rel in found_files, (
            f"missing {expected_rel} in extracted tree; "
            f"have: {sorted(found_files)[:20]}"
        )

    # The list output from cabextract --list must land in the log.
    assert "cabextract --list exit=0" in result.unpack_log
    assert "cabextract exit=0" in result.unpack_log
    assert "CAB extraction complete via cabextract" in result.unpack_log
