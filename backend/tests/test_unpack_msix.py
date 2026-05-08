"""Phase α handler 3 contract tests: :func:`unpack_msix`."""
from __future__ import annotations

import asyncio
import os
import shutil
import zipfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_msix import (
    _SEVEN_ZIP_TIMEOUT_SECONDS,
    unpack_msix,
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


def _make_two_phase_subprocess(list_proc, extract_factory):
    state = {"calls": 0}

    def _side_effect(*args, **kwargs):
        state["calls"] += 1
        if state["calls"] == 1:
            return list_proc
        return extract_factory(*args, **kwargs)

    return _side_effect


# Minimal ZIP magic for fake fixtures used in mock tests.
_ZIP_MAGIC = b"PK\x03\x04"


@pytest.mark.asyncio
async def test_unpack_msix_reports_missing_7z(tmp_path: Path):
    msix = tmp_path / "fake.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "7z binary missing" in (result.error or "")
    assert "p7zip-full" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msix_reports_unreadable(tmp_path: Path):
    msix = tmp_path / "broken.msix"
    msix.write_bytes(b"\x00" * 64)

    list_stub = _make_proc_stub(returncode=2, stderr=b"Cannot open archive\n")
    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "MSIX archive unreadable" in (result.error or "")
    assert "Cannot open archive" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msix_rejects_non_msix_zip(tmp_path: Path):
    """A ZIP without AppxManifest.xml / AppxBundleManifest.xml is not MSIX —
    surfaces a clear error before paying extraction cost."""
    zipped = tmp_path / "plain.zip"
    zipped.write_bytes(_ZIP_MAGIC + b"\x00" * 64)

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"plain.txt\nreadme.md\n",  # no AppxManifest.xml signal
    )

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ):
        result = await unpack_msix(
            firmware_path=str(zipped),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "Not an MSIX/AppX package" in (result.error or "")
    assert "AppxManifest.xml" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_msix_reports_extract_timeout(tmp_path: Path):
    msix = tmp_path / "huge.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"AppxManifest.xml\nAppxBlockMap.xml\nbig.dat\n",
    )
    extract_stub = _make_proc_stub(returncode=0)

    state = {"calls": 0}
    real_wait_for = asyncio.wait_for

    async def _selective_wait_for(coro, timeout=None):
        state["calls"] += 1
        if state["calls"] == 1:
            return await real_wait_for(coro, timeout=timeout)
        coro.close()
        raise asyncio.TimeoutError

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ), patch(
        "app.workers.unpack_msix.asyncio.wait_for",
        side_effect=_selective_wait_for,
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert f"timed out after {_SEVEN_ZIP_TIMEOUT_SECONDS}s" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_msix_reports_extract_failure(tmp_path: Path):
    msix = tmp_path / "bad.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"AppxManifest.xml\nAppxBlockMap.xml\n",
    )
    extract_stub = _make_proc_stub(
        returncode=2,
        stderr=b"7z: extraction failed: corrupt entry\n",
    )

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, lambda *_a, **_kw: extract_stub,
        )),
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is False
    assert "exit=2" in (result.error or "")
    assert "corrupt entry" in (result.error or "")


@pytest.mark.asyncio
async def test_unpack_msix_succeeds_with_appx_manifest(tmp_path: Path):
    """The canonical MSIX layout: AppxManifest.xml + AppxBlockMap.xml +
    AppxSignature.p7x + payload tree (PE binaries, resource pri, etc).
    """
    msix = tmp_path / "vendor.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=(
            b"AppxManifest.xml\n"
            b"AppxBlockMap.xml\n"
            b"AppxSignature.p7x\n"
            b"VendorApp.exe\n"
            b"Vendor.Lib.dll\n"
        ),
    )

    def _populate(*_a, **_kw):
        # Real-shape MSIX payload.
        (extraction_dir / "AppxManifest.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">\n'
            '  <Identity Name="Vendor.App" Version="1.0.0.0" />\n'
            '</Package>\n'
        )
        (extraction_dir / "AppxBlockMap.xml").write_text(
            '<?xml version="1.0" encoding="utf-8"?>\n'
            '<BlockMap xmlns="http://schemas.microsoft.com/appx/2010/blockmap">\n'
            '  <File Name="VendorApp.exe" Size="1024" LfhSize="0">\n'
            '    <Block Hash="..."/>\n'
            '  </File>\n'
            '</BlockMap>\n'
        )
        (extraction_dir / "AppxSignature.p7x").write_bytes(b"PKCX" + b"\x00" * 100)
        (extraction_dir / "VendorApp.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        (extraction_dir / "Vendor.Lib.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 200)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None
    assert "MSIX extraction complete via 7z" in result.unpack_log
    # The 4 MSIX signal files must actually exist post-extraction.
    assert (extraction_dir / "AppxManifest.xml").exists()
    assert (extraction_dir / "AppxBlockMap.xml").exists()
    assert (extraction_dir / "AppxSignature.p7x").exists()


@pytest.mark.asyncio
async def test_unpack_msix_succeeds_with_appx_bundle_manifest(tmp_path: Path):
    """A MSIXBundle has AppxBundleManifest.xml (not AppxManifest.xml). The
    signal-file check accepts EITHER.
    """
    bundle = tmp_path / "vendor.msixbundle"
    bundle.write_bytes(_ZIP_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=(
            b"AppxMetadata/AppxBundleManifest.xml\n"
            b"vendor.x64.appx\n"
            b"vendor.arm64.appx\n"
        ),
    )

    def _populate(*_a, **_kw):
        (extraction_dir / "AppxMetadata").mkdir()
        (extraction_dir / "AppxMetadata" / "AppxBundleManifest.xml").write_text(
            '<?xml version="1.0" ?>\n<Bundle/>\n'
        )
        (extraction_dir / "vendor.x64.appx").write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        (extraction_dir / "vendor.arm64.appx").write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        return _make_proc_stub(returncode=0)

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        result = await unpack_msix(
            firmware_path=str(bundle),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True, f"expected success, got error={result.error!r}"
    # Inner per-arch MSIX files must be present (Phase α.4 will recurse them).
    assert (extraction_dir / "vendor.x64.appx").exists()
    assert (extraction_dir / "vendor.arm64.appx").exists()


@pytest.mark.asyncio
async def test_unpack_msix_warning_exit_code_still_succeeds(tmp_path: Path):
    """7z exit=1 means warnings (e.g. checksum mismatch on individual entries)
    but content extracted — still report success with a warning note in the log.
    """
    msix = tmp_path / "vendor.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(returncode=0, stdout=b"AppxManifest.xml\n")

    def _populate(*_a, **_kw):
        (extraction_dir / "AppxManifest.xml").write_text("<Package/>\n")
        return _make_proc_stub(returncode=1, stderr=b"WARNING: data error in 'foo.dat'\n")

    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        result = await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    # Warning note must point operator at verify_msix_blockmap MCP tool.
    assert "warnings (rc=1)" in result.unpack_log
    assert "verify_msix_blockmap" in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_msix_invokes_progress_callback(tmp_path: Path):
    msix = tmp_path / "small.msix"
    msix.write_bytes(_ZIP_MAGIC + b"\x00" * 64)
    extraction_dir = tmp_path / "extracted"

    list_stub = _make_proc_stub(returncode=0, stdout=b"AppxManifest.xml\n")

    def _populate(*_a, **_kw):
        (extraction_dir / "AppxManifest.xml").write_text("<Package/>\n")
        return _make_proc_stub(returncode=0)

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_msix.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_make_two_phase_subprocess(
            list_stub, _populate,
        )),
    ):
        await unpack_msix(
            firmware_path=str(msix),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


@pytest.mark.asyncio
async def test_unpack_msix_live_canary_real_msix(tmp_path: Path):
    """Rule #35b live canary — synthesise a minimal MSIX using Python's
    zipfile module (no external tooling needed) and extract via 7z.
    """
    if not shutil.which("7z"):
        pytest.skip("7z not on PATH (run via container)")

    msix_path = tmp_path / "canary.msix"
    with zipfile.ZipFile(msix_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AppxManifest.xml",
            '<?xml version="1.0" ?>\n<Package><Identity Name="Canary" Version="0.0.0.1"/></Package>\n',
        )
        zf.writestr(
            "AppxBlockMap.xml",
            '<?xml version="1.0" ?>\n<BlockMap><File Name="canary.exe" Size="6"/></BlockMap>\n',
        )
        zf.writestr("canary.exe", b"\x4d\x5a" + b"\x00" * 4)

    output_base = tmp_path / "out"
    output_base.mkdir()

    result = await unpack_msix(
        firmware_path=str(msix_path),
        output_base_dir=str(output_base),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    extract_root = result.extraction_dir or result.extracted_path
    assert os.path.isfile(os.path.join(extract_root, "AppxManifest.xml"))
    assert os.path.isfile(os.path.join(extract_root, "AppxBlockMap.xml"))
    assert os.path.isfile(os.path.join(extract_root, "canary.exe"))
    assert "7z l exit=0" in result.unpack_log
    assert "7z x exit=0" in result.unpack_log
