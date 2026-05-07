"""Phase 2 handler 3 contract tests: :func:`unpack_windows_installer_iso`.

Covers the composition contract — outer ISO 9660 extraction via the
shipped :func:`unpack_iso9660` handler, inner WIM expansion via the
shipped :func:`unpack_wim` handler — and the surface-level behaviour:
candidate scanning (canonical + recursive), preferred-root selection
(install.wim with Windows/ > install.{wim,esd} > boot.{wim,esd} >
ISO root), graceful degradation when an inner WIM fails to extract,
ESD variant handling, non-canonical layouts.

Includes a Rule #35b live canary that builds a real Windows installer
ISO (mkisofs/genisoimage outer + wimlib-imagex captured inner) and
runs it through the full subprocess pipeline. Skipped gracefully if
either tool is missing.

The strategy-table assertion lives in test_extraction_pipeline.py
(``test_windows_installer_iso_routes_to_unpack_windows_installer_iso``)
so the lockstep between the worker module and the registry is
enforced from the dispatch side.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.workers.unpack_common import UnpackResult
from app.workers.unpack_windows_installer_iso import (
    _find_inner_wim_candidates,
    _pick_preferred_root,
    unpack_windows_installer_iso,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_iso_result(
    *,
    success: bool,
    extraction_dir: str | None = None,
    extracted_path: str | None = None,
    error: str | None = None,
    unpack_log: str = "",
) -> UnpackResult:
    """Construct an UnpackResult shaped like an unpack_iso9660 return value."""
    r = UnpackResult()
    r.success = success
    r.extraction_dir = extraction_dir
    r.extracted_path = extracted_path or extraction_dir
    r.error = error
    r.unpack_log = unpack_log
    return r


# ---------------------------------------------------------------------------
# 1. Outer ISO extraction fails -> failure propagates unchanged.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_outer_iso_failure_propagates_unchanged(tmp_path: Path):
    """If the ISO 9660 outer extraction fails, the composite handler
    must NOT swallow or wrap the error — the operator needs to see the
    real 7z failure to debug the input.
    """
    fake_iso = tmp_path / "broken.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    iso_failure = _make_iso_result(
        success=False,
        error="7z extraction failed (exit=2): bad signature",
        unpack_log="7z exit=2\nstderr: bad signature\n",
    )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_failure),
    ) as iso_mock:
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    iso_mock.assert_awaited_once()
    assert result.success is False
    assert result.error is not None
    assert "7z extraction failed" in result.error
    assert "bad signature" in result.unpack_log


# ---------------------------------------------------------------------------
# 2. Outer ISO succeeds, no inner WIM/ESD found -> success with note.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_iso_succeeds_no_inner_wim(tmp_path: Path):
    """A Windows recovery-driver ISO with no installer payloads still
    extracts successfully; unpack_log carries the "no inner WIM/ESD"
    message so the operator knows the recursion ran.
    """
    fake_iso = tmp_path / "drivers.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    extraction_dir.mkdir()
    (extraction_dir / "drivers").mkdir()
    (extraction_dir / "drivers" / "vendor.inf").write_text("[Manufacturer]\n")

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    wim_mock = AsyncMock()
    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim", wim_mock,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "No inner WIM/ESD payloads detected" in result.unpack_log
    # unpack_wim must NOT have been called when there's nothing to expand.
    wim_mock.assert_not_awaited()


# ---------------------------------------------------------------------------
# 3. Outer ISO + canonical install.wim -> composite extracted_path
#    points into install.wim_extracted/Windows.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_canonical_install_wim_with_windows_subdir_is_preferred_root(
    tmp_path: Path,
):
    fake_iso = tmp_path / "windows10.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    sources = extraction_dir / "sources"
    sources.mkdir(parents=True)
    install_wim = sources / "install.wim"
    install_wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    async def _fake_wim_apply(firmware_path, output_base_dir, **_kwargs):
        # Plant the same shape unpack_wim ships: <output_base_dir>/extracted/.
        ed = Path(output_base_dir) / "extracted"
        (ed / "Windows" / "System32").mkdir(parents=True)
        (ed / "Windows" / "System32" / "kernel32.dll").write_bytes(
            b"\x4d\x5a" + b"\x00" * 100,
        )
        return _make_iso_result(
            success=True,
            extraction_dir=str(ed),
            extracted_path=str(ed),
            unpack_log="WIM extraction complete via wimlib-imagex (image 1).\n",
        )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim",
        side_effect=_fake_wim_apply,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    # Preferred-root contract: install.wim with Windows/ subdir wins.
    assert result.extracted_path is not None
    assert "install.wim_extracted" in result.extracted_path
    assert os.path.isdir(os.path.join(result.extracted_path, "Windows"))
    # The composite layout must be on disk: install.wim_extracted/ sibling
    # to install.wim itself.
    assert (sources / "install.wim_extracted").is_dir()
    # Forensic log: the inner expansion was recorded.
    assert "[OK]" in result.unpack_log
    assert "sources/install.wim" in result.unpack_log


# ---------------------------------------------------------------------------
# 4. Boot.wim only (no install.wim) -> extracted_path falls back to
#    boot.wim_extracted/.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_boot_wim_only_falls_back_to_boot_wim_root(tmp_path: Path):
    fake_iso = tmp_path / "winpe.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    sources = extraction_dir / "sources"
    sources.mkdir(parents=True)
    (sources / "boot.wim").write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    async def _fake_wim_apply(firmware_path, output_base_dir, **_kwargs):
        ed = Path(output_base_dir) / "extracted"
        (ed / "Windows" / "System32").mkdir(parents=True)
        (ed / "Windows" / "System32" / "winpeshl.exe").write_bytes(b"\x4d\x5a")
        return _make_iso_result(
            success=True,
            extraction_dir=str(ed),
            extracted_path=str(ed),
            unpack_log="WIM extraction complete via wimlib-imagex (image 1).\n",
        )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim",
        side_effect=_fake_wim_apply,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert result.extracted_path is not None
    assert "boot.wim_extracted" in result.extracted_path


# ---------------------------------------------------------------------------
# 5. Inner WIM extraction fails -> degrade to PARTIAL (composite still
#    success=True; per-WIM failure recorded in unpack_log).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_inner_wim_failure_degrades_to_partial(tmp_path: Path):
    fake_iso = tmp_path / "windows10.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    sources = extraction_dir / "sources"
    sources.mkdir(parents=True)
    install_wim = sources / "install.wim"
    install_wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    async def _fake_wim_failure(firmware_path, output_base_dir, **_kwargs):
        return _make_iso_result(
            success=False,
            error="wimlib-imagex apply failed (exit=2): corrupt resource",
            unpack_log="wimlib-imagex apply exit=2\n",
        )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim",
        side_effect=_fake_wim_failure,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    # Composite degrades to PARTIAL: outer ISO is still useful even when
    # inner-WIM expansion fails. Operator pulls the WIM with 7z manually
    # using the truncated stderr from unpack_log.
    assert result.success is True
    assert "[FAIL]" in result.unpack_log
    assert "corrupt resource" in result.unpack_log
    # extracted_path falls back to the ISO root since no inner extraction
    # produced a tree.
    assert result.extracted_path == str(extraction_dir)


# ---------------------------------------------------------------------------
# 6. ESD variant handling — sources/install.esd is recognised and
#    routed through unpack_wim (wimlib handles ESD natively).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_install_esd_variant_is_routed_to_unpack_wim(tmp_path: Path):
    fake_iso = tmp_path / "win11.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    sources = extraction_dir / "sources"
    sources.mkdir(parents=True)
    install_esd = sources / "install.esd"
    install_esd.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    received_paths: list[str] = []

    async def _fake_wim_apply(firmware_path, output_base_dir, **_kwargs):
        received_paths.append(firmware_path)
        ed = Path(output_base_dir) / "extracted"
        ed.mkdir(parents=True)
        (ed / "Windows").mkdir()
        return _make_iso_result(
            success=True,
            extraction_dir=str(ed),
            extracted_path=str(ed),
            unpack_log="WIM extraction complete via wimlib-imagex (image 1).\n",
        )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim",
        side_effect=_fake_wim_apply,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    # unpack_wim received the .esd path verbatim.
    assert len(received_paths) == 1
    assert received_paths[0] == str(install_esd)
    # Preferred-root: install.esd with Windows/ subdir wins.
    assert result.extracted_path is not None
    assert "install.esd_extracted" in result.extracted_path


# ---------------------------------------------------------------------------
# 7. Non-canonical layout — recursive os.walk picks up a WIM at
#    /recovery/winpe.wim (vendor recovery USB shape).
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_non_canonical_layout_recursive_scan(tmp_path: Path):
    fake_iso = tmp_path / "vendor_recovery.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    recovery = extraction_dir / "recovery"
    recovery.mkdir(parents=True)
    winpe_wim = recovery / "winpe.wim"
    winpe_wim.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 1024)

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete via 7z.\n",
    )

    async def _fake_wim_apply(firmware_path, output_base_dir, **_kwargs):
        ed = Path(output_base_dir) / "extracted"
        ed.mkdir(parents=True)
        (ed / "vendor.bin").write_bytes(b"\x00" * 256)
        return _make_iso_result(
            success=True,
            extraction_dir=str(ed),
            extracted_path=str(ed),
            unpack_log="WIM extraction complete via wimlib-imagex (image 1).\n",
        )

    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ), patch(
        "app.workers.unpack_windows_installer_iso.unpack_wim",
        side_effect=_fake_wim_apply,
    ):
        result = await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
        )

    assert result.success is True
    assert "recovery/winpe.wim" in result.unpack_log
    # Non-canonical layout has no install.wim/boot.wim, so the
    # preferred-root falls back to the ISO root.
    assert result.extracted_path == str(extraction_dir)
    # The winpe extraction tree is still on disk for downstream
    # detection_roots scanning.
    assert (recovery / "winpe.wim_extracted").is_dir()


# ---------------------------------------------------------------------------
# 8. _find_inner_wim_candidates direct contract — canonical-first,
#    recursive-fallback, no double-listing.
# ---------------------------------------------------------------------------

def test_find_inner_wim_candidates_canonical_first(tmp_path: Path):
    """When canonical paths exist, the recursive scan does NOT run —
    we don't want to double-list the same payloads.
    """
    sources = tmp_path / "sources"
    sources.mkdir()
    install = sources / "install.wim"
    install.write_bytes(b"MSWIM")
    boot = sources / "boot.wim"
    boot.write_bytes(b"MSWIM")
    # An extra non-canonical WIM that should NOT be listed (canonical
    # pass found install + boot, so the recursive fallback is skipped).
    extra = tmp_path / "winre" / "extra.wim"
    extra.parent.mkdir()
    extra.write_bytes(b"MSWIM")

    candidates = _find_inner_wim_candidates(str(tmp_path))

    # Canonical pass listed install.wim + boot.wim only.
    assert str(install) in candidates
    assert str(boot) in candidates
    assert str(extra) not in candidates
    assert len(candidates) == 2


def test_find_inner_wim_candidates_recursive_fallback(tmp_path: Path):
    """When no canonical paths exist, the recursive fallback runs and
    discovers WIMs anywhere in the tree.
    """
    deep = tmp_path / "vendor" / "winre"
    deep.mkdir(parents=True)
    wim1 = deep / "winre.wim"
    wim1.write_bytes(b"MSWIM")
    wim2 = tmp_path / "boot" / "boot_recovery.esd"
    wim2.parent.mkdir()
    wim2.write_bytes(b"MSWIM")

    candidates = _find_inner_wim_candidates(str(tmp_path))

    assert str(wim1) in candidates
    assert str(wim2) in candidates
    assert len(candidates) == 2


def test_find_inner_wim_candidates_empty_tree(tmp_path: Path):
    """An ISO with no WIMs at all returns an empty list, not None."""
    (tmp_path / "drivers").mkdir()
    (tmp_path / "drivers" / "vendor.inf").write_text("[Manufacturer]\n")

    candidates = _find_inner_wim_candidates(str(tmp_path))
    assert candidates == []


# ---------------------------------------------------------------------------
# 9. _pick_preferred_root direct contract — preference ordering.
# ---------------------------------------------------------------------------

def test_pick_preferred_root_install_wim_with_windows_wins(tmp_path: Path):
    install_root = tmp_path / "sources" / "install.wim_extracted"
    install_root.mkdir(parents=True)
    (install_root / "Windows").mkdir()

    boot_root = tmp_path / "sources" / "boot.wim_extracted"
    boot_root.mkdir(parents=True)
    (boot_root / "Windows").mkdir()

    picked = _pick_preferred_root(
        [str(boot_root), str(install_root)],
        fallback="/iso",
    )
    assert picked == str(install_root)


def test_pick_preferred_root_install_esd_without_windows_still_wins_over_boot(
    tmp_path: Path,
):
    """Tier 2: install.esd with no Windows/ subdir still wins over boot.wim."""
    install_root = tmp_path / "sources" / "install.esd_extracted"
    install_root.mkdir(parents=True)
    # No Windows/ subdir.

    boot_root = tmp_path / "sources" / "boot.wim_extracted"
    boot_root.mkdir(parents=True)
    (boot_root / "Windows").mkdir()  # boot has Windows/ but is still tier 3.

    picked = _pick_preferred_root(
        [str(boot_root), str(install_root)],
        fallback="/iso",
    )
    assert picked == str(install_root)


def test_pick_preferred_root_boot_wim_when_no_install(tmp_path: Path):
    boot_root = tmp_path / "sources" / "boot.wim_extracted"
    boot_root.mkdir(parents=True)

    picked = _pick_preferred_root([str(boot_root)], fallback="/iso")
    assert picked == str(boot_root)


def test_pick_preferred_root_falls_back_when_no_inner(tmp_path: Path):
    picked = _pick_preferred_root([], fallback=str(tmp_path))
    assert picked == str(tmp_path)


# ---------------------------------------------------------------------------
# 10. Progress-callback contract — worker reports milestones and ends at 100.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_progress_callback_reaches_100(tmp_path: Path):
    fake_iso = tmp_path / "drivers.iso"
    fake_iso.write_bytes(b"\x00" * 1024)

    extraction_dir = tmp_path / "extracted"
    extraction_dir.mkdir()

    iso_success = _make_iso_result(
        success=True,
        extraction_dir=str(extraction_dir),
        extracted_path=str(extraction_dir),
        unpack_log="ISO 9660 extraction complete.\n",
    )

    progress = AsyncMock()
    with patch(
        "app.workers.unpack_windows_installer_iso.unpack_iso9660",
        AsyncMock(return_value=iso_success),
    ):
        await unpack_windows_installer_iso(
            firmware_path=str(fake_iso),
            output_base_dir=str(tmp_path),
            progress_callback=progress,
        )

    progress.assert_awaited()
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 11. Rule #35b live canary — build a real Windows installer ISO with
#     mkisofs/genisoimage + wimlib-imagex capture, run through the full
#     subprocess pipeline.
# ---------------------------------------------------------------------------

def _have_iso_creator() -> str | None:
    for name in ("mkisofs", "genisoimage", "xorrisofs"):
        if shutil.which(name):
            return name
    return None


@pytest.mark.asyncio
async def test_unpack_windows_installer_iso_live_canary(tmp_path: Path):
    """Build a real installer ISO (genisoimage/mkisofs) with a real
    inner sources/boot.wim (wimlib-imagex capture), then unpack through
    the full composite pipeline (7z + wimlib-imagex apply).

    Rule #35b live canary — mocks confirm the contract we wrote, this
    test confirms the contract the real toolchain actually has.
    Skipped gracefully when either tool is unavailable on PATH; the
    backend container ships both, so this canary runs in CI / dev
    smoke when the suite is invoked from the container or a host that
    has the tools.
    """
    iso_creator = _have_iso_creator()
    if not iso_creator:
        pytest.skip("No ISO creation tool available (mkisofs / genisoimage / xorrisofs)")
    if not shutil.which("7z"):
        pytest.skip("7z binary not on PATH")
    if not shutil.which("wimlib-imagex"):
        pytest.skip("wimlib-imagex not on PATH")

    # Step 1: build a real boot.wim with wimlib-imagex capture.
    wim_src = tmp_path / "wim_src"
    (wim_src / "Windows" / "System32").mkdir(parents=True)
    (wim_src / "Windows" / "System32" / "winpeshl.exe").write_bytes(
        b"\x4d\x5a" + b"\x00" * 100,
    )
    (wim_src / "Windows" / "System32" / "boot.wim_marker.txt").write_text(
        "this file proves the inner WIM expansion ran\n",
    )

    boot_wim = tmp_path / "boot.wim"
    cap = subprocess.run(
        [
            "wimlib-imagex", "capture",
            str(wim_src), str(boot_wim), "winpe-canary",
            "--compress=none",
        ],
        capture_output=True,
        timeout=60,
    )
    if cap.returncode != 0 or not boot_wim.exists():
        pytest.skip(
            f"wimlib-imagex capture failed (rc={cap.returncode}): "
            f"{cap.stderr.decode(errors='replace')[:200]}"
        )

    # Step 2: build a Windows-installer-shaped ISO around it.
    iso_src = tmp_path / "iso_src"
    (iso_src / "sources").mkdir(parents=True)
    shutil.copy(str(boot_wim), str(iso_src / "sources" / "boot.wim"))
    # Add a bootmgr stub so detect_format would land on
    # WINDOWS_INSTALLER_ISO if we re-classified the result. Not strictly
    # required by the worker (caller already routed us here), but keeps
    # the canary realistic.
    (iso_src / "bootmgr").write_bytes(b"BOOTMGR-STUB" + b"\x00" * 100)

    iso_path = tmp_path / "canary_installer.iso"
    iso_proc = subprocess.run(
        [iso_creator, "-quiet", "-R", "-o", str(iso_path), str(iso_src)],
        capture_output=True,
        timeout=30,
    )
    if iso_proc.returncode != 0 or not iso_path.exists():
        pytest.skip(
            f"{iso_creator} failed (rc={iso_proc.returncode}): "
            f"{iso_proc.stderr.decode(errors='replace')[:200]}"
        )

    # Step 3: run the composite handler on the real ISO.
    out = tmp_path / "out"
    out.mkdir()
    result = await unpack_windows_installer_iso(
        firmware_path=str(iso_path),
        output_base_dir=str(out),
    )

    assert result.success is True, f"expected success, got error={result.error!r}"
    assert result.extracted_path is not None

    # Inner WIM expansion must have produced sources/boot.wim_extracted/.
    extraction_dir = result.extraction_dir or str(out / "extracted")
    boot_wim_extracted = Path(extraction_dir) / "sources" / "boot.wim_extracted"
    assert boot_wim_extracted.is_dir(), (
        f"sources/boot.wim_extracted/ missing after composite extraction; "
        f"unpack_log:\n{result.unpack_log[-1000:]}"
    )

    # Value-flow check: the marker file we planted in the source tree
    # must land in the extracted tree.
    marker = boot_wim_extracted / "Windows" / "System32" / "boot.wim_marker.txt"
    assert marker.is_file(), (
        f"marker file missing under boot.wim_extracted; "
        f"see contents:\n{list(boot_wim_extracted.rglob('*'))[:20]}"
    )
    assert "expansion ran" in marker.read_text()

    # Preferred root contract: only boot.wim present (no install.wim) so
    # extracted_path is boot.wim_extracted/.
    assert "boot.wim_extracted" in result.extracted_path

    # Forensic log: composite log must mention both the outer 7z run
    # and the inner wimlib-imagex run.
    assert "ISO 9660 extraction complete via 7z" in result.unpack_log
    assert "[OK]" in result.unpack_log
    assert "sources/boot.wim" in result.unpack_log
    assert "Recursive Windows installer ISO extraction complete" in result.unpack_log
