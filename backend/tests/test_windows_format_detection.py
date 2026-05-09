"""Phase α.3 contract tests: Windows-format detection.

Covers the detection cascade additions in
``backend/app/services/format_detection.py`` and the strategy-table
additions in ``backend/app/workers/extraction_strategies.py``.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from app.services.format_detection import (
    EXTRACTION_CAPABILITY,
    DetectedFormat,
    ExtractionCapability,
    detect_format,
)
from app.workers.extraction_strategies import (
    STRATEGIES,
    get_strategy,
)
from app.workers.unpack_cab import unpack_cab
from app.workers.unpack_driver_package import unpack_driver_package
from app.workers.unpack_msi import unpack_msi
from app.workers.unpack_msix import unpack_msix
from app.workers.unpack_msu import unpack_msu
from app.workers.unpack_psf import unpack_psf
from app.workers.unpack_vhdx import unpack_vhdx

# ── Detection cascade tests ────────────────────────────────────────────────


def test_detect_cab_magic_routes_to_windows_cab(tmp_path: Path):
    """MSCF magic at offset 0 + .cab filename → WINDOWS_CAB."""
    cab = tmp_path / "vendor.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 1024)
    assert detect_format(cab) == DetectedFormat.WINDOWS_CAB


def test_detect_cab_magic_with_msu_filename_routes_to_msu(tmp_path: Path):
    """MSCF magic + .msu filename → WINDOWS_MSU (filename-based subtype)."""
    msu = tmp_path / "windows10.0-kb1234.msu"
    msu.write_bytes(b"MSCF" + b"\x00" * 1024)
    assert detect_format(msu) == DetectedFormat.WINDOWS_MSU


def test_detect_cab_magic_with_uppercase_msu_filename_routes_to_msu(tmp_path: Path):
    """Filename matching is case-insensitive."""
    msu = tmp_path / "Windows10.0-KB1234.MSU"
    msu.write_bytes(b"MSCF" + b"\x00" * 1024)
    assert detect_format(msu) == DetectedFormat.WINDOWS_MSU


def test_detect_psf_pa30_magic(tmp_path: Path):
    """PA30 magic → WINDOWS_PSF (Win10/11 cumulative Express delta)."""
    psf = tmp_path / "express.psf"
    psf.write_bytes(b"PA30" + b"\x00" * 1024)
    assert detect_format(psf) == DetectedFormat.WINDOWS_PSF


def test_detect_psf_pa19_magic(tmp_path: Path):
    """PA19 magic → WINDOWS_PSF (Win7/8 era)."""
    psf = tmp_path / "legacy.psf"
    psf.write_bytes(b"PA19" + b"\x00" * 1024)
    assert detect_format(psf) == DetectedFormat.WINDOWS_PSF


def test_detect_psf_pa17_magic(tmp_path: Path):
    """PA17 magic → WINDOWS_PSF (earliest variant)."""
    psf = tmp_path / "earliest.psf"
    psf.write_bytes(b"PA17" + b"\x00" * 1024)
    assert detect_format(psf) == DetectedFormat.WINDOWS_PSF


def test_detect_vhdx_magic(tmp_path: Path):
    """'vhdxfile' magic at offset 0 → WINDOWS_VHDX."""
    vhdx = tmp_path / "vendor.vhdx"
    vhdx.write_bytes(b"vhdxfile" + b"\x00" * 1024)
    assert detect_format(vhdx) == DetectedFormat.WINDOWS_VHDX


def test_detect_msi_ole2_with_msi_filename(tmp_path: Path):
    """OLE2 CFB magic + .msi filename → WINDOWS_MSI."""
    msi = tmp_path / "vendor.msi"
    # OLE2 compound document magic.
    msi.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 1024)
    assert detect_format(msi) == DetectedFormat.WINDOWS_MSI


def test_detect_msi_ole2_with_msp_filename(tmp_path: Path):
    """OLE2 CFB magic + .msp filename → WINDOWS_MSI (Microsoft Patch)."""
    msp = tmp_path / "kb1234.msp"
    msp.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 1024)
    assert detect_format(msp) == DetectedFormat.WINDOWS_MSI


def test_detect_doc_ole2_does_NOT_route_to_msi(tmp_path: Path):
    """OLE2 magic with .doc / .xls filename must NOT classify as MSI —
    the filename gate is the disambiguator (Office docs share OLE2 magic).
    Existing behavior must be preserved."""
    doc = tmp_path / "report.doc"
    doc.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 1024)
    fmt = detect_format(doc)
    assert fmt != DetectedFormat.WINDOWS_MSI
    # Should fall through to UNKNOWN (no Office handler in this codebase).
    assert fmt == DetectedFormat.UNKNOWN


def test_detect_msix_via_appx_manifest(tmp_path: Path):
    """ZIP with AppxManifest.xml at root → WINDOWS_MSIX."""
    msix = tmp_path / "vendor.msix"
    with zipfile.ZipFile(msix, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AppxManifest.xml",
            '<?xml version="1.0"?><Package/>\n',
        )
        zf.writestr("AppxBlockMap.xml", '<?xml version="1.0"?><BlockMap/>\n')
        zf.writestr("vendor.exe", b"\x4d\x5a" + b"\x00" * 50)
    assert detect_format(msix) == DetectedFormat.WINDOWS_MSIX


def test_detect_msix_bundle_via_bundle_manifest(tmp_path: Path):
    """ZIP with AppxMetadata/AppxBundleManifest.xml → WINDOWS_MSIX."""
    bundle = tmp_path / "vendor.msixbundle"
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "AppxMetadata/AppxBundleManifest.xml",
            '<?xml version="1.0"?><Bundle/>\n',
        )
        zf.writestr("vendor.x64.appx", b"PK\x03\x04" + b"\x00" * 100)
    assert detect_format(bundle) == DetectedFormat.WINDOWS_MSIX


def test_detect_plain_zip_does_NOT_route_to_msix(tmp_path: Path):
    """ZIP without AppxManifest / AppxBundleManifest → ZIP_ARCHIVE
    (existing behavior preserved)."""
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as zf:
        zf.writestr("readme.txt", "hi\n")
    assert detect_format(plain) == DetectedFormat.ZIP_ARCHIVE


# ── Capability + strategy registry consistency ──────────────────────────────


@pytest.mark.parametrize(
    "fmt,expected_capability",
    [
        (DetectedFormat.WINDOWS_CAB, ExtractionCapability.FULL),
        (DetectedFormat.WINDOWS_MSI, ExtractionCapability.FULL),
        (DetectedFormat.WINDOWS_MSIX, ExtractionCapability.FULL),
        (DetectedFormat.WINDOWS_MSU, ExtractionCapability.FULL),
        (DetectedFormat.WINDOWS_PSF, ExtractionCapability.PARTIAL),
        (DetectedFormat.WINDOWS_VHDX, ExtractionCapability.FULL),
        (DetectedFormat.WINDOWS_DRIVER_PACKAGE, ExtractionCapability.FULL),
    ],
)
def test_extraction_capability_matrix(fmt, expected_capability):
    """Rule #21 mirror discipline: every Windows DetectedFormat enum value
    has a matching EXTRACTION_CAPABILITY entry. Missing entries crash the
    upload-status endpoint."""
    assert EXTRACTION_CAPABILITY[fmt] == expected_capability


@pytest.mark.parametrize(
    "fmt,expected_worker",
    [
        (DetectedFormat.WINDOWS_CAB, unpack_cab),
        (DetectedFormat.WINDOWS_MSI, unpack_msi),
        (DetectedFormat.WINDOWS_MSIX, unpack_msix),
        (DetectedFormat.WINDOWS_MSU, unpack_msu),
        (DetectedFormat.WINDOWS_PSF, unpack_psf),
        (DetectedFormat.WINDOWS_VHDX, unpack_vhdx),
        (DetectedFormat.WINDOWS_DRIVER_PACKAGE, unpack_driver_package),
    ],
)
def test_strategies_dispatch_table(fmt, expected_worker):
    """Rule #21 mirror discipline: every Windows DetectedFormat routes to
    its dedicated worker via STRATEGIES + get_strategy."""
    assert STRATEGIES[fmt] is expected_worker
    assert get_strategy(fmt) is expected_worker


def test_no_unmapped_windows_format():
    """Defensive: every WINDOWS_* enum value must appear in BOTH
    EXTRACTION_CAPABILITY and STRATEGIES. Catches the silent omission
    pattern Rule #21 is built to prevent."""
    windows_formats = [
        f for f in DetectedFormat
        if f.value.startswith("windows_")
        and f != DetectedFormat.WINDOWS_INSTALLER_ISO
        # WINDOWS_INSTALLER_ISO predates Phase α; covered by separate test_format_detection.
    ]
    assert len(windows_formats) == 7, (
        f"Expected 7 Phase-α Windows formats, got {len(windows_formats)}: "
        f"{[f.value for f in windows_formats]}"
    )
    for fmt in windows_formats:
        assert fmt in EXTRACTION_CAPABILITY, (
            f"{fmt.value} missing from EXTRACTION_CAPABILITY"
        )
        assert fmt in STRATEGIES, f"{fmt.value} missing from STRATEGIES"
