"""Phase α.4 contract tests: windows_archive MCP tools."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.ai.tools.windows_archive import (
    _handle_classify_driver_package_subtype,
    _handle_dump_msi_custom_actions,
    _handle_identify_psf_baseline,
    _handle_list_cab_contents,
    _handle_parse_inf_basic,
    _handle_read_msix_manifest,
)


# ── Stub ToolContext (duck-types the resolve_path interface) ──────────────


@dataclass
class _StubContext:
    """Minimal ToolContext stub for unit testing the windows_archive tools.

    Only exposes the attributes/methods the handlers actually use:
    resolve_path() + extracted_path. Real ToolContext has project_id,
    firmware_id, db, etc. — irrelevant for these tests.
    """

    extracted_path: str
    extraction_dir: str | None = None

    def resolve_path(self, path: str) -> str:
        full = os.path.join(self.extracted_path, path.lstrip("/"))
        full_real = os.path.realpath(full)
        root_real = os.path.realpath(self.extracted_path)
        if not full_real.startswith(root_real):
            raise ValueError(f"Path traversal: {path}")
        return full_real


def _make_proc_stub(returncode, stdout=b"", stderr=b""):
    class _Proc:
        def __init__(self):
            self.returncode = returncode

        async def communicate(self):
            return stdout, stderr

        def kill(self):
            pass

    return _Proc()


# ── list_cab_contents ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_cab_contents_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_list_cab_contents({"path": "missing.cab"}, ctx)
    assert "CAB file not found" in out


@pytest.mark.asyncio
async def test_list_cab_contents_handles_missing_cabextract(tmp_path: Path):
    cab = tmp_path / "vendor.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.windows_archive.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        out = await _handle_list_cab_contents({"path": "vendor.cab"}, ctx)

    assert "cabextract binary missing" in out


@pytest.mark.asyncio
async def test_list_cab_contents_returns_cabextract_listing(tmp_path: Path):
    cab = tmp_path / "vendor.cab"
    cab.write_bytes(b"MSCF" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    list_stub = _make_proc_stub(
        returncode=0,
        stdout=b"vendor.sys\nvendor.inf\nvendor.cat\n",
    )

    with patch(
        "app.ai.tools.windows_archive.asyncio.create_subprocess_exec",
        AsyncMock(return_value=list_stub),
    ):
        out = await _handle_list_cab_contents({"path": "vendor.cab"}, ctx)

    assert "CAB contents (3 entries)" in out
    assert "vendor.sys" in out
    assert "vendor.inf" in out
    assert "vendor.cat" in out


# ── read_msix_manifest ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_read_msix_manifest_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_read_msix_manifest({"path": "AppxManifest.xml"}, ctx)
    assert "Manifest file not found" in out


@pytest.mark.asyncio
async def test_read_msix_manifest_handles_parse_error(tmp_path: Path):
    bad = tmp_path / "AppxManifest.xml"
    bad.write_text("not valid xml{{}}")
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_read_msix_manifest({"path": "AppxManifest.xml"}, ctx)
    assert "Manifest XML parse failed" in out


@pytest.mark.asyncio
async def test_read_msix_manifest_parses_canonical_appx_manifest(tmp_path: Path):
    manifest = tmp_path / "AppxManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Package xmlns="http://schemas.microsoft.com/appx/manifest/foundation/windows10">\n'
        '  <Identity Name="Vendor.App" Version="1.2.3.4" Publisher="CN=Vendor" '
        'ProcessorArchitecture="x64"/>\n'
        '  <Capabilities>\n'
        '    <Capability Name="internetClient"/>\n'
        '    <DeviceCapability Name="webcam"/>\n'
        '  </Capabilities>\n'
        '  <Applications>\n'
        '    <Application Id="App" Executable="VendorApp.exe" EntryPoint="MainEntry"/>\n'
        '  </Applications>\n'
        '  <Dependencies>\n'
        '    <TargetDeviceFamily Name="Windows.Desktop" '
        'MinVersion="10.0.17763.0" MaxVersionTested="10.0.22621.0"/>\n'
        '  </Dependencies>\n'
        '</Package>\n'
    )
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_read_msix_manifest({"path": "AppxManifest.xml"}, ctx)
    assert "Type: MSIX/AppX (single package)" in out
    assert "Identity:" in out
    assert "Vendor.App" in out
    assert "1.2.3.4" in out
    assert "Capabilities (2)" in out
    assert "internetClient" in out
    assert "DeviceCapability: webcam" in out
    assert "Applications (1)" in out
    assert "VendorApp.exe" in out
    assert "Target device families (1)" in out
    assert "Windows.Desktop" in out


@pytest.mark.asyncio
async def test_read_msix_manifest_parses_bundle_manifest(tmp_path: Path):
    manifest = tmp_path / "AppxBundleManifest.xml"
    manifest.write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<Bundle xmlns="http://schemas.microsoft.com/appx/2013/bundle">\n'
        '  <Identity Name="Vendor.Bundle" Version="1.0.0.0" Publisher="CN=Vendor"/>\n'
        '</Bundle>\n'
    )
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_read_msix_manifest({"path": "AppxBundleManifest.xml"}, ctx)
    assert "Type: MSIXBundle (multi-package)" in out
    assert "Vendor.Bundle" in out


# ── dump_msi_custom_actions ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_dump_msi_custom_actions_handles_missing_msi(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_dump_msi_custom_actions({"path": "missing.msi"}, ctx)
    assert "MSI file not found" in out


@pytest.mark.asyncio
async def test_dump_msi_custom_actions_handles_missing_msidump(tmp_path: Path):
    msi = tmp_path / "vendor.msi"
    msi.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    with patch(
        "app.ai.tools.windows_archive.asyncio.create_subprocess_exec",
        side_effect=FileNotFoundError,
    ):
        out = await _handle_dump_msi_custom_actions({"path": "vendor.msi"}, ctx)

    assert "msidump binary missing" in out
    assert "msitools" in out


@pytest.mark.asyncio
async def test_dump_msi_custom_actions_extracts_binary_table(tmp_path: Path):
    msi = tmp_path / "vendor.msi"
    msi.write_bytes(b"\xd0\xcf\x11\xe0" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    extract_stub = _make_proc_stub(returncode=0)

    def _create_subprocess(*_args, **_kwargs):
        # Plant the dump_dir contents (msidump would write Binary table
        # entries here).
        dump_dir = str(msi) + "_custom_actions"
        os.makedirs(dump_dir, exist_ok=True)
        (Path(dump_dir) / "ca_install.exe").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        (Path(dump_dir) / "ca_validate.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
        (Path(dump_dir) / "ca_pre_install.vbs").write_text("' VBScript stub\n")
        return extract_stub

    with patch(
        "app.ai.tools.windows_archive.asyncio.create_subprocess_exec",
        AsyncMock(side_effect=_create_subprocess),
    ):
        out = await _handle_dump_msi_custom_actions({"path": "vendor.msi"}, ctx)

    assert "Custom-action dump complete" in out
    assert "extract-only, NEVER executed" in out
    assert "ca_install.exe" in out
    assert "ca_validate.dll" in out
    assert "ca_pre_install.vbs" in out
    assert "(3 entries)" in out


# ── parse_inf_basic ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_parse_inf_basic_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_parse_inf_basic({"path": "missing.inf"}, ctx)
    assert "INF file not found" in out


@pytest.mark.asyncio
async def test_parse_inf_basic_parses_canonical_inf(tmp_path: Path):
    inf = tmp_path / "vendor.inf"
    inf.write_text(
        "[Version]\n"
        "Signature=\"$Windows NT$\"\n"
        "Class=Net\n"
        "ClassGuid={4D36E972-E325-11CE-BFC1-08002BE10318}\n"
        "Provider=%VENDOR%\n"
        "DriverVer=01/15/2025,1.0.0.0\n"
        "\n"
        "[Manufacturer]\n"
        "%VENDOR% = VendorModels,NTamd64\n"
        "\n"
        "[VendorModels.NTamd64]\n"
        "%Net.DeviceDesc% = Net.NT, PCI\\VEN_8086&DEV_0953\n"
        "%Net.DeviceDesc% = Net.NT, PCI\\VEN_8086&DEV_0954\n"
        "\n"
        "[Strings]\n"
        "VENDOR = \"AcmeCorp\"\n"
        "Net.DeviceDesc = \"Acme NIC\"\n"
    )
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_parse_inf_basic({"path": "vendor.inf"}, ctx)
    assert "INF file: vendor.inf" in out
    assert "[Version]" in out
    assert "Class=Net" in out
    assert "ClassGuid={4D36E972-E325-11CE-BFC1-08002BE10318}" in out
    assert "[Manufacturer]" in out
    # Models-like sections must be enumerated.
    assert "Models-like sections" in out
    assert "VendorModels.NTamd64" in out
    assert "PCI\\VEN_8086&DEV_0953" in out


# ── identify_psf_baseline ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_identify_psf_baseline_handles_missing_file(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_identify_psf_baseline({"path": "missing.psf"}, ctx)
    assert "PSF file not found" in out


@pytest.mark.asyncio
async def test_identify_psf_baseline_rejects_invalid_magic(tmp_path: Path):
    bad = tmp_path / "bad.psf"
    bad.write_bytes(b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_identify_psf_baseline({"path": "bad.psf"}, ctx)
    assert "Not a valid PSF" in out


@pytest.mark.asyncio
async def test_identify_psf_baseline_parses_pa30(tmp_path: Path):
    psf = tmp_path / "express.psf"
    psf.write_bytes(b"PA30" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_identify_psf_baseline({"path": "express.psf"}, ctx)
    assert "Magic: PA30" in out
    assert "Win10/11 cumulative" in out


@pytest.mark.asyncio
async def test_identify_psf_baseline_extracts_rsds_guid(tmp_path: Path):
    """When the PSF header carries an RSDS marker (PE PDB hash), the tool
    surfaces the GUID + age so the operator can locate the baseline."""
    psf = tmp_path / "express.psf"
    # PSF header (PA30) + 100 bytes padding + RSDS + GUID + age + path
    rsds_block = (
        b"RSDS"
        + bytes.fromhex("aabbccdd")  # data1 (LE)
        + bytes.fromhex("1122")      # data2 (LE)
        + bytes.fromhex("3344")      # data3 (LE)
        + bytes.fromhex("5566778899aabbcc")  # data4 (BE)
        + bytes.fromhex("01000000")  # age=1 (LE)
    )
    psf.write_bytes(b"PA30" + b"\x00" * 100 + rsds_block + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_identify_psf_baseline({"path": "express.psf"}, ctx)
    assert "Target binary RSDS GUID" in out
    assert "DDCCBBAA-2211-4433-5566-778899AABBCC" in out
    assert "PDB Age: 1" in out
    assert "apply_psf_to_baseline" in out


# ── classify_driver_package_subtype ───────────────────────────────────────


@pytest.mark.asyncio
async def test_classify_subtype_handles_missing_dir(tmp_path: Path):
    ctx = _StubContext(extracted_path=str(tmp_path))
    out = await _handle_classify_driver_package_subtype({"path": "missing"}, ctx)
    assert "Driver-package directory not found" in out


@pytest.mark.asyncio
async def test_classify_subtype_canonical_4_file(tmp_path: Path):
    pkg = tmp_path / "extracted_pkg"
    pkg.mkdir()
    (pkg / "vendor.inf").write_text("[Version]\n")
    (pkg / "vendor.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    (pkg / "vendor.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)
    (pkg / "vendor.dll").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_classify_driver_package_subtype(
        {"path": "extracted_pkg"}, ctx,
    )
    assert "Driver-package subtype: cab_inf_sys_cat" in out
    assert "*.inf: 1" in out
    assert "*.sys: 1" in out
    assert "*.cat: 1" in out
    assert "*.dll: 1" in out


@pytest.mark.asyncio
async def test_classify_subtype_dch(tmp_path: Path):
    pkg = tmp_path / "dch_pkg"
    pkg.mkdir()
    (pkg / "vendor.inf").write_text("[Version]\n")
    (pkg / "ext_vendor.inf").write_text("[Version]\nExtensionId=...\n")
    (pkg / "vendor.sys").write_bytes(b"\x4d\x5a" + b"\x00" * 100)
    (pkg / "vendor.cat").write_bytes(b"\x30\x82" + b"\x00" * 100)
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_classify_driver_package_subtype({"path": "dch_pkg"}, ctx)
    assert "Driver-package subtype: dch" in out


@pytest.mark.asyncio
async def test_classify_subtype_unknown(tmp_path: Path):
    pkg = tmp_path / "weird_pkg"
    pkg.mkdir()
    (pkg / "readme.txt").write_text("hi\n")
    ctx = _StubContext(extracted_path=str(tmp_path))

    out = await _handle_classify_driver_package_subtype(
        {"path": "weird_pkg"}, ctx,
    )
    assert "Driver-package subtype: unknown" in out
