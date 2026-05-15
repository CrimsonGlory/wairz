"""Unit tests for the BT firmware banner parser (``bt_fw_banner`` format).

The parser is the content-evidence backstop introduced 2026-05-16 to make
the BTFM→Broadcom vendor-misattribution class IMPOSSIBLE by construction
(see ``.planning/postmortems/postmortem-btfm-correction-and-corpus-2026-
05-15.md``). These tests pin:

* QCA Rome banner parsing for every observed variant (CMC/CHE/APA/HAS/MOS
  codenames, signed-Z and unsigned ROM tags, CI_ prefix + dotted build).
* Tier 0 BRAKTOOTH version-pin for WCN3950 / WCN3990 / WCN3998.
* Broadcom HCD HCI command-stream validator + BRCMcfgS tag fast-path +
  CYW chip ID → cypress vendor disambiguation.
* MediaTek WMT 32-byte ``btmtk_patch_header`` shape + BT vs WiFi
  disambiguation via marker strings.
* Negative cases — NV calibration ``.bin`` files (no banner), arbitrary
  binary (no signature), short reads (no crash).
* Vendor override contract — when the parser populates
  ``ParsedBlob.vendor``, the detector must use it (verified in
  ``test_hardware_firmware_detector_*``; this file pins the parser-side
  contract).

Fixtures are synthesized at test time. No binary fixture files checked in.
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.hardware_firmware.parsers import ParsedBlob, get_parser


def _read_magic(path: Path, n: int = 64) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def _write(path: Path, data: bytes) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return len(data)


# ---------------------------------------------------------------------------
# QCA Rome BTFM banner parsing
# ---------------------------------------------------------------------------


def _make_qca_tlv(banner: str, *, with_patch_release: str | None = None) -> bytes:
    """Synthesize a QCA Rome TLV patch with the given banner string.

    Layout (per upstream Linux btqca.h):
        offset 0..3   : __le32 type_len (type=1 in low byte; length in upper 24)
        offset 4..27  : struct tlv_type_patch (zeroed for test purposes)
        offset 28..   : raw patch payload — we embed the banner ASCII here
    """
    header = bytearray(28)
    # type=1 (TLV_TYPE_PATCH), length placeholder filled below
    payload = bytearray()
    if with_patch_release:
        payload += with_patch_release.encode("ascii") + b"\x00"
    payload += banner.encode("ascii") + b"\x00"
    # Pad payload so the file isn't trivially small.
    payload += b"\x00" * 64
    total_len = len(header) + len(payload)
    # Encode type_len: byte 0 = type, bytes 1..3 = length (le24).
    type_len = (total_len << 8) | 0x01
    struct.pack_into("<I", header, 0, type_len)
    return bytes(header) + bytes(payload)


@pytest.fixture
def parser():
    p = get_parser("bt_fw_banner")
    assert p is not None, "bt_fw_banner parser is not registered"
    return p


def test_qca_rome_cmc_signed_banner(parser, tmp_path: Path) -> None:
    """BTFM.CMC.1.3.0-00069-QCACHROMZ-1 → Comanche / WCN3950 / signed."""
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    pr = "Patch Release PF=WCN3950ROM= 0103 BUILD=BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    blob = _make_qca_tlv(banner, with_patch_release=pr)
    p = tmp_path / "cmbtfw13.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert isinstance(result, ParsedBlob)
    assert result.vendor == "qualcomm"
    assert result.version == banner
    assert result.chipset_target == "wcn3950"  # from PF= field (preferred)
    assert result.signed == "signed"
    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "qca_rome"
    assert fb["codename"] == "CMC"
    assert fb["codename_display"] == "Comanche"
    assert fb["build_id"] == "00069"
    assert fb["chipset_source"] == "pf_field"
    assert fb["rom_revision"] == "0103"


def test_qca_rome_che_unsigned_banner(parser, tmp_path: Path) -> None:
    """BTFM.CHE.1.1.0-00027-QCACHROM-1 (no Z = unsigned) → Cherokee."""
    banner = "BTFM.CHE.1.1.0-00027-QCACHROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "crbtfw11.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.version == banner
    # No PF= field → fall back to codename map (CHE → wcn3990).
    assert result.chipset_target == "wcn3990"
    assert result.signed == "unsigned"
    fb = result.metadata["bt_fw_banner"]
    assert fb["codename"] == "CHE"
    assert fb["chipset_source"] == "codename_map"


def test_qca_rome_ci_prefix_dotted_build(parser, tmp_path: Path) -> None:
    """CI_BTFM.CHE.2.0.0-00076.1-QCACHROM-16 (CI build + dotted build)."""
    banner = "CI_BTFM.CHE.2.0.0-00076.1-QCACHROM-16"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "crbtfw20.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.version == banner
    fb = result.metadata["bt_fw_banner"]
    assert fb["ci_build"] is True
    assert fb["build_id"] == "00076.1"
    assert fb["patch_index"] == 16


def test_qca_rome_hastings_qca6390(parser, tmp_path: Path) -> None:
    """BTFM.HAS.2.0.0-00043-QCAHTROM-1 → Hastings / QCA6390."""
    banner = "BTFM.HAS.2.0.0-00043-QCAHTROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "htbtfw20.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.chipset_target == "qca6390"
    fb = result.metadata["bt_fw_banner"]
    assert fb["codename"] == "HAS"
    assert fb["codename_display"] == "Hastings"
    assert fb["rom_tag"] == "QCAHTROM"


def test_qca_rome_apache_wcn3988(parser, tmp_path: Path) -> None:
    """BTFM.APA.x.y.z-...-QCACHROM-N → Apache / WCN3988."""
    banner = "BTFM.APA.1.0.0-00007-QCACHROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "apbtfw10.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.chipset_target == "wcn3988"
    fb = result.metadata["bt_fw_banner"]
    assert fb["codename"] == "APA"


def test_qca_rome_moselle_wcn6750(parser, tmp_path: Path) -> None:
    """BTFM.MOS.x.y.z-...-QCAMTROM-N → Moselle / WCN6750."""
    banner = "BTFM.MOS.2.1.0-00027-QCAMTROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "msbtfw20.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.chipset_target == "wcn6750"
    fb = result.metadata["bt_fw_banner"]
    assert fb["codename"] == "MOS"
    assert fb["codename_display"] == "Moselle"
    assert fb["rom_tag"] == "QCAMTROM"


def test_qca_rome_pf_field_wins_over_codename_map(parser, tmp_path: Path) -> None:
    """When PF= and codename disagree, PF= is preferred (more specific)."""
    # PF=WCN3998 with codename CHE — codename map says wcn3990, PF= overrides.
    banner = "BTFM.CHE.3.0.0-00100-QCACHROMZ-1"
    pr = f"Patch Release PF=WCN3998ROM= 0200 BUILD={banner}"
    blob = _make_qca_tlv(banner, with_patch_release=pr)
    p = tmp_path / "crbtfw30.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.chipset_target == "wcn3998"
    fb = result.metadata["bt_fw_banner"]
    assert fb["chipset_source"] == "pf_field"


def test_qca_rome_braktooth_pin_wcn3950(parser, tmp_path: Path) -> None:
    """Tier 0 BRAKTOOTH DoS pin fires when banner confirms WCN3950.

    Important: CVE-2021-28139 (BrakTooth RCE) is NOT pinned — per NVD's
    CPE list it's ESP32-only. Reviewer B 2026-05-16 caught the original
    parser implementation would have shipped this as a false positive.
    """
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    known = result.metadata["known_vulnerabilities"]
    cve_ids = {v["cve_id"] for v in known}
    # Three DoS CVEs from the BrakTooth Qualcomm subset.
    assert "CVE-2021-34147" in cve_ids
    assert "CVE-2021-31609" in cve_ids
    assert "CVE-2021-31612" in cve_ids
    # CVE-2021-28139 is ESP32-only — must NOT be pinned.
    assert "CVE-2021-28139" not in cve_ids
    # All Tier 0 pins from this parser declare parser_version_pin source.
    for v in known:
        assert v["source"] == "parser_version_pin"
        assert v["confidence"] == "high"
        assert "BrakTooth" in v["rationale"]


def test_qca_rome_braktooth_no_esp32_rce_pin(parser, tmp_path: Path) -> None:
    """Explicit guard: CVE-2021-28139 (ESP32 RCE) is NEVER pinned by
    this parser on Qualcomm Rome banners, even on the chipsets that
    are otherwise BrakTooth-vulnerable.

    Reviewer B 2026-05-16 caught the original implementation included
    CVE-2021-28139 in _BRAKTOOTH_CVES — would have shipped ~18
    false-positive RCE-CVSS-8.8 sb_vuln rows per QCA-Rome firmware
    (replicating yesterday's BleedingTooth misattribution failure mode).
    """
    for banner in (
        "BTFM.CMC.1.3.0-00069-QCACHROMZ-1",
        "BTFM.CHE.2.0.0-00082-QCACHROMZ-1",
    ):
        blob = _make_qca_tlv(banner)
        p = tmp_path / f"{banner.split('.')[1].lower()}_test.tlv"
        n = _write(p, blob)
        result = parser.parse(str(p), _read_magic(p), n)
        kv = result.metadata.get("known_vulnerabilities", [])
        cve_ids = {v["cve_id"] for v in kv}
        assert "CVE-2021-28139" not in cve_ids, (
            f"banner {banner!r} should NOT pin CVE-2021-28139 — "
            f"that CVE is ESP32-only per NVD CPE list"
        )


def test_qca_rome_filename_content_mismatch_flagged(parser, tmp_path: Path) -> None:
    """When filename prefix (e.g. apbtfw*) disagrees with content
    codename (BTFM.CHE.*), the parser flags it as forensic-interest
    metadata. Real-world example: G32's apbtfw10.tlv contains a CHE
    banner (Reviewer B M2 2026-05-16)."""
    banner = "BTFM.CHE.2.0.0-00082-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    # Filename prefix `apbtfw` → expected codename APA; content says CHE
    p = tmp_path / "apbtfw10.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    fb = result.metadata["bt_fw_banner"]
    assert "filename_codename_mismatch" in fb
    mm = fb["filename_codename_mismatch"]
    assert mm["filename_codename"] == "APA"
    assert mm["content_codename"] == "CHE"
    assert mm["filename"] == "apbtfw10.tlv"
    # Content remains authoritative.
    assert fb["codename"] == "CHE"
    assert result.chipset_target == "wcn3990"


def test_qca_rome_filename_content_match_no_mismatch_flag(
    parser, tmp_path: Path
) -> None:
    """Matching filename + content → no mismatch flag emitted."""
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "cmbtfw13.tlv"  # cmbtfw → CMC, matches banner
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    fb = result.metadata["bt_fw_banner"]
    assert "filename_codename_mismatch" not in fb


def test_qca_rome_braktooth_pin_wcn3990(parser, tmp_path: Path) -> None:
    """BrakTooth DoS pin also fires for Cherokee → WCN3990."""
    banner = "BTFM.CHE.2.0.0-00082-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "crbtfw20.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    known = result.metadata.get("known_vulnerabilities", [])
    cve_ids = {v["cve_id"] for v in known}
    # 3 BrakTooth Qualcomm-DoS CVEs.
    assert "CVE-2021-34147" in cve_ids
    # CVE-2021-28139 is ESP32-only — must NOT fire on Qualcomm Rome.
    assert "CVE-2021-28139" not in cve_ids


def test_qca_rome_no_braktooth_pin_for_non_rome(parser, tmp_path: Path) -> None:
    """Hastings (QCA6390) should NOT get a BRAKTOOTH pin — different family."""
    banner = "BTFM.HAS.2.0.0-00043-QCAHTROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "htbtfw20.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert "known_vulnerabilities" not in result.metadata


def test_qca_rome_unknown_codename_keeps_vendor_no_chipset(
    parser, tmp_path: Path
) -> None:
    """Unrecognized codename: vendor=qualcomm but chipset_target=None."""
    banner = "BTFM.ZZZ.9.9.9-00001-QCACHROM-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "zzbtfw99.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
    assert result.chipset_target is None
    fb = result.metadata["bt_fw_banner"]
    assert fb["codename"] == "ZZZ"
    assert fb["chipset_source"] == "none"


# ---------------------------------------------------------------------------
# Broadcom HCD HCI command-stream parsing
# ---------------------------------------------------------------------------


def _make_bcm_hcd(*, chip: str = "BCM43455", include_brcm_cfg: bool = True) -> bytes:
    """Synthesize a minimal-valid Broadcom HCD file: one WRITE_RAM + LAUNCH_RAM."""
    # WRITE_RAM at addr 0x00219c00 with embedded BRCMcfgS payload + chip ID
    addr = struct.pack("<I", 0x00219C00)
    if include_brcm_cfg:
        payload = b"\x00\x00\x00\x00" + b"BRCMcfgS\x00" + b"\x00" * 10 + b"BRCMcfgD\x00"
        # Chip ID (NUL-terminated ASCII)
        payload += b"\x00" * 11 + chip.encode("ascii") + b" 37.4MHz Test\x00"
    else:
        payload = b"\x00" * 20
    # WRITE_RAM frame: opcode (0x4cfc LE) + plen + addr + payload
    body = addr + payload
    write_ram = b"\x4c\xfc" + bytes([len(body)]) + body
    # LAUNCH_RAM terminator: opcode (0x4efc LE) + plen=4 + 0xFFFFFFFF
    launch_ram = b"\x4e\xfc\x04\xff\xff\xff\xff"
    return write_ram + launch_ram


def test_broadcom_hcd_full_walk_passes(parser, tmp_path: Path) -> None:
    """Valid HCD stream walks cleanly + emits high-confidence verdict."""
    blob = _make_bcm_hcd(chip="BCM43455")
    p = tmp_path / "BCM43455.hcd"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "broadcom"
    assert result.chipset_target == "bcm43455"
    assert result.signed == "unsigned"
    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "broadcom_hcd"
    assert fb["confidence"] == "high"
    assert fb["brcm_cfg_tag"] is True
    walk = fb["hci_walk"]
    assert walk["commands"] == 2
    assert walk["write_ram"] == 1
    assert walk["launch_ram"] == 1


def test_broadcom_hcd_cyw_disambiguates_to_cypress(parser, tmp_path: Path) -> None:
    """CYW43xxx chipset → vendor=cypress (Cypress / Infineon AIROC)."""
    blob = _make_bcm_hcd(chip="CYW43455")
    p = tmp_path / "CYW43455.hcd"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "cypress"
    assert result.chipset_target == "cyw43455"


def test_broadcom_hcd_truncation_rejected(parser, tmp_path: Path) -> None:
    """Truncated HCD (no LAUNCH_RAM) → walker rejects.

    Without a BRCMcfg tag and without a successful walk, the parser
    falls through to the next family and ultimately returns the
    unknown-family record.
    """
    blob = _make_bcm_hcd(chip="BCM43455", include_brcm_cfg=False)
    truncated = blob[:-1]  # chop off last byte of LAUNCH_RAM
    p = tmp_path / "truncated.hcd"
    n = _write(p, truncated)

    result = parser.parse(str(p), _read_magic(p), n)

    # No BRCMcfg tag + walk failed → fall through to unknown family.
    assert result.vendor is None
    assert result.metadata["bt_fw_banner"]["family"] == "unknown"


def test_broadcom_hcd_qca_tlv_does_not_match(parser, tmp_path: Path) -> None:
    """A QCA TLV file must NOT be misclassified as Broadcom HCD.

    Specifically: the TLV starts with byte 0x01 (TLV_TYPE_PATCH), not
    0x4c — so the HCD walker's opcode check rejects it on the first
    instruction. The QCA branch fires first anyway via the banner regex.
    """
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "ambiguous.tlv"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    # Should land in QCA Rome, not Broadcom HCD.
    assert result.vendor == "qualcomm"
    assert result.metadata["bt_fw_banner"]["family"] == "qca_rome"


# ---------------------------------------------------------------------------
# MediaTek WMT btmtk_patch_header parsing
# ---------------------------------------------------------------------------


def _make_mtk_btmtk(*, datetime_ascii: str = "2024/06/15 12:30",
                    platform: str = "MT79",
                    hwver: int = 0x0001,
                    swver: int = 0x0002,
                    magicnum: int = 0x424D5443,
                    extra_payload: bytes = b"WMT_FW build patch\x00") -> bytes:
    """Synthesize a 32-byte btmtk_patch_header + optional BT marker payload.

    ``extra_payload`` is appended verbatim after the 64-byte global
    descriptor — pass marker tokens (``WMT_FW``, ``btmtk``, ``BT_FW``,
    ``bluetooth``) to drive the BT-vs-WiFi disambiguation gate, OR pass
    a non-marker trailer (e.g. ``b"calibration data"``) to exercise the
    "header passes but no marker" low-confidence path.
    """
    dt = datetime_ascii.encode("ascii").ljust(16, b"\x00")
    plat = platform.encode("ascii").ljust(4, b"\x00")
    hw = struct.pack("<H", hwver)
    sw = struct.pack("<H", swver)
    mag = struct.pack("<I", magicnum)
    # global_desc (64 bytes) — zero-padded for the test
    global_desc = b"\x00" * 64
    return dt + plat + hw + sw + mag + global_desc + extra_payload


def test_mediatek_bt_header_and_marker(parser, tmp_path: Path) -> None:
    """Valid btmtk_patch_header + BT marker → vendor=mediatek + chipset."""
    # Marker (WMT_FW) + known chip ID (MT7961) embedded in payload.
    extra = b"WMT_FW build patch\x00MT7961 chip\x00"
    blob = _make_mtk_btmtk(platform="7961", extra_payload=extra)
    p = tmp_path / "mt7961_patch_mcu_1a_2_hdr.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "mediatek"
    assert result.chipset_target == "mt7961"
    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "mediatek_bt"
    assert "WMT_FW" in fb["tag_hits"]
    assert "btmtk_header" in fb
    header = fb["btmtk_header"]
    assert header["platform_tag"] == "7961"
    assert header["hwver"] == "0x0001"
    assert header["swver"] == "0x0002"


def test_mediatek_bt_header_only_no_marker_is_low_confidence(
    parser, tmp_path: Path
) -> None:
    """Header passes but no BT marker → low confidence (could be WiFi firmware)."""
    # Calibration trailer with NO BT-marker tokens (no WMT/btmtk/BT_FW/bluetooth).
    blob = _make_mtk_btmtk(extra_payload=b"\x00calibration table\x00")
    p = tmp_path / "ambiguous_mtk.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "mediatek_bt"
    assert fb.get("confidence") == "low"
    assert fb.get("note", "").startswith("btmtk header gates passed")


def test_mediatek_bt_filename_chip_fallback(parser, tmp_path: Path) -> None:
    """Filename ``mt7922_*`` extracts chipset when content doesn't pin it."""
    # Header + WMT marker but no chip ID anywhere in content
    blob = _make_mtk_btmtk(platform="WLBT", extra_payload=b"WMT_PATCH\x00")
    p = tmp_path / "mt7922_patch_e2_hdr.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "mediatek"
    assert result.chipset_target == "mt7922"
    fb = result.metadata["bt_fw_banner"]
    assert fb["chipset_source"] == "filename"


# ---------------------------------------------------------------------------
# Negative cases — no banner / unknown family / short reads
# ---------------------------------------------------------------------------


def test_qca_nv_calibration_no_banner_returns_unknown(parser, tmp_path: Path) -> None:
    """NV calibration .bin files have NO banner — parser returns unknown family."""
    # Mimic the cmnv13.bin shape: arbitrary calibration bytes, no QCA banner,
    # no Broadcom magic, no MediaTek struct gates.
    blob = bytes(range(256)) * 4  # 1 KB of cycling bytes, no ASCII banners
    p = tmp_path / "cmnv13.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor is None
    assert result.version is None
    assert result.chipset_target is None
    fb = result.metadata["bt_fw_banner"]
    assert fb["family"] == "unknown"
    assert fb["checked"] is True


def test_empty_file_does_not_crash(parser, tmp_path: Path) -> None:
    p = tmp_path / "empty.bin"
    p.write_bytes(b"")

    result = parser.parse(str(p), b"", 0)

    # Parser returns ParsedBlob with error metadata; never raises.
    assert isinstance(result, ParsedBlob)
    assert "error" in result.metadata


def test_short_random_bytes_no_match(parser, tmp_path: Path) -> None:
    """16 random bytes shouldn't accidentally match any signature."""
    blob = bytes.fromhex("deadbeef" * 4)
    p = tmp_path / "short.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert isinstance(result, ParsedBlob)
    assert result.vendor is None
    assert result.metadata.get("bt_fw_banner", {}).get("family") == "unknown"


def test_parser_format_registered() -> None:
    """The parser must register itself under FORMAT = 'bt_fw_banner'."""
    p = get_parser("bt_fw_banner")
    assert p is not None
    assert p.FORMAT == "bt_fw_banner"


# ---------------------------------------------------------------------------
# ParsedBlob.vendor field contract
# ---------------------------------------------------------------------------


def test_parsed_blob_vendor_field_exists() -> None:
    """``ParsedBlob`` MUST have a ``vendor: str | None`` field.

    This pins the detector.py override contract — content-derived vendor
    beats classifier-derived vendor when populated.
    """
    blob = ParsedBlob()
    assert hasattr(blob, "vendor")
    assert blob.vendor is None
    blob.vendor = "qualcomm"
    assert blob.vendor == "qualcomm"


def test_parser_populates_vendor_for_qca_rome(parser, tmp_path: Path) -> None:
    """The classifier may say vendor=broadcom (yesterday's bug); the
    parser populates vendor=qualcomm from content evidence."""
    banner = "BTFM.CMC.1.3.0-00069-QCACHROMZ-1"
    blob = _make_qca_tlv(banner)
    p = tmp_path / "btfm.bin"
    n = _write(p, blob)

    result = parser.parse(str(p), _read_magic(p), n)

    assert result.vendor == "qualcomm"
