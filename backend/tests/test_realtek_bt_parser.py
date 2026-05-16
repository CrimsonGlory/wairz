"""Tests for the Realtek BT firmware family parser.

Per upstream Linux drivers/bluetooth/btrtl.h `rtl_epatch_header` (v1)
and `rtl_epatch_header_v2`:

  v1 (14-byte header):
    offset  0..7   "Realtech"     (8-byte magic; note "ch" spelling)
    offset  8..11  __le32 fw_version
    offset 12..13  __le16 num_patches

  v2 (20-byte header):
    offset  0..7   "RTBTCore"
    offset  8..15  __u8 fw_version[8]  (ASCII version string)
    offset 16..19  __le32 num_sections

  Both: project_id encoded as TLV records at the END of the file:
    reverse-scan for (opcode=0, length=1, data=project_id) record.

Scout C research 2026-05-18 confirmed the project_id offset claim in
the original prompt was WRONG (offset 8 is fw_version; project_id
lives in trailing TLV records). The parser implements the correct
shape.

Adaptability tests cover:
- All 6 chipset variants from the prompt (RTL8723D / RTL8761B /
  RTL8821C / RTL8852A / RTL8852B / RTL8852C)
- Both magic variants (Realtech v1 + RTBTCore v2)
- Soft "Realtek" / "REALTEK" ASCII fallback (vendor-modified builds)
- Magic at non-zero offset (downstream wrapper)
- project_id unknown to YAML (operator-supplied → MEDIUM confidence)
- File with NO Realtek evidence → parser returns None
- Classifier_pattern routing rtl*_fw.bin → bt_fw_banner format
"""

from __future__ import annotations

import struct

import pytest

from app.services.hardware_firmware import patterns_loader as PL
from app.services.hardware_firmware.parsers.bt_firmware_banner import (
    BtFirmwareBannerParser,
    _parse_realtek_bt,
    _scan_realtek_project_id_from_tail,
)


# ---------------------------------------------------------------------------
# Fixture helpers — synthesize the binary shapes the parser expects.
# ---------------------------------------------------------------------------


def _make_rtl_v1_header(
    fw_version: int = 0x12345678,
    num_patches: int = 3,
    *,
    magic: bytes = b"Realtech",
    prefix: bytes = b"",
) -> bytes:
    """Build a synthetic rtl_epatch_header v1 (14 bytes) with optional
    prefix that places the magic at a non-zero offset."""
    return prefix + magic + struct.pack("<I", fw_version) + struct.pack("<H", num_patches)


def _make_rtl_v2_header(
    fw_version: str = "8761b_v2",
    num_sections: int = 5,
    *,
    magic: bytes = b"RTBTCore",
    prefix: bytes = b"",
) -> bytes:
    """Build a synthetic rtl_epatch_header v2 (20 bytes)."""
    ver_bytes = fw_version.encode("ascii")[:8].ljust(8, b"\x00")
    return prefix + magic + ver_bytes + struct.pack("<I", num_sections)


def _make_project_id_tlv(project_id: int) -> bytes:
    """Build a (data, length=1, opcode=0) tail TLV that the parser's
    reverse-scan will pick up as project_id.

    Reverse-scan order: byte[i] is opcode, byte[i-1] is length,
    byte[i-2..i-1-length] is data.
    """
    # Bytes appear data-first, then length, then opcode; scanner walks
    # right-to-left so the LAST byte must be the opcode (0).
    return bytes([project_id, 1, 0])


def _make_realtek_fixture(
    project_id: int,
    *,
    version: str = "v1",
    fw_version: int = 0x12345678,
    fw_version_str: str = "v1.0",
    magic_offset: int = 0,
    tail_padding: int = 64,
) -> tuple[bytes, bytes, int]:
    """Build (head, tail, total_size) for a Realtek BT fixture.

    Returns the head + tail buffers as the parser would receive them
    after the 4 KB / 8 KB read windows.
    """
    if version == "v1":
        header = _make_rtl_v1_header(
            fw_version=fw_version,
            prefix=b"\x00" * magic_offset,
        )
    else:
        header = _make_rtl_v2_header(
            fw_version=fw_version_str,
            prefix=b"\x00" * magic_offset,
        )

    # Pad head out to 4 KB to simulate full window.
    head = header + b"\x00" * (4096 - len(header))

    tail = b"\x00" * tail_padding + _make_project_id_tlv(project_id)
    # Pad tail out to 8 KB to simulate full window.
    if len(tail) < 8192:
        tail = b"\x00" * (8192 - len(tail)) + tail

    total_size = len(head) + len(tail)  # close enough — parser doesn't
                                        # use size beyond cap checks
    return head, tail, total_size


# ---------------------------------------------------------------------------
# Tail TLV scanner — load-bearing for project_id extraction.
# ---------------------------------------------------------------------------


def test_scan_realtek_project_id_basic() -> None:
    """Standalone TLV scan: (data=14, length=1, opcode=0) → 14."""
    tail = b"\x00" * 32 + bytes([14, 1, 0])
    assert _scan_realtek_project_id_from_tail(tail) == 14


def test_scan_realtek_project_id_with_intermediate_tlv() -> None:
    """Scanner walks past other TLVs and stops at the project_id TLV."""
    # Build a tail with: other TLV first (opcode=0x10, length=3, 3 data
    # bytes), THEN the project_id TLV. Walking right-to-left, the
    # scanner hits project_id first.
    tail = (
        b"\x00" * 16
        + bytes([0xAA, 0xBB, 0xCC])  # data bytes for the other TLV
        + bytes([3, 0x10])              # length=3, opcode=0x10 (skip)
        + bytes([25, 1, 0])             # data=25, length=1, opcode=0 → project_id
    )
    assert _scan_realtek_project_id_from_tail(tail) == 25


def test_scan_realtek_project_id_stops_at_eof_marker() -> None:
    """opcode=0xFF is the EOF marker; scanner returns None when reached."""
    tail = b"\x00" * 16 + bytes([0xFF])
    assert _scan_realtek_project_id_from_tail(tail) is None


def test_scan_realtek_project_id_returns_none_on_too_short_tail() -> None:
    assert _scan_realtek_project_id_from_tail(b"") is None
    assert _scan_realtek_project_id_from_tail(b"\x00") is None


# ---------------------------------------------------------------------------
# All 6 chipset variants from the prompt — each must round-trip.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "project_id,expected_chipset,expected_lmp",
    [
        (9, "rtl8723d", 0x8723),
        (14, "rtl8761b", 0x8761),
        (10, "rtl8821c", 0x8821),
        (18, "rtl8852a", 0x8852),
        (20, "rtl8852b", 0x8852),
        (25, "rtl8852c", 0x8852),
    ],
)
def test_realtek_parser_classifies_all_prompt_chipsets(
    project_id: int, expected_chipset: str, expected_lmp: int
) -> None:
    """Each of the prompt-named Realtek chipsets must round-trip through
    parser: project_id TLV → chipset name + LMP subver from YAML."""
    head, tail, size = _make_realtek_fixture(project_id, version="v1")
    rec = _parse_realtek_bt(head, tail, f"/tmp/{expected_chipset}_fw.bin", size)
    assert rec is not None
    assert rec["family"] == "realtek_bt"
    assert rec["vendor"] == "realtek"
    assert rec["chipset_target"] == expected_chipset
    assert rec["chipset_source"] == "project_id_tlv"
    assert rec["project_id"] == project_id
    assert rec["confidence"] == "high"
    assert rec["lmp_subver"] == f"0x{expected_lmp:04x}"
    assert rec["header_version"] == "v1"
    assert rec["magic_offset"] == 0


# ---------------------------------------------------------------------------
# v2 (RTBTCore) header support.
# ---------------------------------------------------------------------------


def test_realtek_parser_handles_v2_rtbtcore_header() -> None:
    """v2 header with ASCII fw_version + project_id TLV."""
    # RTL8852C uses the v2 header in real linux-firmware blobs
    # (rtl8852cu_fw_v2.bin).
    head, tail, size = _make_realtek_fixture(
        25, version="v2", fw_version_str="2.2.0a"
    )
    rec = _parse_realtek_bt(head, tail, "/tmp/rtl8852cu_fw_v2.bin", size)
    assert rec is not None
    assert rec["header_version"] == "v2"
    assert rec["chipset_target"] == "rtl8852c"
    assert rec["confidence"] == "high"
    assert "2.2.0a" in (rec.get("fw_version") or "")
    assert rec["num_sections"] is not None


# ---------------------------------------------------------------------------
# Adaptability — non-canonical placement + soft Realtek ASCII fallback.
# ---------------------------------------------------------------------------


def test_realtek_parser_accepts_magic_at_non_zero_offset() -> None:
    """A small wrapper preamble before the magic still parses → MEDIUM
    confidence (HIGH only when magic at offset 0)."""
    head, tail, size = _make_realtek_fixture(14, magic_offset=16)
    rec = _parse_realtek_bt(head, tail, "/tmp/rtl8761b_wrapped.bin", size)
    assert rec is not None
    assert rec["family"] == "realtek_bt"
    assert rec["chipset_target"] == "rtl8761b"
    assert rec["magic_offset"] == 16
    # Magic at non-zero offset + project_id known → MEDIUM (the gating
    # ladder: high requires magic@0 AND chipset).
    assert rec["confidence"] == "medium"


def test_realtek_parser_soft_realtek_ascii_fallback_low_confidence() -> None:
    """Soft fallback: a blob with 'Realtek' ASCII anywhere in head but
    no canonical Realtech/RTBTCore magic → LOW confidence, vendor stamped."""
    head = b"\x00" * 8 + b"Vendor: Realtek Semiconductor\n" + b"\x00" * 4000
    tail = b"\x00" * 8192
    rec = _parse_realtek_bt(head, tail, "/tmp/vendor_modified.bin", 12288)
    assert rec is not None
    assert rec["family"] == "realtek_bt"
    assert rec["vendor"] == "realtek"
    assert rec["confidence"] == "low"
    assert rec["chipset_target"] is None
    # The soft path emits a "note" field documenting why confidence is low.
    assert "note" in rec


@pytest.mark.parametrize(
    "casing",
    ["Realtek", "REALTEK", "realtek", "RealTek", "REALTeC", "Realtec"],
)
def test_realtek_soft_fallback_accepts_case_variants(casing: str) -> None:
    """The soft regex accepts case variants of 'realte[ck]' for
    vendor-modified blobs. Magic must land in the first 64 bytes of
    head (the soft-scan window matches the canonical scan window)."""
    # Place the casing string at offset 8 — well within the 64-byte
    # head-scan window the soft regex inspects.
    head = b"\x00" * 8 + casing.encode("ascii") + b"\x00" * 4000
    tail = b"\x00" * 8192
    rec = _parse_realtek_bt(head, tail, f"/tmp/{casing.lower()}_fw.bin", 12288)
    assert rec is not None
    assert rec["vendor"] == "realtek"


# ---------------------------------------------------------------------------
# Unknown project_id — operator extension story.
# ---------------------------------------------------------------------------


def test_realtek_parser_unknown_project_id_medium_confidence() -> None:
    """A project_id outside the YAML map (e.g. future chipset) → still
    emits vendor=realtek with MEDIUM confidence (operator can extend
    bt_realtek_project_ids.yaml without Python change to get HIGH)."""
    head, tail, size = _make_realtek_fixture(99, version="v1")  # not in YAML
    rec = _parse_realtek_bt(head, tail, "/tmp/rtl_future_fw.bin", size)
    assert rec is not None
    assert rec["family"] == "realtek_bt"
    assert rec["vendor"] == "realtek"
    assert rec["project_id"] == 99
    assert rec["chipset_target"] is None
    assert rec["chipset_source"] == "none"
    # Magic at offset 0 but chipset unknown → MEDIUM confidence.
    assert rec["confidence"] == "medium"


# ---------------------------------------------------------------------------
# Negative cases — non-Realtek inputs return None.
# ---------------------------------------------------------------------------


def test_realtek_parser_returns_none_on_non_realtek_input() -> None:
    head = b"BTFM.CMC.1.0.0-00001-QCACHROMZ-1" + b"\x00" * 4000
    tail = b"\x00" * 8192
    assert _parse_realtek_bt(head, tail, "/tmp/qca_btfm.bin", 12288) is None


def test_realtek_parser_returns_none_on_empty() -> None:
    assert _parse_realtek_bt(b"", b"", "/tmp/empty", 0) is None


# ---------------------------------------------------------------------------
# Patterns_loader contract — Realtek YAML hot-reload.
# ---------------------------------------------------------------------------


def test_realtek_yaml_loaded_has_all_prompt_chipsets() -> None:
    """The shipped YAML must cover all 6 chipsets from the prompt."""
    chipsets = PL.get_realtek_chipsets()
    project_ids = {c.project_id for c in chipsets}
    # All 6 chipsets from the prompt:
    assert 9 in project_ids  # RTL8723D
    assert 14 in project_ids  # RTL8761B
    assert 10 in project_ids  # RTL8821C
    assert 18 in project_ids  # RTL8852A
    assert 20 in project_ids  # RTL8852B
    assert 25 in project_ids  # RTL8852C


def test_realtek_yaml_uniqueness_invariant() -> None:
    """No duplicate project_ids in the shipped YAML — loader rejects
    duplicates at parse time so this is a regression guard."""
    chipsets = PL.get_realtek_chipsets()
    project_ids = [c.project_id for c in chipsets]
    assert len(project_ids) == len(set(project_ids))


def test_realtek_yaml_lookup_returns_entry() -> None:
    entry = PL.get_realtek_chipset_by_project_id(14)
    assert entry is not None
    assert entry.chipset == "rtl8761b"
    assert entry.lmp_subver == 0x8761


def test_realtek_yaml_lookup_unknown_returns_none() -> None:
    assert PL.get_realtek_chipset_by_project_id(99) is None


# ---------------------------------------------------------------------------
# realtek_bt family registered in _BT_PARSER_FAMILIES (operators can
# author CVE pins under family: realtek_bt now).
# ---------------------------------------------------------------------------


def test_realtek_bt_family_registered_in_parser_families() -> None:
    """patterns_loader._BT_PARSER_FAMILIES must include realtek_bt so
    bt_banner_cve_pins.yaml authors can write `family: realtek_bt`."""
    assert "realtek_bt" in PL._BT_PARSER_FAMILIES


def test_bt_parser_families_stay_in_sync_with_public_tuple() -> None:
    """Reviewer C C1+C3 (2026-05-15) cross-stack alignment canary —
    the hard-coded ``patterns_loader._BT_PARSER_FAMILIES`` validation
    set MUST stay in sync with the public
    ``parsers.bt_firmware_banner.BT_PARSER_FAMILIES`` tuple (the
    source of truth surfaced by the ``list_extension_points`` MCP
    tool).

    Drift here means: (a) a new BT family added to the parser tuple
    silently rejects YAML pins that reference it (the validation gate
    in _parse_banner_cve_pin doesn't know about the new family); or
    (b) the MCP tool reports a family that the YAML schema rejects.

    Future contributors adding a 5th BT family parser MUST update
    BOTH bt_firmware_banner.BT_PARSER_FAMILIES AND patterns_loader.
    _BT_PARSER_FAMILIES (or refactor to a runtime-derived shape; a
    lazy-init wrapper avoids the circular import between the two
    modules but is heavier than the test-time alignment check).

    Pairs with the existing test that asserts realtek_bt is present.
    """
    from app.services.hardware_firmware.parsers.bt_firmware_banner import (
        BT_PARSER_FAMILIES,
    )
    public_families = frozenset(
        entry["family"] for entry in BT_PARSER_FAMILIES
    )
    assert PL._BT_PARSER_FAMILIES == public_families, (
        f"BT parser-family sets drifted between patterns_loader._BT_"
        f"PARSER_FAMILIES ({sorted(PL._BT_PARSER_FAMILIES)}) and "
        f"parsers.bt_firmware_banner.BT_PARSER_FAMILIES "
        f"({sorted(public_families)}). Update both modules together "
        f"or refactor to a lazy-init wrapper."
    )


# ---------------------------------------------------------------------------
# Classifier_pattern — rtl87XX_fw.bin routes to bt_fw_banner format.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "filename",
    [
        "rtl8761b_fw.bin",
        "rtl8761bu_fw.bin",
        "rtl8723d_fw.bin",
        "rtl8723ds_fw.bin",
        "rtl8821c_fw.bin",
        "rtl8821cs_fw.bin",
        "rtl8852au_fw.bin",
        "rtl8852bu_fw.bin",
        "rtl8852cu_fw.bin",
        "rtl8852cu_fw_v2.bin",
        "rtl8852btu_fw.bin",
        "rtl8851bu_fw.bin",
        "rtl8922au_fw.bin",
    ],
)
def test_realtek_bt_classifier_pattern_routes_to_bt_fw_banner(filename: str) -> None:
    """Classifier patterns must route Realtek BT firmware filenames to
    the bt_fw_banner format so BtFirmwareBannerParser picks them up."""
    m = PL.match(filename)
    assert m is not None, f"{filename} unclassified"
    assert m.vendor == "realtek"
    assert m.category == "bluetooth"
    assert m.format == "bt_fw_banner"


def test_realtek_config_pattern_does_not_route_to_parser() -> None:
    """Realtek BT companion config files (_config.bin) carry UART
    init parameters — NOT firmware. They classify as bluetooth but
    NOT format=bt_fw_banner (no parser needed)."""
    m = PL.match("rtl8761b_config.bin")
    assert m is not None
    assert m.vendor == "realtek"
    assert m.category == "bluetooth"
    assert m.format != "bt_fw_banner"


# ---------------------------------------------------------------------------
# End-to-end: BtFirmwareBannerParser dispatches to _parse_realtek_bt
# when the file looks Realtek-shaped.
# ---------------------------------------------------------------------------


def test_bt_parser_dispatches_to_realtek_on_realtech_magic(tmp_path) -> None:
    """Drop a synthetic Realtek fixture on disk, invoke the parser
    via the BtFirmwareBannerParser instance, confirm vendor=realtek
    in the ParsedBlob."""
    fixture_path = tmp_path / "rtl8761b_fw.bin"
    head, tail, size = _make_realtek_fixture(14, version="v1")
    # Concatenate head + tail with a gap so the file size > head size
    # (parser reads head AND tail windows separately).
    fixture_bytes = head + b"\x00" * 16384 + tail
    fixture_path.write_bytes(fixture_bytes)

    parser = BtFirmwareBannerParser()
    result = parser.parse(
        str(fixture_path), magic=fixture_bytes[:16], size=len(fixture_bytes)
    )
    assert result is not None
    assert result.vendor == "realtek"
    assert result.chipset_target == "rtl8761b"
    assert result.metadata.get("bt_fw_banner", {}).get("family") == "realtek_bt"
