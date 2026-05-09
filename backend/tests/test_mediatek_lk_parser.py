"""Regression tests for the MediaTek LK / GFH parser.

Covers:

- Compact (16-byte) vs legacy (512-byte) layout dispatch
- Partition name → (category, component) table
- Stub-descriptor detection for modem-less SKUs (the 528-byte `md1rom`
  case that used to emit `partition_size: 1.9 GB` nonsense)
- Classifier dispatch of LK blobs to their correct Wairz category
  (`atf` → tee, `cam_vpu1` → camera, `md1rom` → modem, etc.)
- NVD subcomponent extractor (`"In geniezone, ..."` → `"geniezone"`)
"""

from __future__ import annotations

import struct
from pathlib import Path

import pytest

from app.services.hardware_firmware.classifier import classify
from app.services.hardware_firmware.cve_matcher import extract_subcomponent
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    derive_chipset,
    is_stub_descriptor,
    lookup_partition,
    parse_lk_header,
)
from app.services.hardware_firmware.parsers.mediatek_lk import MediatekLkParser

_LK_MAGIC = 0x58881688
_LK_FILE_INFO_MAGIC = 0x58891689


def _compact_header(name: str, file_info_offset: int = 0x1000) -> bytes:
    """Build a compact 16-byte LK header with the given name."""
    name_bytes = name.encode("ascii").ljust(8, b"\x00")[:8]
    header = struct.pack("<II", _LK_MAGIC, file_info_offset) + name_bytes
    # Pad to 64 bytes (what the classifier sees) with the LK_FILE_INFO
    # marker at 0x30 to look like a real blob.
    padding = b"\x00" * (0x30 - len(header))
    fi_marker = struct.pack("<I", _LK_FILE_INFO_MAGIC)
    return header + padding + fi_marker + b"\x00" * 12


def _legacy_header(name: str) -> bytes:
    """Build a 512-byte legacy LK header with the 32-byte name at 0x20."""
    header = struct.pack("<III", _LK_MAGIC, 0x200, 1024) + b"\x00" * 4  # magic/fio/size/ver
    header = header.ljust(0x20, b"\x00")
    header += name.encode("ascii").ljust(32, b"\x00")
    header += b"\x00" * (512 - len(header))
    return header


# ─── Header parsing ───────────────────────────────────────────────────

class TestParseLkHeader:
    def test_compact_extracts_name(self):
        hdr = parse_lk_header(_compact_header("cam_vpu1"))
        assert hdr is not None
        assert hdr.name == "cam_vpu1"
        assert hdr.layout == "compact"
        assert hdr.has_file_info_magic

    def test_compact_short_name(self):
        hdr = parse_lk_header(_compact_header("lk"))
        assert hdr.name == "lk"
        assert hdr.layout == "compact"

    def test_legacy_extracts_name(self):
        hdr = parse_lk_header(_legacy_header("md1img"))
        assert hdr.name == "md1img"
        assert hdr.layout == "legacy"

    def test_bad_magic_returns_none(self):
        garbage = b"\x00" * 64
        assert parse_lk_header(garbage) is None

    def test_truncated_returns_none(self):
        assert parse_lk_header(b"\x88\x16\x88\x58") is None

    def test_md1rom_stub_real_bytes(self):
        """Reproduces the exact bytes observed on the DPCS10 modem.img
        (528-byte scatter-config stub)."""
        raw = bytes.fromhex(
            "88168858"           # LK magic
            "01000000"           # file_info_offset = 1 (sentinel / stub)
            "6d643172" "6f6d0000"  # "md1rom\x00\x00"
            + "00" * 32          # pad to 0x2C
            + "ffffffff"         # 4 bytes 0xff before the file-info magic
            + "89168958"         # LK_FILE_INFO magic at 0x30
            + "00" * 12
        )
        hdr = parse_lk_header(raw)
        assert hdr is not None
        assert hdr.name == "md1rom"
        assert hdr.layout == "compact"
        assert hdr.file_info_offset == 1  # faithfully reflects the stub


# ─── Partition-name lookup ────────────────────────────────────────────

class TestLookupPartition:
    @pytest.mark.parametrize("name,expected", [
        ("lk",       ("bootloader", "lk")),
        ("lk_a",     ("bootloader", "lk")),
        ("atf",      ("tee", "atf")),
        ("gz",       ("tee", "geniezone")),
        ("tee1",     ("tee", "tee")),
        ("scp",      ("mcu", "tinysys")),
        ("sspm",     ("mcu", "tinysys")),
        ("spmfw",    ("mcu", "spmfw")),
        ("cam_vpu1", ("camera", "cam_vpu")),
        ("cam_vpu2", ("camera", "cam_vpu")),
        ("md1rom",   ("modem", "modem")),
        ("md1dsp",   ("modem", "modem_dsp")),
        ("md1img",   ("modem", "modem")),
        ("logo",     ("display", "logo")),
    ])
    def test_known_names(self, name, expected):
        assert lookup_partition(name) == expected

    def test_unknown_name_returns_none(self):
        assert lookup_partition("not_a_real_partition") is None

    def test_empty_name_returns_none(self):
        assert lookup_partition("") is None

    def test_tinysys_prefix_match(self):
        """Newer bundles use `tinysys-scp`, `tinysys-sspm` as the compact name."""
        assert lookup_partition("tinysys-scp") == ("mcu", "tinysys")


# ─── Chipset derivation ──────────────────────────────────────────────

class TestDeriveChipset:
    """Chipset extraction from MTK parser metadata.

    Drives the curated_yaml chipset_regex matcher — without a populated
    chipset_target, every yaml entry with chipset_regex silently skips.
    """

    def test_mt6771_from_platform_tree(self):
        # tinysys/SCP path observed on DPCS10 (Genio 700 / MT6771 era)
        meta = {"platform_tree": "project/CM4_A/mt6771/"}
        assert derive_chipset(meta) == "mt6771"

    def test_mt8788_from_aiot_board_tag(self):
        # DPCS10 board_tag — only chipset signal on SPMFW/SSPM blobs
        meta = {"board_tag": "aiot8788ep1_64_bsp_k66"}
        assert derive_chipset(meta) == "mt8788"

    def test_explicit_mt_takes_precedence_over_aiot(self):
        # When both signals are present, the explicit ``mt\d+`` token wins
        meta = {
            "platform_tree": "plat/mediatek/mt6989/",
            "board_tag": "aiot8788ep1",
        }
        assert derive_chipset(meta) == "mt6989"

    def test_uppercase_normalised(self):
        meta = {"platform_tree": "MT8195_PROJ/CM4_A/"}
        assert derive_chipset(meta) == "mt8195"

    def test_no_hint_returns_none(self):
        meta = {"runtime": "freertos", "component": "scp"}
        assert derive_chipset(meta) is None

    def test_empty_metadata_returns_none(self):
        assert derive_chipset({}) is None

    def test_non_string_values_ignored(self):
        # Sub-image lists, version numbers etc. shouldn't crash the scan
        meta = {
            "sub_images": [{"name": "tinysys-scp", "size": 100}],
            "vector_msp": 0x000302E8,
            "platform_tree": "project/CM4_A/mt6771/",
        }
        assert derive_chipset(meta) == "mt6771"

    def test_word_boundary_avoids_false_positives(self):
        # `kmtxxx` or `format=mt` shouldn't match — needs word boundary
        meta = {"runtime": "tinysys_rtos", "note": "format mtfoo"}
        assert derive_chipset(meta) is None


# ─── Stub detection ───────────────────────────────────────────────────

class TestStubDescriptor:
    def test_md1rom_tiny_is_stub(self):
        assert is_stub_descriptor("md1rom", 528) is True

    def test_md1dsp_tiny_is_stub(self):
        assert is_stub_descriptor("md1dsp", 2048) is True

    def test_real_modem_image_not_stub(self):
        assert is_stub_descriptor("md1img", 50 * 1024 * 1024) is False

    def test_lk_not_stub(self):
        assert is_stub_descriptor("lk", 996 * 1024) is False

    def test_empty_name_not_stub(self):
        assert is_stub_descriptor("", 0) is False


# ─── Classifier integration ───────────────────────────────────────────

class TestClassifierDispatch:
    """Verifies the classifier no longer lumps every LK blob into bootloader."""

    def _classify(self, name: str) -> tuple[str, str, str]:
        magic = _compact_header(name)
        cls = classify(f"/tmp/{name}.img", magic, size=1024)
        assert cls is not None
        return (cls.category, cls.vendor, cls.format)

    def test_lk_stays_bootloader(self):
        assert self._classify("lk") == ("bootloader", "mediatek", "mtk_lk")

    def test_atf_becomes_tee(self):
        # Phase C: atf now routes to the role-specific mtk_atf parser.
        assert self._classify("atf") == ("tee", "mediatek", "mtk_atf")

    def test_gz_becomes_tee(self):
        assert self._classify("gz") == ("tee", "mediatek", "mtk_geniezone")

    def test_cam_vpu1_becomes_camera(self):
        # No role-specific parser for camera yet; stays on mtk_lk.
        assert self._classify("cam_vpu1") == ("camera", "mediatek", "mtk_lk")

    def test_md1rom_becomes_modem(self):
        assert self._classify("md1rom") == ("modem", "mediatek", "mtk_lk")

    def test_scp_becomes_mcu(self):
        # SCP is a Cortex-M4 system controller, not a DSP.  Categorized
        # as ``mcu`` so it buckets with sspm/spmfw/mcupm/dpm.
        assert self._classify("scp") == ("mcu", "mediatek", "mtk_tinysys")

    def test_spmfw_becomes_mcu(self):
        assert self._classify("spmfw") == ("mcu", "mediatek", "mtk_tinysys")


# ─── Parser metadata sanity (no more 1.9GB nonsense) ──────────────────

class TestParserMetadata:
    def test_compact_does_not_emit_legacy_fields(self, tmp_path: Path):
        """Compact-layout files must NOT get `partition_size` or
        `magic_version` keys in metadata (those are legacy-only struct
        offsets that happen to land inside the name string on compact)."""
        path = tmp_path / "md1rom"
        path.write_bytes(_compact_header("md1rom") + b"\x00" * 464)
        parser = MediatekLkParser()
        result = parser.parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["layout"] == "compact"
        assert md["partition_name"] == "md1rom"
        assert "partition_size" not in md
        assert "magic_version" not in md

    def test_md1rom_tiny_flagged_as_stub(self, tmp_path: Path):
        path = tmp_path / "modem.img"
        path.write_bytes(_compact_header("md1rom") + b"\x00" * 464)  # 528 B
        parser = MediatekLkParser()
        result = parser.parse(str(path), magic=b"", size=path.stat().st_size)
        assert result.metadata.get("stub_descriptor") is True
        assert "Partition placeholder" in result.metadata.get("note", "")

    def test_large_cam_vpu1_not_stub(self, tmp_path: Path):
        path = tmp_path / "cam_vpu1.img"
        path.write_bytes(_compact_header("cam_vpu1") + b"\x00" * (1024 * 1024))
        parser = MediatekLkParser()
        result = parser.parse(str(path), magic=b"", size=path.stat().st_size)
        assert result.metadata.get("stub_descriptor") is not True
        assert result.metadata["partition_name"] == "cam_vpu1"
        assert result.metadata["component"] == "cam_vpu"


# ─── NVD subcomponent extractor ───────────────────────────────────────

class TestExtractSubcomponent:
    @pytest.mark.parametrize("description,expected", [
        ("In geniezone, there is a possible use after free ...", "geniezone"),
        ("In atf, there is a possible information disclosure ...", "atf"),
        ("In wlan service, there is a possible OOB write ...", "wlan"),
        ("In modem, there is a buffer overflow ...", "modem"),
    ])
    def test_matches_mtk_bulletin_format(self, description, expected):
        assert extract_subcomponent(description) == expected

    def test_returns_none_on_unrelated_format(self):
        assert extract_subcomponent("A flaw was found in the Linux kernel...") is None

    def test_empty_returns_none(self):
        assert extract_subcomponent("") is None
