"""Regression tests for Phase C MediaTek subsystem parsers.

Covers:
- Sub-image walker (LK container ``[primary, cert2, (secondary, cert2)]``)
- ATF parser: MTK TEE wrapper strip + TF-A banner extraction
- GenieZone parser: ``GZ_hypervisor`` banner + CVE-2025-20707 fingerprint
- tinysys parser: Cortex-M vector-table validation, FreeRTOS detection,
  SPMFW "2MPS" PCM microcode detection, SSPM segment-chain recognition
- Classifier dispatch (atf → mtk_atf, gz → mtk_geniezone, scp → mtk_tinysys)
"""

from __future__ import annotations

import struct

from app.services.hardware_firmware.classifier import classify
from app.services.hardware_firmware.parsers.mediatek_atf import MediatekAtfParser
from app.services.hardware_firmware.parsers.mediatek_geniezone import (
    MediatekGenieZoneParser,
    _is_vulnerable_20707,
    _parse_built_date,
)
from app.services.hardware_firmware.parsers.mediatek_gfh import (
    walk_sub_images,
)
from app.services.hardware_firmware.parsers.mediatek_tinysys import MediatekTinysysParser

_LK_MAGIC = 0x58881688
_LK_FILE_INFO_MAGIC = 0x58891689
_HEADER = 0x200


def _make_lk_header(name: str, payload_size: int) -> bytes:
    """Build a 512-byte LK container header (compact layout)."""
    header = bytearray(_HEADER)
    struct.pack_into("<II", header, 0, _LK_MAGIC, payload_size)
    name_bytes = name.encode("ascii").ljust(32, b"\x00")[:32]
    header[0x08:0x08 + 32] = name_bytes
    struct.pack_into("<I", header, 0x30, _LK_FILE_INFO_MAGIC)
    # 0xFF padding from 0x48 onwards mimics the real layout
    for i in range(0x48, _HEADER):
        header[i] = 0xFF
    return bytes(header)


def _build_container(payloads: list[tuple[str, bytes]]) -> bytes:
    """Build a full LK container with N sub-images. Each sub-image gets
    a trailing 0x3F0-byte ``cert2`` signature so the walker sees the
    real-world pattern."""
    out = bytearray()
    for name, data in payloads:
        out += _make_lk_header(name, len(data)) + data
        # Align to 16
        pad = (-len(out)) & 0xF
        out += b"\x00" * pad
        cert = b"\x00" * 0x3F0
        out += _make_lk_header("cert2", len(cert)) + cert
        pad = (-len(out)) & 0xF
        out += b"\x00" * pad
    return bytes(out)


# ─── Sub-image walker ─────────────────────────────────────────────────

class TestSubImageWalker:
    def test_single_payload_with_cert(self):
        container = _build_container([("lk", b"\x00" * 1024)])
        subs = walk_sub_images(container)
        assert len(subs) == 2
        assert subs[0].name == "lk"
        assert subs[0].is_signature is False
        assert subs[0].payload_size == 1024
        assert subs[0].payload_offset == _HEADER
        assert subs[1].name == "cert2"
        assert subs[1].is_signature is True

    def test_tee_img_layout(self):
        """Real tee.img shape: atf + cert2 + atf_dram + cert2."""
        container = _build_container([
            ("atf", b"\xAA" * 0x13C00),
            ("atf_dram", b"\xBB" * 0x11E00),
        ])
        subs = walk_sub_images(container)
        names = [s.name for s in subs]
        assert names == ["atf", "cert2", "atf_dram", "cert2"]
        real = [s for s in subs if not s.is_signature]
        assert len(real) == 2
        assert real[0].payload_size == 0x13C00
        assert real[1].payload_size == 0x11E00

    def test_empty_returns_empty(self):
        assert walk_sub_images(b"") == []

    def test_non_magic_returns_empty(self):
        assert walk_sub_images(b"\x00" * 1024) == []

    def test_safety_cap(self):
        """Defensive cap: hand-crafted pathological input doesn't loop."""
        # A container whose size field points back to itself would loop.
        # walk_sub_images caps iterations at 16.
        bad = _make_lk_header("lk", 0) * 32
        subs = walk_sub_images(bad)
        assert len(subs) <= 16


# ─── ATF parser ───────────────────────────────────────────────────────

class TestAtfParser:
    def test_tfa_banner_extraction(self, tmp_path):
        """Banner + git hash + build date extracted from raw payload."""
        banner = (
            b"BL31: v1.3(debug):0cf92e67769\x00\x00"
            b"BL31: Built : 16:06:49, Apr 13 2026\x00\x00"
            b"plat/mediatek/mt6771/bl31_plat_setup.c\x00"
        )
        # MTK ATF inner wrapper (0x240 bytes of zeros after the magic)
        mtk_tee_wrapper = (
            b"\x45\x45\x54\x20\x4B\x54\x4D\x20"  # "MTK TEE " word-swapped
            + b"\x40\x02\x00\x00"                # header_size 0x240
            + b"\x00" * 0x234                    # rest of wrapper
        )
        payload = mtk_tee_wrapper + banner + b"\x00" * 1024
        container = _build_container([("atf", payload)])
        path = tmp_path / "tee.img"
        path.write_bytes(container)

        result = MediatekAtfParser().parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["component"] == "atf"
        assert md["runtime"] == "arm_trusted_firmware"
        assert md["inner_wrapper"] == "mtk_tee"
        assert result.version and "v1.3" in result.version
        assert md["tfa_git_hash"] == "0cf92e67769"
        assert "Apr 13 2026" in md["build_date"]
        assert md["platform_tree"] == "mt6771"
        # Ghidra params present
        gp = md["ghidra_import_params"]
        assert gp["processor"] == "AARCH64:LE:64:v8A"
        assert gp["base_addr"] == 0x54600000
        # load_offset skips both the LK container (0x200) AND the MTK TEE
        # wrapper (0x240) so the code starts at byte 0.
        assert gp["load_offset_in_file"] == _HEADER + 0x240


# ─── GenieZone parser ─────────────────────────────────────────────────

class TestGenieZoneParser:
    def _make_gz_container(self, version: str, built_str: str) -> bytes:
        banner = (
            f"GZ_hypervisor: {version}.V0MP1, Built: {built_str}\x00"
            f"GZ_CORE_hypervisor: {version}.V0MP1, Built: 09:56:19 Nov  4 2025\x00"
            f"mTEE_SDK: 2.2.2.000.U0TRUNK, Built: 09:56:26 Nov  4 2025\x00"
            f"vendor/mediatek/geniezone/platform/common/platform_common.c\x00"
        ).encode("ascii")
        payload = b"\x00" * 0x100 + banner + b"\x00" * 1024
        return _build_container([("gz", payload)])

    def test_banner_extraction(self, tmp_path):
        container = self._make_gz_container("3.2.1.004", "17:57:43 Dec 12 2025")
        path = tmp_path / "gz.img"
        path.write_bytes(container)
        result = MediatekGenieZoneParser().parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["component"] == "geniezone"
        assert md["gz_hypervisor_version"] == "3.2.1.004"
        assert md["gz_hypervisor_build_date"] == "2025-12-12"
        assert md["gz_core_version"] == "3.2.1.004"
        assert md["mtee_sdk_version"] == "2.2.2.000"
        assert result.version == "3.2.1.004"

    def test_cve_20707_vulnerable_build_flagged(self, tmp_path):
        """DPCS10 build: 3.2.1.004 / Dec 12 2025 — pre-patch → flag."""
        container = self._make_gz_container("3.2.1.004", "17:57:43 Dec 12 2025")
        path = tmp_path / "gz.img"
        path.write_bytes(container)
        result = MediatekGenieZoneParser().parse(str(path), magic=b"", size=path.stat().st_size)
        vulns = result.metadata.get("known_vulnerabilities", [])
        cve_ids = {v["cve_id"] for v in vulns}
        assert "CVE-2025-20707" in cve_ids
        v20707 = next(v for v in vulns if v["cve_id"] == "CVE-2025-20707")
        assert v20707["subcomponent"] == "geniezone"
        assert v20707["confidence"] == "high"
        assert "3.2.1.004" in v20707["rationale"]

    def test_cve_20707_patched_build_not_flagged(self, tmp_path):
        """Later build (3.2.2.0, May 2026) → must NOT be flagged."""
        container = self._make_gz_container("3.2.2.000", "12:00:00 May 15 2026")
        path = tmp_path / "gz.img"
        path.write_bytes(container)
        result = MediatekGenieZoneParser().parse(str(path), magic=b"", size=path.stat().st_size)
        vulns = result.metadata.get("known_vulnerabilities", [])
        assert vulns == []

    def test_cve_20707_date_only_fix_not_flagged(self, tmp_path):
        """Older version but build on/after Feb 2026 — treated as patched."""
        container = self._make_gz_container("3.2.1.999", "10:00:00 Feb 15 2026")
        path = tmp_path / "gz.img"
        path.write_bytes(container)
        result = MediatekGenieZoneParser().parse(str(path), magic=b"", size=path.stat().st_size)
        assert result.metadata.get("known_vulnerabilities", []) == []


class TestFingerprintHelpers:
    def test_vulnerable_pre_version(self):
        import datetime as dt
        assert _is_vulnerable_20707("3.2.1.004", dt.date(2025, 12, 12)) is True

    def test_safe_at_patch_version(self):
        import datetime as dt
        assert _is_vulnerable_20707("3.2.2.0", dt.date(2025, 12, 12)) is False

    def test_safe_by_date(self):
        import datetime as dt
        assert _is_vulnerable_20707("3.2.1.999", dt.date(2026, 3, 1)) is False

    def test_malformed_version_is_safe(self):
        assert _is_vulnerable_20707("garbage", None) is False

    def test_parse_built_date(self):
        import datetime as dt
        assert _parse_built_date("17:57:43 Dec 12 2025") == dt.date(2025, 12, 12)
        assert _parse_built_date("not a date") is None


# ─── tinysys / SPMFW / SSPM parser ────────────────────────────────────

class TestTinysysParser:
    def test_cortex_m_vector_table(self, tmp_path):
        """Cortex-M vector table with Thumb-bit reset handler is accepted."""
        # MSP = 0x00030000 (aligned), Reset = 0x00013CD5 (Thumb)
        payload = struct.pack("<II", 0x00030000, 0x00013CD5) + b"\x00" * 1024
        payload += b"FreeRTOS/Source/list.c\x00"
        payload += b"aiot8788ep1_64_bsp_k66\x00"
        payload += b"project/CM4_A/mt6771/platform/src/interrupt.c\x00"
        container = _build_container([("tinysys-scp-CM4_A", payload)])
        path = tmp_path / "scp.img"
        path.write_bytes(container)
        result = MediatekTinysysParser().parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["runtime"] == "freertos"
        assert md["component"] == "scp"
        assert md["vector_reset"] == "0x00013cd5"
        assert md["vector_msp"] == "0x00030000"
        assert md["board_tag"] == "aiot8788ep1_64_bsp_k66"
        gp = md["ghidra_import_params"]
        assert gp["processor"] == "ARM:LE:32:Cortex"
        # Entry with Thumb bit stripped
        assert gp["entry_point"] == 0x00013CD4

    def test_largest_payload_selected(self, tmp_path):
        """When container has loader + real payload, pick the larger."""
        loader = struct.pack("<II", 0x20000000, 0x00000201) + b"\x00" * 64
        real = struct.pack("<II", 0x00030000, 0x00013CD5) + b"\x00" * 2048
        container = _build_container([
            ("tinysys-loader-CM4_A", loader),
            ("tinysys-scp-CM4_A", real),
        ])
        path = tmp_path / "scp.img"
        path.write_bytes(container)
        result = MediatekTinysysParser().parse(str(path), magic=b"", size=path.stat().st_size)
        assert result.metadata["selected_sub_image"] == "tinysys-scp-CM4_A"

    def test_spmfw_pcm_microcode_no_ghidra(self, tmp_path):
        """SPMFW starts with '2MPS' magic — flagged as PCM, no Ghidra."""
        payload = (
            b"2MPS\x0a\x2f\x00\x00"            # magic + version
            + b"pcm_allinone_lp3_1866.bin".ljust(40, b"\x00")
            + b"\x00" * 512
        )
        container = _build_container([("spmfw", payload)])
        path = tmp_path / "spmfw.img"
        path.write_bytes(container)
        result = MediatekTinysysParser().parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["runtime"] == "mtk_pcm_microcode"
        assert md["no_ghidra_import"] is True
        assert md["pcm_artifact"] == "pcm_allinone_lp3_1866.bin"
        assert "ghidra_import_params" not in md

    def test_sspm_segment_chain(self, tmp_path):
        """SSPM payload begins with 0x58901690 segment chain."""
        payload = b"\x90\x16\x90\x58" + b"\x00" * 2048
        container = _build_container([("tinysys-sspm", payload)])
        path = tmp_path / "sspm.img"
        path.write_bytes(container)
        result = MediatekTinysysParser().parse(str(path), magic=b"", size=path.stat().st_size)
        md = result.metadata
        assert md["runtime"] == "mtk_sspm_rtos"
        assert md["component"] == "sspm"
        assert md["inner_wrapper"] == "sspm_segment_chain"


# ─── Classifier dispatch ──────────────────────────────────────────────

class TestClassifierSubsystemDispatch:
    def _classify_by_name(self, name: str):
        """Build a 64-byte fake magic with the given LK partition name."""
        magic = bytearray(64)
        struct.pack_into("<II", magic, 0, _LK_MAGIC, 0x1000)
        magic[8:8 + 32] = name.encode("ascii").ljust(32, b"\x00")[:32]
        struct.pack_into("<I", magic, 0x30, _LK_FILE_INFO_MAGIC)
        return classify(f"/tmp/{name}.img", bytes(magic), size=0x10000)

    def test_atf_routes_to_mtk_atf(self):
        cls = self._classify_by_name("atf")
        assert cls.format == "mtk_atf"
        assert cls.category == "tee"

    def test_gz_routes_to_mtk_geniezone(self):
        cls = self._classify_by_name("gz")
        assert cls.format == "mtk_geniezone"
        assert cls.category == "tee"

    def test_scp_routes_to_mtk_tinysys(self):
        cls = self._classify_by_name("scp")
        assert cls.format == "mtk_tinysys"
        assert cls.category == "mcu"

    def test_sspm_routes_to_mtk_tinysys(self):
        cls = self._classify_by_name("sspm")
        assert cls.format == "mtk_tinysys"

    def test_spmfw_routes_to_mtk_tinysys(self):
        cls = self._classify_by_name("spmfw")
        assert cls.format == "mtk_tinysys"

    def test_lk_still_routes_to_mtk_lk(self):
        cls = self._classify_by_name("lk")
        assert cls.format == "mtk_lk"
        assert cls.category == "bootloader"

    def test_cam_vpu1_still_routes_to_mtk_lk(self):
        """cam_vpu has no role-specific parser; falls back to mtk_lk."""
        cls = self._classify_by_name("cam_vpu1")
        assert cls.format == "mtk_lk"
        assert cls.category == "camera"
