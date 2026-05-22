"""Unit tests for per-format hardware firmware parsers (Phase 2).

Fixtures are synthesized at test time from ``tests.fixtures.hardware_firmware``
— no binary fixture files are checked in.  Each parser gets its own positive
case plus a shared malformed-input test to confirm graceful error handling.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from app.services.hardware_firmware.parsers import PARSER_REGISTRY, ParsedBlob, get_parser
from app.services.hardware_firmware.parsers.base import Parser  # noqa: F401 - Protocol import
from tests.fixtures.hardware_firmware._build_fixtures import (
    build_awinic_acf,
    build_broadcom_firmware,
    build_high_entropy_blob,
    build_mbn_v3,
    build_minimal_dtb,
    build_minimal_dtbo,
    build_minimal_kernel_image,
    build_minimal_ko,
    build_minimal_optee_ta,
    build_mtk_lk_partition,
    build_mtk_md1img,
    build_mtk_preloader,
    build_mtk_wifi_hdr,
    build_raw_bin_with_version,
    build_self_signed_cert_der,
    write_fixture,
)

# Skip whole module gracefully if `fdt` is missing — the test host doesn't
# always have it installed (Docker builds always do).
fdt = pytest.importorskip("fdt")


_EXPECTED_FORMATS = {
    "qcom_mbn",
    "mbn_v3",
    "mbn_v5",
    "mbn_v6",
    "dtb",
    "dtbo",
    "ko",
    "optee_ta",
    "fw_bcm",
    "raw_bin",
    # Phase 3 — MediaTek + Awinic
    "mtk_lk",
    "mtk_preloader",
    "mtk_modem",
    "mtk_wifi_hdr",
    "awinic_acf",
    # Phase 4 — Linux kernel-Image family (IKCFG + banner extraction)
    "zImage",
    "uImage",
    "vmlinuz",
    "Image",
}


# -----------------------------------------------------------------------------
# Registry coverage.
# -----------------------------------------------------------------------------


def test_parser_registry_contains_all_formats() -> None:
    """Every format the detector may emit must map to a parser instance."""
    missing = _EXPECTED_FORMATS - set(PARSER_REGISTRY.keys())
    assert not missing, f"missing parsers for formats: {missing}"

    for fmt in _EXPECTED_FORMATS:
        parser = get_parser(fmt)
        assert parser is not None
        assert hasattr(parser, "parse")


# -----------------------------------------------------------------------------
# DTB parser.
# -----------------------------------------------------------------------------


def _read_magic(path: Path, n: int = 64) -> bytes:
    with open(path, "rb") as f:
        return f.read(n)


def test_dtb_parser_extracts_compatible_and_firmware_names(tmp_path: Path) -> None:
    blob = build_minimal_dtb()
    dtb_path = tmp_path / "platform.dtb"
    write_fixture(dtb_path, blob)

    parser = get_parser("dtb")
    assert parser is not None
    result = parser.parse(str(dtb_path), _read_magic(dtb_path), len(blob))

    assert isinstance(result, ParsedBlob)
    assert result.signed == "unsigned"
    compats = result.metadata.get("compatible_strings") or []
    assert "wairz,test-v1" in compats
    assert "qcom,sm8450-test" in compats
    assert "qcom,wcn6750-wifi" in compats

    firmware_names = result.metadata.get("firmware_names") or []
    assert "wcn6750.bin" in firmware_names

    # Chipset should derive from the qcom,sm8450-test compatible string.
    assert result.chipset_target is not None
    assert "sm8450" in result.chipset_target.lower()


def test_dtbo_parser_aggregates_entries(tmp_path: Path) -> None:
    inner = build_minimal_dtb()
    blob = build_minimal_dtbo([inner, inner])
    dtbo_path = tmp_path / "overlay.dtbo"
    write_fixture(dtbo_path, blob)

    parser = get_parser("dtbo")
    assert parser is not None
    result = parser.parse(str(dtbo_path), _read_magic(dtbo_path), len(blob))

    assert result.signed == "unsigned"
    meta = result.metadata
    assert meta.get("container") == "dtbo"
    assert meta.get("dt_entry_count") == 2
    assert len(meta.get("dtb_entries") or []) == 2
    # Aggregated compatibles/firmware_names include sub-DTB values.
    compats = meta.get("compatible_strings") or []
    assert any("sm8450" in c for c in compats)
    fws = meta.get("firmware_names") or []
    assert "wcn6750.bin" in fws


# -----------------------------------------------------------------------------
# Kernel module (.ko) parser.
# -----------------------------------------------------------------------------


def test_kmod_parser_extracts_modinfo(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL"),
            ("version", "1.2.3"),
            ("srcversion", "ABCDEF0123456789"),
            ("vermagic", "5.10.0 SMP preempt mod_unload aarch64"),
            ("depends", "cfg80211,mac80211"),
            ("alias", "pci:v00001234d0000ABCD"),
            ("firmware", "wcn6750.bin"),
            ("firmware", "athwlan.bin"),
        ]
    )
    ko_path = tmp_path / "test.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    assert result.version == "1.2.3"
    meta = result.metadata
    assert meta.get("license") == "GPL"
    assert meta.get("vermagic", "").startswith("5.10.0")
    assert meta.get("firmware_deps") == ["wcn6750.bin", "athwlan.bin"]
    assert "cfg80211" in (meta.get("depends") or [])
    assert "mac80211" in (meta.get("depends") or [])
    # Phase 2: leading semver is exposed for the Tier 4 kernel_cpe matcher.
    assert meta.get("kernel_semver") == "5.10.0"


def test_kmod_parser_extracts_android_kernel_semver(tmp_path: Path) -> None:
    """An Android vermagic string like ``6.6.102-android15-8-g...`` yields
    a clean ``6.6.102`` in ``metadata.kernel_semver``."""
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL v2"),
            ("vermagic", "6.6.102-android15-8-g123456789abc SMP preempt mod_unload aarch64"),
        ]
    )
    ko_path = tmp_path / "bluetooth.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    meta = result.metadata
    assert meta.get("kernel_semver") == "6.6.102"


def test_kmod_parser_omits_kernel_semver_when_vermagic_missing(tmp_path: Path) -> None:
    """No vermagic → no ``kernel_semver`` key (not just a None value)."""
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [
            ("license", "GPL"),
            ("srcversion", "1234567890ABCDEF"),
        ]
    )
    ko_path = tmp_path / "nomagic.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    # vermagic is None so kernel_semver should NOT be set.
    assert "kernel_semver" not in result.metadata


def test_kmod_parser_detects_appended_signature(tmp_path: Path) -> None:
    pytest.importorskip("elftools")
    blob = build_minimal_ko(
        [("license", "GPL"), ("version", "2.0.0")],
        with_signature=True,
    )
    ko_path = tmp_path / "signed.ko"
    write_fixture(ko_path, blob)

    parser = get_parser("ko")
    assert parser is not None
    result = parser.parse(str(ko_path), _read_magic(ko_path), len(blob))

    assert result.signed == "signed"
    assert result.signature_algorithm == "CMS (kernel module)"


# -----------------------------------------------------------------------------
# OP-TEE TA parser.
# -----------------------------------------------------------------------------


def test_optee_ta_parser_extracts_uuid(tmp_path: Path) -> None:
    pytest.importorskip("lief")
    uuid_bytes = bytes.fromhex("0123456789abcdef0011223344556677")
    blob = build_minimal_optee_ta(uuid_bytes, ta_version="3.1.4")
    ta_path = tmp_path / "trusted_app.ta"
    write_fixture(ta_path, blob)

    parser = get_parser("optee_ta")
    assert parser is not None
    result = parser.parse(str(ta_path), _read_magic(ta_path), len(blob))

    assert result.signed == "signed"
    assert result.signature_algorithm == "RSA-SHA256"
    assert result.cert_subject == "OP-TEE TA Signing"
    assert result.metadata.get("ta_uuid") == "01234567-89ab-cdef-0011-223344556677"
    assert result.version == "3.1.4"


# -----------------------------------------------------------------------------
# Qualcomm MBN parser.
# -----------------------------------------------------------------------------


def test_qualcomm_mbn_v3_parser_extracts_header_fields(tmp_path: Path) -> None:
    pytest.importorskip("cryptography")
    cert_der = build_self_signed_cert_der("Wairz Test Signer")
    blob = build_mbn_v3(
        image_id=12,
        code=b"CODE" * 64,
        sig=b"SIG" * 32,
        cert_chain=cert_der,
        version_string="SDM660.MBN.1.0",
    )
    mbn_path = tmp_path / "tz.mbn"
    write_fixture(mbn_path, blob)

    parser = get_parser("mbn_v3")
    assert parser is not None
    result = parser.parse(str(mbn_path), _read_magic(mbn_path), len(blob))

    meta = result.metadata
    # Header parsed.
    assert meta.get("mbn_header_version") in {"v3", "v5_or_v6"}  # v3 expected for this fixture
    assert meta.get("image_id") == 12
    assert meta.get("codeword") == "0x844bdcd1"
    assert meta.get("magic") == "0x73d71034"
    # Version string scan hit.
    assert "qc_image_version_string" in meta
    # Cert chain extraction from the raw-header tail: leaf subject must
    # resolve to the CN we embedded.
    assert result.cert_subject is not None
    assert "Wairz Test Signer" in result.cert_subject
    assert result.signature_algorithm is not None
    assert "RSA" in result.signature_algorithm
    # Scan should pick up SDM660 from the embedded version string.
    if result.chipset_target:
        assert result.chipset_target.upper().startswith("SDM")


def test_qualcomm_mbn_v3_non_elf_signs_when_sig_present(tmp_path: Path) -> None:
    """A raw MBN v3 with non-zero sig_size should report signed=signed."""
    blob = build_mbn_v3(sig=b"X" * 128, cert_chain=b"")
    mbn_path = tmp_path / "sbl1.mbn"
    write_fixture(mbn_path, blob)

    parser = get_parser("mbn_v3")
    assert parser is not None
    result = parser.parse(str(mbn_path), _read_magic(mbn_path), len(blob))
    assert result.signed == "signed"


# -----------------------------------------------------------------------------
# Broadcom Wi-Fi parser.
# -----------------------------------------------------------------------------


def test_broadcom_wl_parser_extracts_version(tmp_path: Path) -> None:
    version = "7.35.180.11"
    blob = build_broadcom_firmware(version)
    fw_path = tmp_path / "brcmfmac43430-sdio.bin"
    write_fixture(fw_path, blob)

    parser = get_parser("fw_bcm")
    assert parser is not None
    result = parser.parse(str(fw_path), _read_magic(fw_path), len(blob))

    assert result.signed == "unsigned"
    assert result.version is not None
    assert version in result.version
    assert result.chipset_target is not None
    assert "43430" in result.chipset_target
    assert result.metadata.get("fw_version_raw") is not None


def test_broadcom_wl_parser_detects_paired_nvram(tmp_path: Path) -> None:
    blob = build_broadcom_firmware("7.35.180.11")
    fw_path = tmp_path / "brcmfmac4366c-pcie.bin"
    write_fixture(fw_path, blob)
    # Write paired NVRAM alongside.
    nvram = tmp_path / "brcmfmac4366c-pcie.txt"
    nvram.write_text("nvram_version=1.0\nboardrev=0x1234\n")

    parser = get_parser("fw_bcm")
    assert parser is not None
    result = parser.parse(str(fw_path), _read_magic(fw_path), len(blob))
    assert result.metadata.get("nvram_present") is True
    nv = result.metadata.get("nvram") or {}
    assert nv.get("nvram_version") == "1.0"


# -----------------------------------------------------------------------------
# Raw binary fallback.
# -----------------------------------------------------------------------------


def test_raw_bin_parser_extracts_version_and_entropy(tmp_path: Path) -> None:
    blob = build_raw_bin_with_version("1.2.3")
    bin_path = tmp_path / "touchpad.bin"
    write_fixture(bin_path, blob)

    parser = get_parser("raw_bin")
    assert parser is not None
    result = parser.parse(str(bin_path), _read_magic(bin_path), len(blob))

    assert result.signed == "unknown"
    assert result.version == "1.2.3"
    assert isinstance(result.metadata.get("entropy"), float)
    assert 0.0 <= result.metadata["entropy"] <= 8.0


def test_raw_bin_parser_flags_high_entropy(tmp_path: Path) -> None:
    blob = build_high_entropy_blob(4096)
    bin_path = tmp_path / "encrypted.bin"
    write_fixture(bin_path, blob)

    parser = get_parser("raw_bin")
    assert parser is not None
    result = parser.parse(str(bin_path), _read_magic(bin_path), len(blob))
    assert result.metadata["entropy"] > 7.0
    # Pseudo-random SHA-256 stream should trigger the high-entropy note.
    if result.metadata["entropy"] > 7.5:
        assert "high entropy" in (result.metadata.get("note") or "").lower()


# -----------------------------------------------------------------------------
# MediaTek LK parser (Phase 3).
# -----------------------------------------------------------------------------


def test_mtk_lk_parser_extracts_partition_name_and_size(tmp_path: Path) -> None:
    blob = build_mtk_lk_partition(partition_name="lk", partition_size=0x100000)
    lk_path = tmp_path / "lk.img"
    write_fixture(lk_path, blob)

    parser = get_parser("mtk_lk")
    assert parser is not None
    result = parser.parse(str(lk_path), _read_magic(lk_path), len(blob))

    assert isinstance(result, ParsedBlob)
    meta = result.metadata
    assert meta.get("partition_name") == "lk"
    # parser intentionally does NOT emit partition_size — compact-layout
    # headers don't have that field, and emitting garbage u32s from the
    # name bytes was the historical bug this parser was rewritten to fix
    # (see mediatek_lk.py header comment). Assert structural fields only.
    assert meta.get("magic") == "0x58881688"
    assert meta.get("layout") == "legacy"
    assert meta.get("file_info_offset") == 0x200


def test_mtk_lk_parser_reports_bad_magic(tmp_path: Path) -> None:
    # Valid file size but wrong magic bytes.
    blob = b"\x00" * 512
    lk_path = tmp_path / "not_lk.img"
    write_fixture(lk_path, blob)

    parser = get_parser("mtk_lk")
    assert parser is not None
    result = parser.parse(str(lk_path), _read_magic(lk_path), len(blob))
    assert result.metadata.get("error") is not None


# -----------------------------------------------------------------------------
# MediaTek preloader parser (Phase 3).
# -----------------------------------------------------------------------------


def test_mtk_preloader_parser_extracts_version_and_sig(tmp_path: Path) -> None:
    blob = build_mtk_preloader(file_ver="V1.2", sig_type=1, file_len=0x8000, file_id="pm")
    pre_path = tmp_path / "preloader.bin"
    write_fixture(pre_path, blob)

    parser = get_parser("mtk_preloader")
    assert parser is not None
    result = parser.parse(str(pre_path), _read_magic(pre_path), len(blob))

    assert result.version == "V1.2"
    assert result.signed == "signed"
    meta = result.metadata
    assert meta.get("file_type") == "pm"
    assert meta.get("file_len") == 0x8000
    assert meta.get("sig_type") == 1


def test_mtk_preloader_parser_unsigned_when_no_signature(tmp_path: Path) -> None:
    blob = build_mtk_preloader(file_ver="V2.0", sig_type=0, file_len=0x2000)
    pre_path = tmp_path / "preloader_unsigned.bin"
    write_fixture(pre_path, blob)

    parser = get_parser("mtk_preloader")
    assert parser is not None
    result = parser.parse(str(pre_path), _read_magic(pre_path), len(blob))

    assert result.version == "V2.0"
    assert result.signed == "unsigned"


# -----------------------------------------------------------------------------
# MediaTek modem (md1img) parser (Phase 3).
# -----------------------------------------------------------------------------


def test_mtk_modem_parser_extracts_sections(tmp_path: Path) -> None:
    blob = build_mtk_md1img(
        sections=[("md1rom", 0x400, 0x800), ("cert_md", 0xC00, 0x200)],
        chipset="MT6771",
        version="v1.2.3",
    )
    mod_path = tmp_path / "md1img.img"
    write_fixture(mod_path, blob)

    parser = get_parser("mtk_modem")
    assert parser is not None
    result = parser.parse(str(mod_path), _read_magic(mod_path), len(blob))

    assert isinstance(result, ParsedBlob)
    meta = result.metadata
    section_names = meta.get("section_names") or []
    assert "md1rom" in section_names
    assert "cert_md" in section_names
    # cert_md presence → signed
    assert result.signed == "signed"
    # Chipset pulled from banner.
    assert result.chipset_target == "MT6771"
    # Version scraped from "md1rom_version:v1.2.3" banner.
    assert result.version is not None and "1.2.3" in result.version


def test_mtk_modem_parser_missing_magic_is_graceful(tmp_path: Path) -> None:
    blob = b"\x00" * 1024
    mod_path = tmp_path / "not_md1img.img"
    write_fixture(mod_path, blob)

    parser = get_parser("mtk_modem")
    assert parser is not None
    result = parser.parse(str(mod_path), _read_magic(mod_path), len(blob))
    assert "MD1IMG magic not found" in (result.metadata.get("note") or "")


# -----------------------------------------------------------------------------
# MediaTek Wi-Fi header parser (Phase 3).
# -----------------------------------------------------------------------------


def test_mtk_wifi_parser_extracts_timestamp_and_chipset(tmp_path: Path) -> None:
    blob = build_mtk_wifi_hdr(timestamp="20230401120000", at_offset=0x20)
    wifi_path = tmp_path / "mt7921_patch_mcu_hdr.bin"
    write_fixture(wifi_path, blob)

    parser = get_parser("mtk_wifi_hdr")
    assert parser is not None
    result = parser.parse(str(wifi_path), _read_magic(wifi_path), len(blob))

    assert result.version == "20230401120000"
    meta = result.metadata
    assert meta.get("build_timestamp") == "20230401120000"
    assert meta.get("timestamp_origin") == "header"
    assert result.chipset_target == "MT7921"
    assert meta.get("chipset_match_origin") == "filename"
    assert meta.get("variant") == "mt76_hdr"


def test_mtk_wifi_parser_connsys_pairing(tmp_path: Path) -> None:
    """WIFI_RAM_CODE_MT6759 gets the connsys-pairing enrichment."""
    blob = build_mtk_wifi_hdr(timestamp="20210115093000", at_offset=0x10)
    wifi_path = tmp_path / "WIFI_RAM_CODE_MT6759.bin"
    write_fixture(wifi_path, blob)

    parser = get_parser("mtk_wifi_hdr")
    assert parser is not None
    result = parser.parse(str(wifi_path), _read_magic(wifi_path), len(blob))

    assert result.chipset_target == "MT6759"
    meta = result.metadata
    assert "connectivity" in (meta.get("chipset_role") or "").lower()


# -----------------------------------------------------------------------------
# Awinic ACF parser (Phase 3).
# -----------------------------------------------------------------------------


def test_awinic_acf_parser_extracts_chip_id_and_version(tmp_path: Path) -> None:
    blob = build_awinic_acf(acf_version=2, chip_id="aw88266", profile_count=4)
    acf_path = tmp_path / "aw88266_acf.bin"
    write_fixture(acf_path, blob)

    parser = get_parser("awinic_acf")
    assert parser is not None
    result = parser.parse(str(acf_path), _read_magic(acf_path), len(blob))

    assert result.chipset_target == "aw88266"
    assert result.version == "2"
    meta = result.metadata
    assert meta.get("magic") == "AWINIC"
    assert meta.get("acf_version") == 2
    assert meta.get("profile_count") == 4


def test_awinic_acf_parser_magic_mismatch_is_graceful(tmp_path: Path) -> None:
    blob = b"\x00" * 128
    acf_path = tmp_path / "notacf.bin"
    write_fixture(acf_path, blob)

    parser = get_parser("awinic_acf")
    assert parser is not None
    result = parser.parse(str(acf_path), _read_magic(acf_path), len(blob))
    assert "magic_mismatch" in result.metadata


# -----------------------------------------------------------------------------
# Linux kernel-Image parser (zImage / uImage / vmlinuz / Image).
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["zImage", "uImage", "vmlinuz", "Image"])
def test_kernel_image_parser_extracts_ikconfig_and_banner(tmp_path: Path, fmt: str) -> None:
    """All four kernel-image FORMAT subclasses share one parse() body; verify
    each registers and dispatches correctly to the IKCFG + banner extraction.
    """
    blob = build_minimal_kernel_image(version="5.10.42")
    kpath = tmp_path / f"kernel_{fmt}.bin"
    write_fixture(kpath, blob)

    parser = get_parser(fmt)
    assert parser is not None, f"no parser registered for {fmt}"
    result = parser.parse(str(kpath), _read_magic(kpath), len(blob))

    assert isinstance(result, ParsedBlob)
    assert result.version == "5.10.42", f"banner SemVer not extracted: {result.version}"
    assert result.metadata.get("ikconfig_present") is True
    cfg = result.metadata.get("kernel_config") or {}
    # Default fixture exercises all three line shapes.
    assert cfg.get("CONFIG_RANDOMIZE_BASE") == "y"
    assert cfg.get("CONFIG_DEVMEM") == "y"
    assert cfg.get("CONFIG_MODULE_SIG") == "n", \
        f"`# CONFIG_FOO is not set` not parsed to 'n': {cfg.get('CONFIG_MODULE_SIG')!r}"
    assert cfg.get("CONFIG_LOCALVERSION") == '"-tegra"'
    assert result.metadata.get("kernel_semver") == "5.10.42"
    assert "Linux version 5.10.42" in (result.metadata.get("kernel_banner") or "")


def test_kernel_image_parser_no_ikconfig_returns_banner_only(tmp_path: Path) -> None:
    """When CONFIG_IKCONFIG was stripped, banner is the only thing we recover.
    Verifies ikconfig_present=False is the truthful "no config available"
    signal — the parser MUST NOT fabricate an empty kernel_config dict.
    """
    blob = build_minimal_kernel_image(version="4.19.0", include_ikcfg=False)
    kpath = tmp_path / "kernel_no_ikcfg.bin"
    write_fixture(kpath, blob)

    parser = get_parser("Image")
    result = parser.parse(str(kpath), _read_magic(kpath), len(blob))

    assert result.version == "4.19.0"
    assert result.metadata.get("ikconfig_present") is False
    assert "kernel_config" not in result.metadata, \
        "ikconfig_present=False must NOT carry a kernel_config dict"
    assert "Linux version 4.19.0" in (result.metadata.get("kernel_banner") or "")


def test_kernel_image_parser_vendor_inference_tegra(tmp_path: Path) -> None:
    """Filename-driven Rule #19 content-evidence vendor override — the
    classifier emits vendor='nvidia' for Tegra Image filenames; the parser
    confirms via banner ("tegra" substring in build host).
    """
    blob = build_minimal_kernel_image(
        version="4.9.140",
        banner_extra="-tegra (buildbrain@host) (gcc 7.3.1)",
    )
    kpath = tmp_path / "Image"  # NVIDIA Tegra L4T ships as raw `Image`
    write_fixture(kpath, blob)

    parser = get_parser("Image")
    result = parser.parse(str(kpath), _read_magic(kpath), len(blob))
    # Filename "Image" alone doesn't hit the regex; vendor inference falls
    # through to banner substring ("tegra") → 'nvidia'.
    assert result.vendor == "nvidia", f"banner-driven vendor not 'nvidia': {result.vendor!r}"


def test_kernel_image_parser_gzip_bomb_mitigated(tmp_path: Path) -> None:
    """Rule #46 META-CANARY for Wave-2 attack F.

    A malicious kernel image with an IKCFG_ST marker followed by a 5 MB
    decompressed-size gzip stream must NOT be returned (would OOM the
    worker on real-world repeated invocations).  The mitigation lives in
    the shared helper (_kernel_ikconfig.py) but the META-CANARY proves
    the parser surface preserves it.

    Without the cap, this test would either OOM or return a 5 MB
    kernel_config string.  With the cap, it must return
    ikconfig_present=False.
    """
    import gzip as _gzip

    from app.services.hardware_firmware.parsers._kernel_ikconfig import (
        IKCFG_ED,
        IKCFG_ST,
    )

    # 5 MB of 'A' compresses to ~5 kB but expands beyond the 4 MB cap.
    bomb_payload = b"A" * (5 * 1024 * 1024)
    gz_bomb = _gzip.compress(bomb_payload)
    bomb_blob = (
        b"\x00" * 4096
        + b"Linux version 9.9.9-bomb\x00"
        + b"\x00" * 1024
        + IKCFG_ST + gz_bomb + IKCFG_ED
    )
    kpath = tmp_path / "bomb.Image"
    write_fixture(kpath, bomb_blob)

    parser = get_parser("Image")
    result = parser.parse(str(kpath), _read_magic(kpath), len(bomb_blob))

    # Banner still extracts (banner scan is bounded separately).
    assert result.metadata.get("kernel_semver") == "9.9.9"
    # Gzip-bomb payload MUST be rejected by the helper's bounded read.
    assert result.metadata.get("ikconfig_present") is False, \
        "Wave-2 attack F: gzip bomb leaked through the helper's _MAX_CONFIG_BYTES cap"


def test_kernel_image_parser_no_decrypt_gate(tmp_path: Path) -> None:
    """Rule #45 + Rule #46 paired gate: confirm the parser source contains
    no decrypt / exec / subprocess tokens.  Walker discipline applied at
    the parse-only surface.

    Companion canary: this gate's regex MUST be whitespace-tolerant
    because `tokenize` joins tokens with single spaces (`obj.decrypt(`
    becomes `obj . decrypt (`).  Per CLAUDE.md Rule #45 + #46.
    """
    import tokenize
    from pathlib import Path as _P

    parser_src_path = _P(__file__).parent.parent / "app/services/hardware_firmware/parsers/kernel_image.py"
    assert parser_src_path.is_file(), f"parser source missing: {parser_src_path}"

    with parser_src_path.open("rb") as f:
        tokens = []
        try:
            for tok in tokenize.tokenize(f.readline):
                if tok.type in (tokenize.COMMENT, tokenize.STRING):
                    continue
                tokens.append(tok.string)
        except tokenize.TokenizeError:
            pass

    joined = " ".join(tokens)
    # Whitespace-tolerant regex — per Rule #46 + the κ.D canary lesson
    # (Cli regex `\.decrypt\(` would miss `obj . decrypt (` after tokenize).
    forbidden = re.compile(
        r"\.\s*(decrypt|encrypt)\s*\(|"
        r"subprocess\s*\.\s*(run|Popen|call|check_output)\s*\(|"
        r"os\s*\.\s*(system|execvp|execve)\s*\(|"
        r"asyncio\s*\.\s*create_subprocess_(exec|shell)\s*\(",
        re.IGNORECASE,
    )
    matches = forbidden.findall(joined)
    assert not matches, (
        f"Rule #36/#45 parse-only violation in kernel_image.py: forbidden tokens found: {matches}"
    )


def test_kernel_image_parser_no_decrypt_gate_actually_fires() -> None:
    """Rule #46 META-CANARY companion: prove the gate above actually
    rejects a synthesised violation.

    Mirrors κ.D's whitespace-tolerant canary discipline.  Without this
    canary the gate is a Rule #17 silent-pass risk: a passing
    `test_kernel_image_parser_no_decrypt_gate` is only meaningful if
    we ALSO know the gate's regex would catch a violation.
    """
    import tokenize
    import io as _io

    # Synthesize source that contains a forbidden pattern AFTER tokenize
    # joins tokens with spaces.  Use NORMAL Python code paths (not
    # f-strings — tokenize strips STRING tokens which would hide the
    # violation in a string literal).
    synthetic = b"def x(): subprocess.run(['echo', 'hi'])\n"
    tokens = []
    try:
        for tok in tokenize.tokenize(_io.BytesIO(synthetic).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            tokens.append(tok.string)
    except tokenize.TokenizeError:
        pass
    joined = " ".join(tokens)

    forbidden = re.compile(
        r"\.\s*(decrypt|encrypt)\s*\(|"
        r"subprocess\s*\.\s*(run|Popen|call|check_output)\s*\(|"
        r"os\s*\.\s*(system|execvp|execve)\s*\(|"
        r"asyncio\s*\.\s*create_subprocess_(exec|shell)\s*\(",
        re.IGNORECASE,
    )
    assert forbidden.search(joined), (
        f"Rule #46 META-CANARY: the no-decrypt gate's regex FAILED to catch a "
        f"synthesised violation. Tokenized source was: {joined!r}"
    )


# -----------------------------------------------------------------------------
# Malformed-input defense: every parser must handle zero / truncated bytes.
# -----------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", sorted(_EXPECTED_FORMATS))
def test_parser_handles_malformed_bytes_gracefully(tmp_path: Path, fmt: str) -> None:
    parser = get_parser(fmt)
    assert parser is not None, f"no parser for {fmt}"

    # Empty file.
    empty = tmp_path / f"empty_{fmt}.bin"
    empty.write_bytes(b"")
    res = parser.parse(str(empty), b"", 0)
    assert isinstance(res, ParsedBlob)

    # A few random bytes.
    junk = tmp_path / f"junk_{fmt}.bin"
    junk.write_bytes(b"\x00" * 64)
    res2 = parser.parse(str(junk), b"\x00" * 64, 64)
    assert isinstance(res2, ParsedBlob)

    # A random ELF-ish prefix (no valid structure past the magic).
    elfish = tmp_path / f"elfish_{fmt}.bin"
    elfish.write_bytes(b"\x7fELF" + b"\x41" * 200)
    res3 = parser.parse(str(elfish), b"\x7fELF" + b"\x41" * 60, 204)
    assert isinstance(res3, ParsedBlob)
