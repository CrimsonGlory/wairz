"""Tests for the data-driven firmware classifier (Phase 1).

Covers:

* ``patterns_loader.match()`` — unit tests for each vendor the task spec
  explicitly calls out (Awinic, MediaTek Wi-Fi + FM/WMT combo, Sensortek,
  Bosch, InvenSense, Mali-on-MT, NXP NFC).
* ``patterns_loader.VENDORS`` — must always include the Wairz core set of
  canonical vendor prefixes, regardless of YAML contents.
* Classifier integration — end-to-end ``classify()`` calls with synthetic
  magic bytes (ELF ET_REL for ``.ko`` fixtures, raw-bin for ``.bin``).

No on-disk fixtures required: ``classify()`` and ``match()`` operate on the
supplied ``magic`` / ``path`` without touching the filesystem.
"""
from __future__ import annotations

import pytest

from app.services.hardware_firmware import classifier
from app.services.hardware_firmware.classifier import Classification, classify
from app.services.hardware_firmware.patterns_loader import (
    VENDOR_DISPLAY,
    VENDORS,
    PathContextMatch,
    PatternMatch,
    match,
    match_path_context,
    resolve_vendor,
)

# Synthetic ELF magic tuned so ``_is_elf_relocatable()`` returns True.
# Byte layout: 0-3=\x7fELF, 4=ELFCLASS32(1), 5=ELFDATA2LSB(1), 6-15=padding,
# 16-17=e_type (LE uint16) = ET_REL (1).  Total = 4 + 2 + 10 + 2 + 46 = 64.
_ELF_KO_MAGIC = b"\x7fELF\x01\x01" + b"\x00" * 10 + b"\x01\x00" + b"\x00" * 46
_RAW_BIN_MAGIC = b"\x00" * 64

assert len(_ELF_KO_MAGIC) == 64
assert len(_RAW_BIN_MAGIC) == 64
# Sanity-check ELF bytes.
assert _ELF_KO_MAGIC[0:4] == b"\x7fELF"
assert _ELF_KO_MAGIC[5] == 1  # EI_DATA = ELFDATA2LSB
assert _ELF_KO_MAGIC[16] == 0x01 and _ELF_KO_MAGIC[17] == 0x00  # ET_REL LE


# ---------------------------------------------------------------------------
# Loader sanity checks.
# ---------------------------------------------------------------------------


def test_vendor_prefixes_yaml_loads() -> None:
    """vendor_prefixes.yaml must populate VENDORS + VENDOR_DISPLAY."""
    assert isinstance(VENDORS, frozenset)
    assert len(VENDORS) >= 50, "expected at least 50 vendor prefixes"
    assert isinstance(VENDOR_DISPLAY, dict)
    assert len(VENDOR_DISPLAY) >= 50
    # Each display value must be a non-empty string.
    for key, val in VENDOR_DISPLAY.items():
        assert isinstance(key, str) and key
        assert isinstance(val, str) and val


def test_vendors_contains_core_set() -> None:
    """Wairz core VENDORS must always be present, even if YAML is missing."""
    core = {
        "qualcomm",
        "mediatek",
        "samsung",
        "broadcom",
        "nvidia",
        "imagination",
        "arm",
        "apple",
        "cypress",
        "unisoc",
        "hisilicon",
        "intel",
        "realtek",
        "unknown",
    }
    missing = core - VENDORS
    assert not missing, f"missing core vendors: {missing}"


def test_firmware_patterns_yaml_loads() -> None:
    """Basic sanity — a representative set of patterns must be live."""
    # A well-known vendor from every major category should resolve.
    assert match("aw88264_acf.bin") is not None
    assert match("bmi160_i2c.ko") is not None
    assert match("pn553.ko") is not None
    assert match("mali_kbase_mt6771_r49p0.ko") is not None
    assert match("WIFI_RAM_CODE_MT7622.bin") is not None


def test_vendor_alias_resolution() -> None:
    """qcom / mtk / brcm must resolve to their canonical prefixes."""
    assert resolve_vendor("qcom") == "qualcomm"
    assert resolve_vendor("mtk") == "mediatek"
    assert resolve_vendor("brcm") == "broadcom"
    assert resolve_vendor("") == "unknown"
    assert resolve_vendor(None) == "unknown"
    # Unknown tokens pass through lowercased.
    assert resolve_vendor("NovelVendor") == "novelvendor"


# ---------------------------------------------------------------------------
# Pattern match unit tests (required cases from the task spec).
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path,expected_vendor,expected_category",
    [
        # Spec-required cases — keep names identical to the spec.
        ("/vendor/firmware/aw883xx_acf.bin", "awinic", "audio"),
        ("/vendor/firmware/WIFI_RAM_CODE_6759.bin", "mediatek", "wifi"),
        ("/vendor/firmware/mt6631_fm_v1_p1.bin", "mediatek", "wifi"),
        ("/vendor/lib/modules/stk3x1x.ko", "sensortek", "sensor"),
        ("/vendor/lib/modules/bmi160_i2c.ko", "bosch", "sensor"),
        ("/vendor/lib/modules/icm42600_i2c.ko", "invensense", "sensor"),
        ("/vendor/lib/modules/mali_kbase_mt6771_r49p0.ko", "arm", "gpu"),
        ("/vendor/lib/modules/pn553.ko", "nxp", "nfc"),
        # Qualcomm Atheros Rome / WCN3xx0 Bluetooth on Motorola /
        # Qualcomm Bengal platforms — DS1 Moto-G32 BTFM.bin archive +
        # its unblob-extracted sub-components.
        # ATTRIBUTION HISTORY: originally added 2026-05-14 with
        # vendor=broadcom (commit f6bdc4e, forensic-review A2 #3).
        # Corrected to vendor=qualcomm 2026-05-15 (commit 3d8d018) when
        # the content-evidence audit found BTFM.<codename>.x.y.z-
        # QCACHROMZ-1 banners + PF=WCN3950ROM= build strings + zero
        # Broadcom/brcm strings in any BTFM file. See
        # .planning/postmortems/postmortem-btfm-correction-and-corpus-
        # 2026-05-15.md for the full audit chain.
        ("/vendor/firmware/BTFM.bin", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/cmbtfw13.tlv", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/apbtfw10.tlv", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/crbtfw11.tlv", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/cmbtfw12.ver", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/cmnv12.bin", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/cmnv13s.bin", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/crnv21.bin", "qualcomm", "bluetooth"),
        ("/.../BTFM.bin_extract/.../image/apnv11.bin", "qualcomm", "bluetooth"),
    ],
)
def test_match_returns_expected_vendor_and_category(
    path: str, expected_vendor: str, expected_category: str
) -> None:
    hit = match(path)
    assert hit is not None, f"{path} should match some pattern"
    assert hit.vendor == expected_vendor
    assert hit.category == expected_category
    assert hit.confidence in {"high", "medium", "low"}


def test_match_returns_pattern_match_instance() -> None:
    """Type-check the returned object to guard against refactors."""
    hit = match("aw88264_acf.bin")
    assert isinstance(hit, PatternMatch)
    assert hit.product is not None
    assert "AW88" in hit.product.upper() or "awinic" in hit.vendor


@pytest.mark.parametrize(
    "path",
    [
        "/bin/sh",
        "/system/lib/libc.so",
        "/vendor/bin/vendor_service",
        "",
        "README.md",
    ],
)
def test_match_returns_none_for_unrelated_paths(path: str) -> None:
    assert match(path) is None


def test_match_is_case_insensitive() -> None:
    """The regex engine is compiled with IGNORECASE — capitalisation should not matter."""
    upper = match("WIFI_RAM_CODE_MT7622.BIN")
    lower = match("wifi_ram_code_mt7622.bin")
    assert upper is not None and lower is not None
    assert upper.vendor == lower.vendor == "mediatek"
    assert upper.category == lower.category == "wifi"


def test_match_operates_on_basename_not_full_path() -> None:
    """Two paths with the same basename must match the same template."""
    a = match("/vendor/firmware/aw88264_acf.bin")
    b = match("/product/etc/firmware/aw88264_acf.bin")
    c = match("aw88264_acf.bin")
    assert a == b == c
    assert a is not None
    assert a.vendor == "awinic"


# ---------------------------------------------------------------------------
# Classifier integration tests — end-to-end via ``classify()``.
# ---------------------------------------------------------------------------


def test_classify_aw883xx_acf_bin_raw() -> None:
    cls = classify("/vendor/firmware/aw883xx_acf.bin", _RAW_BIN_MAGIC, 2048)
    assert isinstance(cls, Classification)
    assert cls.vendor == "awinic"
    assert cls.category == "audio"
    # Phase 3: ACF now routes to the native awinic_acf parser.
    assert cls.format == "awinic_acf"
    assert cls.confidence == "high"
    assert cls.product is not None


def test_classify_mediatek_wifi_raw() -> None:
    cls = classify("/vendor/firmware/WIFI_RAM_CODE_6759.bin", _RAW_BIN_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "mediatek"
    assert cls.category == "wifi"


def test_classify_mediatek_fm_combo() -> None:
    cls = classify("/vendor/firmware/mt6631_fm_v1_p1.bin", _RAW_BIN_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "mediatek"
    assert cls.category == "wifi"


def test_classify_sensortek_ko() -> None:
    cls = classify("/vendor/lib/modules/stk3x1x.ko", _ELF_KO_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "sensortek"
    assert cls.category == "sensor"
    assert cls.format == "ko"


def test_classify_bosch_ko() -> None:
    cls = classify("/vendor/lib/modules/bmi160_i2c.ko", _ELF_KO_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "bosch"
    assert cls.category == "sensor"
    assert cls.format == "ko"


def test_classify_invensense_ko() -> None:
    cls = classify("/vendor/lib/modules/icm42600_i2c.ko", _ELF_KO_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "invensense"
    assert cls.category == "sensor"


def test_classify_mali_on_mediatek_ko() -> None:
    cls = classify(
        "/vendor/lib/modules/mali_kbase_mt6771_r49p0_01dev2.ko",
        _ELF_KO_MAGIC,
        10_000,
    )
    assert cls is not None
    assert cls.vendor == "arm"
    assert cls.category == "gpu"
    assert cls.format == "ko"


def test_classify_nxp_nfc_ko() -> None:
    cls = classify("/vendor/lib/modules/pn553.ko", _ELF_KO_MAGIC, 10_000)
    assert cls is not None
    assert cls.vendor == "nxp"
    assert cls.category == "nfc"


def test_classify_unknown_ko_still_kernel_module() -> None:
    """.ko files that don't match any YAML pattern must still be captured
    as kernel_module with vendor=unknown — ensures existing detector flow
    keeps working on legacy fixtures."""
    cls = classify("/vendor/lib/modules/mysterious_thing.ko", _ELF_KO_MAGIC, 10_000)
    assert cls is not None
    assert cls.category == "kernel_module"
    assert cls.vendor == "unknown"
    assert cls.format == "ko"


# ---------------------------------------------------------------------------
# Backwards-compatibility — confirm the existing behaviours still work.
# ---------------------------------------------------------------------------


def test_classify_preserves_magic_byte_precedence_dtb() -> None:
    """DTB magic wins before YAML filename matching."""
    magic = b"\xd0\x0d\xfe\xed" + b"\x00" * 60
    cls = classify("/vendor/firmware/aw88264_acf.bin", magic, 2048)
    assert cls is not None
    # Magic wins → dtb category.
    assert cls.category == "dtb"
    assert cls.format == "dtb"


def test_classify_preserves_shannon_toc() -> None:
    magic = b"TOC\x00" + b"\x00" * 60
    cls = classify("/vendor/firmware/modem.bin", magic, 100_000)
    assert cls is not None
    assert cls.category == "modem"
    assert cls.vendor == "samsung"
    assert cls.format == "shannon_toc"


def test_classify_preserves_qcom_pil_stem() -> None:
    """Qualcomm PIL stems must still win over YAML (stem list is more precise)."""
    cls = classify("/vendor/firmware/tz.mbn", _RAW_BIN_MAGIC, 100_000)
    assert cls is not None
    assert cls.vendor == "qualcomm"
    assert cls.category == "tee"


def test_classify_returns_none_for_regular_binary() -> None:
    """Regular system binaries must not be tagged as firmware."""
    # A normal /system/bin ELF with no firmware-partition context.
    non_rel_magic = b"\x7fELF\x02\x01" + b"\x00" * 10 + b"\x02\x00" + b"\x00" * 50
    assert classify("/system/bin/ls", non_rel_magic, 20_000) is None


def test_classify_path_fallback_still_works() -> None:
    """Files in /vendor/firmware/ without specific matches are tagged as 'other'."""
    cls = classify(
        "/vendor/firmware/mystery_thing_no_match_12345.fw",
        _RAW_BIN_MAGIC,
        1024,
    )
    assert cls is not None
    assert cls.category == "other"
    assert cls.format == "raw_bin"


def test_classifier_vendors_export_matches_loader() -> None:
    """classifier.VENDORS is the same object as patterns_loader.VENDORS."""
    from app.services.hardware_firmware.patterns_loader import VENDORS as loader_v

    assert classifier.VENDORS is loader_v


# ---------------------------------------------------------------------------
# Pattern coverage sanity — make sure the YAML actually has enough entries.
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# MCU / kernel / signed-archive patterns (2026-04-17 RespArray investigation).
# Covers gaps surfaced by project 00815038 after the extraction-integrity fix.
# ---------------------------------------------------------------------------


def test_classify_nxp_imxrt_mcu_bin() -> None:
    """NXP i.MX RT Cortex-M MCU firmware by filename."""
    cls = classify("/firmware/imxrt1052_ix_iv_iap.bin", _RAW_BIN_MAGIC, 89_000)
    assert cls is not None
    assert cls.vendor == "nxp"
    assert cls.category == "mcu"
    assert cls.format == "imxrt_bin"
    assert cls.confidence == "high"


def test_classify_nxp_imxrt_merge_filename_variant() -> None:
    """Filenames with parenthesised suffix (MERGE) must still match."""
    cls = classify("/firmware/imxrt1052_ix_iv(MERGE).bin", _RAW_BIN_MAGIC, 1_900_000)
    assert cls is not None
    assert cls.vendor == "nxp"
    assert cls.category == "mcu"


def test_classify_edan_frontboard_bin() -> None:
    """Edan medical-device frontboard MCU firmware."""
    cls = classify("/frontboard/ix_iv_070(MERGE).bin", _RAW_BIN_MAGIC, 500_000)
    assert cls is not None
    assert cls.vendor == "edan"
    assert cls.category == "mcu"
    assert cls.confidence == "medium"


def test_classify_edan_iap_variant() -> None:
    cls = classify("/frontboard/update/ix_iv_070(IAP).bin", _RAW_BIN_MAGIC, 300_000)
    assert cls is not None
    assert cls.vendor == "edan"
    assert cls.category == "mcu"


def test_classify_edan_vendor_in_registry() -> None:
    """edan must resolve through vendor_prefixes.yaml with a display string."""
    assert "edan" in VENDORS
    assert VENDOR_DISPLAY.get("edan") == "Edan Instruments, Inc."


def test_classify_linux_zimage_by_magic() -> None:
    """ARM zImage magic 0x016F2818 at offset 0x24 — high-confidence gate."""
    magic = b"\x00" * 0x24 + b"\x18\x28\x6f\x01" + b"\x00" * 32
    # classifier requires len(magic) >= 0x28 (40 bytes) to read the 4 magic bytes
    assert len(magic) >= 0x28
    cls = classify("/zImage-restore/zImage-restore", magic, 2_400_000)
    assert cls is not None
    assert cls.category == "kernel"
    assert cls.format == "zImage"
    assert cls.confidence == "high"


def test_classify_linux_zimage_by_filename_fallback() -> None:
    """zImage without the canonical magic still classifies via filename."""
    cls = classify("/boot/zImage", _RAW_BIN_MAGIC, 4_000_000)
    assert cls is not None
    assert cls.category == "kernel"
    assert cls.format == "zImage"


def test_classify_uimage_by_filename() -> None:
    cls = classify("/boot/uImage", _RAW_BIN_MAGIC, 5_000_000)
    assert cls is not None
    assert cls.category == "kernel"
    assert cls.format == "uImage"


def test_classify_vmlinuz_by_filename() -> None:
    cls = classify("/boot/vmlinuz-5.10.0", _RAW_BIN_MAGIC, 8_000_000)
    assert cls is not None
    assert cls.category == "kernel"
    assert cls.format == "vmlinuz"


def test_classify_signed_archive_placeholder() -> None:
    """Custom a3 df bb bf archive magic emits a placeholder classification."""
    magic = b"\xa3\xdf\xbb\xbf" + b"\x00" * 60
    cls = classify(
        "/data/system_update.tar.xz",  # real filename lies about the format
        magic,
        10_000,
    )
    assert cls is not None
    assert cls.category == "other"
    assert cls.format == "signed_archive"
    assert cls.confidence == "medium"


def test_classify_zimage_magic_wins_over_yaml() -> None:
    """Magic-byte precedence: zImage magic beats filename YAML pattern."""
    magic = b"\x00" * 0x24 + b"\x18\x28\x6f\x01" + b"\x00" * 32
    # Filename would also match YAML (zimage pattern), so both agree — test
    # that the result is the high-confidence magic path, not a YAML hit.
    cls = classify("/boot/zImage-restore", magic, 2_000_000)
    assert cls is not None
    assert cls.format == "zImage"
    assert cls.vendor == "unknown"
    # Magic path emits confidence=high with no source/product fields
    assert cls.confidence == "high"


def test_classify_mcu_and_kernel_in_categories() -> None:
    """Ensure the new categories are in the export so downstream validation passes."""
    assert "mcu" in classifier.CATEGORIES
    assert "kernel" in classifier.CATEGORIES
    for fmt in ("imxrt_bin", "zImage", "uImage", "vmlinuz", "signed_archive"):
        assert fmt in classifier.FORMATS, f"{fmt} must be in FORMATS"


def test_firmware_patterns_minimum_coverage() -> None:
    """The YAML must carry at least the 40 curated entries we committed to."""
    # We don't expose the compiled list directly (internal), but we can
    # count distinct vendors that are reachable via known filenames.
    probes = [
        "aw88264_acf.bin",
        "WIFI_RAM_CODE_MT7622.bin",
        "mt6631_fm_v1_p1.bin",
        "md1img_g.img",
        "md1dsp.img",
        "preloader_k62v1.bin",
        "lk.bin",
        "spmfw.img",
        "sspm.img",
        "mcupm.img",
        "camera_dip_isp7.ko",
        "fdvt_dip1.ko",
        "mtk_ccu_fw.bin",
        "mali_kbase_mt6771_r49p0.ko",
        "bmi160_i2c.ko",
        "bmp280_i2c.ko",
        "bma456.ko",
        "bmm150_i2c.ko",
        "icm42600_i2c.ko",
        "mpu6050.ko",
        "stk3x1x.ko",
        "stk8ba50.ko",
        "pn553.ko",
        "pn557_fw.bin",
        "sn100u_fw.bin",
        "nq_nci.ko",
        "goodix_fp_fw.bin",
        "goodix_touch_cfg.bin",
        "gt9286_cfg.bin",
        "silead_firmware.fw",
        "mssl1680a_fw.bin",
        "ft5416_ts.bin",
        "himax_mpimage.bin",
        "hx83112_fw.bin",
        "synaptics_ts.img",
        "syna_fp.bin",
        "ekt2202_iap.bin",
        "brcmfmac43455-sdio.bin",
        "bcm4345c5.hcd",
        "cyfmac43430-sdio.bin",
        "rtl8723bs_fw.bin",
        "rtw88_8822c_fw.bin",
        "rtw89_8852b_fw.bin",
        "a630_sqe.fw",
        "a660_gmu.bin",
        "venus-5.4.fw",
        "tps65987d_pdo.bin",
        "ccg3pa_fw.bin",
        "cs35l41_dsp1.bin",
        "tas2563_fw.bin",
        "nrf52840_fw.bin",
        "fpc1035_fw.bin",
    ]
    hits = sum(1 for p in probes if match(p) is not None)
    # Require at least 40 of the probes to match (we aim for all of them,
    # but some regexes are intentionally conservative).
    assert hits >= 40, f"only {hits}/{len(probes)} probes matched a pattern"


# ---------------------------------------------------------------------------
# Path-context tests — added 2026-05-15 for the DS1 Moto-G32 + G30 fix that
# rescues / refines blobs in known extraction-tree partitions (radio.img,
# BTFM.bin, dspso.bin, bootloader.img) using YAML-driven path_contexts:.
# ---------------------------------------------------------------------------


def test_path_contexts_yaml_loads() -> None:
    """firmware_patterns.yaml::path_contexts must populate the loader.

    Updated 2026-05-18 (YAML hot-reload migration): the module-level
    ``_PATH_CONTEXTS`` constant was replaced with the mtime-cached
    ``_PATH_CONTEXTS_LOADER`` instance whose ``.get()`` returns the
    current compiled list. Public accessor: ``match_path_context``.
    """
    from app.services.hardware_firmware.patterns_loader import (
        _PATH_CONTEXTS_LOADER,
    )

    path_contexts = _PATH_CONTEXTS_LOADER.get()
    assert isinstance(path_contexts, list)
    assert len(path_contexts) >= 14, (
        "expected at least 14 path_contexts entries (radio.img / BTFM / dspso /"
        " bootloader / RFNV / EFS / FSG / WLAN / GPU / carrier / bluedroid-system"
        " / bluedroid-vendor / bluedroid-daemon / wpa_supplicant-bin / wpa-libwpa)"
    )
    # Each tuple: (path_rx, filename_rx_or_None, PathContextMatch).
    for path_rx, filename_rx, tmpl in path_contexts:
        assert path_rx is not None
        assert isinstance(tmpl, PathContextMatch)
        assert tmpl.category in classifier.CATEGORIES, (
            f"path-context category {tmpl.category!r} not in CATEGORIES"
        )
        assert tmpl.confidence in {"high", "medium", "low"}


def test_path_context_match_rfnv() -> None:
    """RFNV calibration item path → modem (high confidence)."""
    p = (
        "/data/firmware/projects/x/firmware/y/extracted/Moto-G32-XT2235-1.zip_extract/"
        "radio.img_extract/extfs/efs_item_files/nv/item_files/rfnv/00123.bin"
    )
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "qualcomm"
    assert m.category == "modem"
    assert m.confidence == "high"


def test_path_context_match_btfm() -> None:
    """BTFM.bin tree → bluetooth/qualcomm (corrected 2026-05-15)."""
    p = "/x/Moto-G32-XT2235-1.zip_extract/BTFM.bin_extract/raw.image_extract/image/unknown.tlv"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "qualcomm"
    assert m.category == "bluetooth"


def test_path_context_match_bluedroid_apex() -> None:
    """libbluetooth.so under Android 12+ APEX → bluetooth/aosp."""
    p = "/apex/com.android.btservices/lib64/libbluetooth_jni.so"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "aosp"
    assert m.category == "bluetooth"
    assert m.product is not None and "Bluedroid" in m.product


def test_path_context_match_bluedroid_system_lib() -> None:
    """Pre-Android-12 libbluetooth.so under /system/lib64/ → bluetooth/aosp."""
    p = "/system/lib64/libbluetooth.so"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "aosp"
    assert m.category == "bluetooth"


def test_path_context_match_bluedroid_vendor_qti() -> None:
    """libbt-vendor-qti.so / libbluetooth_qti.so → bluetooth/qualcomm."""
    p = "/vendor/lib64/libbt-vendor-qti.so"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "qualcomm"
    assert m.category == "bluetooth"


def test_path_context_match_wpa_supplicant_vendor_hw() -> None:
    """wpa_supplicant under /vendor/bin/hw/ (modern Android HAL) → wifi/aosp."""
    p = "/vendor/bin/hw/wpa_supplicant"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "aosp"
    assert m.category == "wifi"
    assert m.product is not None and "wpa_supplicant" in m.product


def test_path_context_match_wpa_supplicant_system_bin() -> None:
    """wpa_supplicant under /system/bin/ (legacy / GKI) → wifi/aosp."""
    p = "/system/bin/wpa_supplicant"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "aosp"
    assert m.category == "wifi"


def test_path_context_match_wpa_supplicant_libwpa_client() -> None:
    """libwpa_client.so → wifi/aosp."""
    p = "/system/lib64/libwpa_client.so"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "aosp"
    assert m.category == "wifi"


def test_path_context_match_dspso() -> None:
    """dspso.bin/adsp and /cdsp must split into audio vs dsp categories."""
    p_adsp = "/x/Moto-G32-XT2235-1.zip_extract/dspso.bin_extract/adsp/something.bin"
    p_cdsp = "/x/Moto-G32-XT2235-1.zip_extract/dspso.bin_extract/cdsp/something.bin"
    m_adsp = match_path_context(p_adsp)
    m_cdsp = match_path_context(p_cdsp)
    assert m_adsp is not None and m_adsp.category == "audio"
    assert m_cdsp is not None and m_cdsp.category == "dsp"


def test_path_context_match_wlan_split() -> None:
    """bdwlan.b0X (Qualcomm WLAN combo split chunk) in radio.img → wifi."""
    p = "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/bdwlan.b04"
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "qualcomm"
    assert m.category == "wifi"


def test_path_context_match_carrier_config() -> None:
    """Carrier-named .mbn (att_usa_volte.mbn) inside radio.img → modem high."""
    p = (
        "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/"
        "carrier_config/att_usa_volte.mbn"
    )
    m = match_path_context(p)
    assert m is not None
    assert m.vendor == "qualcomm"
    assert m.category == "modem"
    assert m.confidence == "high"


def test_path_context_no_match_for_random_path() -> None:
    """Paths outside any known extraction tree must NOT match anything."""
    assert match_path_context("/data/random/place/something.bin") is None
    assert match_path_context("/tmp/somerandom/file") is None
    assert match_path_context("") is None
    assert match_path_context("/") is None


def test_path_context_priority_ordering() -> None:
    """RFNV (priority=30) must beat the radio.img catch-all (priority=5)."""
    # Path inside radio.img with the RFNV subpath. Both rules match the path
    # regex; the higher-priority RFNV rule must win.
    p = (
        "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/"
        "efs_item_files/nv/item_files/rfnv/some.bin"
    )
    m = match_path_context(p)
    assert m is not None
    # priority=30 entry sets confidence="high" + product mentions RFNV.
    assert m.priority >= 25
    assert m.confidence == "high"
    assert m.product is not None
    assert "RFNV" in m.product


# ---------------------------------------------------------------------------
# Classifier integration — path-context as REFINE / RESCUE step.
# ---------------------------------------------------------------------------


def test_classify_rescue_rfnv_returns_modem_not_none() -> None:
    """A raw_bin file in RFNV that filename + magic wouldn't classify gets
    rescued by path-context into modem/qualcomm — was None before this fix."""
    p = (
        "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/"
        "efs_item_files/nv/item_files/rfnv/00123.bin"
    )
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is not None
    assert cls.category == "modem"
    assert cls.vendor == "qualcomm"
    # Rescue path uses format="raw_bin" because path alone gives no format hint.
    assert cls.format == "raw_bin"


def test_classify_refine_carrier_mbn_moves_other_to_modem() -> None:
    """A carrier .mbn (e.g. att_usa_volte.mbn) was qualcomm/other under the
    old qcom-prefix if-chain; path-context refines it to qualcomm/modem."""
    p = (
        "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/"
        "carrier_config/att_usa_volte.mbn"
    )
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is not None
    assert cls.category == "modem"
    assert cls.vendor == "qualcomm"
    # Filename format wins — refine keeps qcom_mbn.
    assert cls.format == "qcom_mbn"


def test_classify_refine_wlan_split_other_to_wifi() -> None:
    """bdwlan.b04 inside radio.img was qualcomm/other; refines to wifi."""
    p = "/x/Moto-G32-XT2235-1.zip_extract/radio.img_extract/extfs/bdwlan.b04"
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is not None
    assert cls.category == "wifi"
    assert cls.vendor == "qualcomm"


def test_classify_rescue_btfm_unmatched_sub_blob() -> None:
    """A file inside BTFM.bin_extract that doesn't match any BTFM filename
    pattern still gets rescued to bluetooth/qualcomm via path-context.
    (vendor corrected from broadcom to qualcomm 2026-05-15.)"""
    p = "/x/Moto-G32-XT2235-1.zip_extract/BTFM.bin_extract/raw.image_extract/image/unknown.dat"
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is not None
    assert cls.category == "bluetooth"
    assert cls.vendor == "qualcomm"


def test_classify_path_context_does_not_demote_specific_category() -> None:
    """A filename that classifies as (qualcomm, bluetooth) via the BTFM
    YAML pattern must STAY that way — path-context contract says it never
    overrides a non-"other" category. Regression guard for the precedence
    rule. (Vendor corrected from broadcom to qualcomm 2026-05-15.)"""
    # cmbtfw10.tlv matches firmware_patterns.yaml's
    # "^[a-z]{2}btfw[0-9]+\\.(tlv|ver)$" with vendor=qualcomm + category=bluetooth.
    p = "/x/Moto-G32-XT2235-1.zip_extract/BTFM.bin_extract/raw.image_extract/image/cmbtfw10.tlv"
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is not None
    assert cls.category == "bluetooth"
    assert cls.vendor == "qualcomm"
    # Confidence comes from the filename pattern (high), NOT from the path
    # rule (which would have produced medium). This verifies path-context
    # did not run on the already-specific filename match.
    assert cls.confidence == "high"


def test_classify_unmatched_path_still_returns_none() -> None:
    """Paths outside any known partition tree get None (skipped), confirming
    path-context doesn't over-promote arbitrary files into firmware blobs."""
    p = "/var/lib/somewhere/random.bin"
    cls = classify(p, _RAW_BIN_MAGIC, 4096)
    assert cls is None
