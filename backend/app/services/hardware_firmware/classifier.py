"""Hardware-firmware blob classifier — catalog-driven dispatch (P3.1.h).

Cut-over per P3.1.h:

* Magic-byte classification routes through the file-format catalog at
  :mod:`app.services.file_format_catalog`. YAML manifests at
  ``data/file_formats/`` declare detection signals + classifier output.
* The legacy filename-pattern path
  (:func:`app.services.hardware_firmware.patterns_loader.match`) +
  path-context refinement are PRESERVED — they cover Android partition
  paths + vendor extension tables the catalog does not yet express.

The pre-P3.1.h implementation lived at `classifier_legacy.py` as a
revert-safety shim through Phase 3.2; deleted in P3.3.a (2026-05-19)
after the parity test converted to JSON-snapshot form in P3.2.e. New
classification logic belongs in the catalog YAMLs.

The legacy public API is preserved:

    Classification(category, vendor, format, confidence, product)
    classify(path, magic, size) -> Classification | None
    CATEGORIES, FORMATS, VENDORS

Adding a new format_id to the catalog automatically expands what
``classify`` can return; the constants below are kept for backward
compatibility with existing import sites that grep these sets at
runtime.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass

from app.services.file_format_catalog import resolve as _catalog_resolve
from app.services.hardware_firmware.patterns_loader import VENDORS
from app.services.hardware_firmware.patterns_loader import match as pattern_match
from app.services.hardware_firmware.patterns_loader import (
    match_path_context as _path_context_match,
)


# Kept for backward compatibility with import sites that introspect these
# sets at runtime (frontend lookups, test discovery, MCP tool descriptions).
# The catalog is the source of truth for new formats — these sets are NOT
# exhaustive across all catalog-extensible vendor/format space.
CATEGORIES: set[str] = {
    "modem",
    "tee",
    "wifi",
    "bluetooth",
    "gpu",
    "dsp",
    "camera",
    "audio",
    "sensor",
    "touchpad",
    "nfc",
    "usb",
    "display",
    "fingerprint",
    "dtb",
    "kernel_module",
    "bootloader",
    "mcu",
    "kernel",
    "other",
}

FORMATS: set[str] = {
    "qcom_mbn",
    "mbn_v3", "mbn_v5", "mbn_v6",
    "elf", "dtb", "dtbo", "ko",
    "fw_bcm", "raw_bin", "tzbsp", "kinibi_mclf",
    "optee_ta", "shannon_toc",
    "mtk_lk", "mtk_preloader", "mtk_modem", "mtk_wifi_hdr",
    "mtk_atf", "mtk_geniezone", "mtk_tinysys",
    "awinic_acf",
    "imxrt_bin", "zImage", "uImage", "vmlinuz",
    "signed_archive",
    "bt_fw_banner",
}


__all__ = ["CATEGORIES", "FORMATS", "VENDORS", "Classification", "classify"]


@dataclass
class Classification:
    """Result of classifying a firmware blob candidate."""

    category: str
    vendor: str
    format: str
    confidence: str  # high|medium|low
    product: str | None = None


# Qualcomm PIL filename patterns — preserved verbatim from legacy. The catalog
# YAML can't yet express the stem table + ``_category_from_qcom_name`` derivation.
_QCOM_EXT = re.compile(r"\.(mbn|mdt|b0[0-9a-f])$", re.IGNORECASE)
_QCOM_STEMS = {
    "xbl.elf", "xbl_config.elf", "tz.mbn", "hyp.mbn", "aop.mbn",
    "adsp.mbn", "cdsp.mbn", "modem.mbn", "slpi.mbn", "wlanmdsp.mbn",
    "mba.mbn", "abl.elf", "rpm.mbn", "sbl1.mbn", "aboot.mbn",
    "devcfg.mbn", "cmnlib.mbn", "cmnlib64.mbn", "keymaster.mbn",
    "qupfw.mbn", "tzbsp.mbn",
}
_ADRENO_RE = re.compile(r"^a\d+_(zap|sqe|gmu)\b", re.IGNORECASE)
_VENUS_RE = re.compile(r"^(venus\.mbn|video-firmware\.elf)$", re.IGNORECASE)
_IPA_RE = re.compile(r"^(ipa_fws\.elf|ipa_uc\.elf)$", re.IGNORECASE)
_TLBIN_RE = re.compile(r"\.tlbin$", re.IGNORECASE)
_FW_PARTITION_HINTS = (
    "/vendor/firmware_mnt/",
    "/firmware/image/",
)
_FIRMWARE_PATH_SIGNALS = (
    "/vendor/firmware/",
    "/vendor/firmware_mnt/",
    "/vendor/etc/firmware/",
    "/vendor/dsp/",
    "/vendor/rfs/",
    "/vendor/app/mcregistry/",
    "/vendor/lib/modules/",
    "/system/etc/firmware/",
    "/system/vendor/firmware/",
    "/system/lib/modules/",
    "/system_ext/etc/firmware/",
    "/odm/firmware/",
    "/odm/etc/firmware/",
    "/product/firmware/",
)


# Catalog format_id -> legacy ``Classification.format`` translation when
# names diverge between the two registries. Where the catalog format_id
# already matches the legacy format, no entry is needed.
_CATALOG_FORMAT_TO_LEGACY: dict[str, str] = {
    "samsung_shannon_toc": "shannon_toc",
    "linux_fit_dtb": "dtb",
    "android_dtb": "dtb",
    "android_dtbo": "dtbo",
    "linux_zimage": "zImage",
    # These pass through unchanged: mtk_lk, mtk_preloader, mtk_atf,
    # mtk_geniezone, mtk_tinysys, signed_archive, kinibi_mclf
}


def _classification_from_catalog(
    catalog_format_id: str, catalog_vendor: str, catalog_category: str,
    catalog_confidence: str, catalog_product: str | None,
) -> Classification:
    """Translate a catalog match into a ``Classification`` dataclass."""
    legacy_format = _CATALOG_FORMAT_TO_LEGACY.get(
        catalog_format_id, catalog_format_id,
    )
    return Classification(
        category=catalog_category,
        vendor=catalog_vendor,
        format=legacy_format,
        confidence=catalog_confidence,
        product=catalog_product,
    )


def _is_firmware_path(lpath: str) -> bool:
    """True if the lowercase path matches a known firmware-blob directory."""
    return any(hint in lpath for hint in _FIRMWARE_PATH_SIGNALS)


def _is_qcom_filename(name: str) -> bool:
    """True if filename matches a Qualcomm PIL pattern."""
    lname = name.lower()
    if lname in _QCOM_STEMS:
        return True
    return bool(_QCOM_EXT.search(lname))


def _category_from_qcom_name(name: str) -> str:
    """Infer category from a Qualcomm PIL filename stem."""
    lname = name.lower()
    if lname.startswith(("modem", "mba", "wlanmdsp")) or lname.startswith("non-hlos"):
        return "modem"
    if lname.startswith(("tz", "hyp", "cmnlib", "keymaster", "tzbsp")):
        return "tee"
    if lname.startswith(("xbl", "sbl1", "abl", "aboot", "aop", "rpm", "devcfg", "qupfw")):
        return "bootloader"
    if lname.startswith("adsp"):
        return "audio"
    if lname.startswith("cdsp"):
        return "dsp"
    if lname.startswith("slpi"):
        return "sensor"
    if lname.startswith("venus"):
        return "other"
    return "other"


def _is_elf_relocatable(magic: bytes) -> bool:
    """True if the ELF at offset 0 has e_type == ET_REL (kernel module)."""
    if len(magic) < 18 or magic[:4] != b"\x7fELF":
        return False
    if magic[5] == 1:
        return magic[16] == 0x01 and magic[17] == 0x00
    return magic[16] == 0x00 and magic[17] == 0x01


def _classify_via_catalog(path: str, magic: bytes, size: int) -> Classification | None:
    """Magic-byte classification via the catalog resolver.

    Returns a ``Classification`` ONLY when the catalog yields a SPECIFIC
    match (i.e. not the always_matches ``linux_blob`` fallback). The
    catch-all is left as None so the caller can chain through the
    filename + path-context refinement steps below.
    """
    from app.services.file_format_catalog import get_default_catalog

    result = _catalog_resolve(magic, path, size)
    if result is None:
        return None
    # The linux_blob fallback is too coarse for the hardware-firmware
    # classifier — let the caller's filename / path refinement run instead.
    if result.format_id == "linux_blob":
        return None
    # PE/MZ negative evidence is intentionally low-confidence on this code
    # path; the legacy classifier returned None for bare PE binaries (those
    # aren't firmware blobs). Preserve that.
    if result.format_id == "pe_binary":
        return None
    # Upload-level / container formats — NOT individual firmware blob
    # classifications. These are surfaces for unpack workers, not entries
    # in the hardware_firmware blobs table. Let the legacy filename chain
    # below run instead so vendor-tagged inner blobs still classify.
    if result.format_id in {
        "iso_9660", "zip_archive", "tar_archive", "wim_archive",
        "windows_cab", "windows_msi", "windows_msix", "windows_msu",
        "windows_psf", "windows_vhdx", "windows_driver_package",
        "windows_installer_iso", "qnx_ifs", "android_apk", "android_ota",
        "android_scatter", "android_sparse", "android_boot",
        "uefi_firmware", "intel_hex", "rtos_blob", "acronis_backup",
        "partition_dump_tar", "rootfs_tar",
        # ELF is too generic for the firmware classifier — let the filename
        # refinement below decide (Qualcomm PIL, Adreno, etc.).
        "linux_elf",
        # Linux filesystem formats are upload-level, not firmware-blob.
        "linux_squashfs", "linux_cramfs", "linux_jffs2",
        "linux_uboot_uimage",
        "bt_fw_banner", "qcom_mbn_split",
        # P3.2.a: qcom_mbn YAML doesn't yet express the per-stem category
        # refinement (`_category_from_qcom_name` maps tz.mbn → tee,
        # modem.mbn → modem, etc.). Fall through to legacy filename chain
        # so stem-driven category resolution still runs. A future P3.x
        # YAML extension (Refinement.stem_category_map) closes the gap.
        "qcom_mbn",
    }:
        return None

    cat = get_default_catalog().get_catalog().get(result.format_id)
    if cat is None or cat.output is None:
        return None
    return _classification_from_catalog(
        catalog_format_id=result.format_id,
        catalog_vendor=cat.output.classifier_vendor,
        catalog_category=cat.output.classifier_category,
        catalog_confidence=cat.output.confidence,
        catalog_product=cat.output.classifier_product,
    )


def _apply_path_context(
    path: str, result: Classification | None,
) -> Classification | None:
    """Apply YAML-driven path_contexts rules to refine or rescue a result.

    Behaviour preserved from the legacy implementation:
      * **Refine** — when ``result.category == "other"``, a matching
        path-context rule replaces the category. Filename-inferred
        vendor is preserved when specific (Reviewer A M1, 2026-05-15).
      * **Rescue** — when ``result is None``, a matching rule produces a
        ``raw_bin`` Classification.
    """
    if result is not None and result.category != "other":
        return result
    pcm = _path_context_match(path)
    if pcm is None:
        return result
    if result is None:
        new_vendor = pcm.vendor if pcm.vendor and pcm.vendor != "unknown" else "unknown"
        return Classification(
            category=pcm.category,
            vendor=new_vendor,
            format="raw_bin",
            confidence=pcm.confidence,
            product=pcm.product,
        )
    filename_vendor = (result.vendor or "").lower()
    if filename_vendor and filename_vendor != "unknown":
        new_vendor = filename_vendor
    elif pcm.vendor and pcm.vendor != "unknown":
        new_vendor = pcm.vendor
    else:
        new_vendor = result.vendor
    return Classification(
        category=pcm.category,
        vendor=new_vendor,
        format=result.format,
        confidence=pcm.confidence,
        product=pcm.product or result.product,
    )


def classify(path: str, magic: bytes, size: int) -> Classification | None:
    """Classify a firmware blob candidate; return None to skip.

    Cut-over precedence (P3.1.h):
      0. **Catalog** — magic-byte match via the file-format catalog
         (``app.services.file_format_catalog.resolve``).
      1. Kernel module — ELF + ET_REL + ``.ko`` extension.
      2. Qualcomm PIL — comprehensive stem/extension list.
      3. Filename patterns — YAML-driven classifier (broad vendor coverage).
      4. Kinibi ``.tlbin`` / MCRegistry — fallback when TRUS magic is absent.
      5. DTB/DTBO by extension — fallback when magic bytes are missing.
      6. Path fallback — any file in a known firmware partition is captured.
      7. Path-context refinement — for blobs whose filename matched with
         ``category="other"``, a YAML-driven rule rescues them into a
         specific category.
    """
    name = os.path.basename(path)
    lname = name.lower()
    lpath = path.replace(os.sep, "/").lower()

    # 0. Catalog — magic-byte match for the canonical firmware-blob shapes.
    #
    # P3.2.a: the prior `_legacy_magic_classify` branch was deleted as the
    # resolver sort-tier reform (sentinels sort LAST via `sort_tier=floor`)
    # closes the catalog-uncovered shapes. The catalog now returns
    # mtk_lk / shannon_toc / kinibi_mclf / mtk_preloader / signed_archive /
    # dtb / dtbo directly because their `core` manifests (general tier)
    # beat `_system/linux_blob_fallback` (floor tier) in the new sort key.
    catalog_hit = _classify_via_catalog(path, magic, size)
    if catalog_hit is not None:
        return _apply_path_context(lpath, catalog_hit)

    result = _classify_inner(path, name, lname, lpath, magic)
    return _apply_path_context(lpath, result)


def _classify_inner(
    path: str, name: str, lname: str, lpath: str, magic: bytes,
) -> Classification | None:
    """Filename + magic-only classification — STEPS 1-7 (legacy fallback).

    The catalog handles Step 0 (magic-byte) up-front in :func:`classify`;
    this function runs ONLY when the catalog produced no specific match.
    Preserved verbatim from the legacy implementation so filename-driven
    rules (Qualcomm PIL, Adreno GPU, vendor pattern tables, .tlbin, .dtbo)
    continue to fire as before.
    """
    is_elf = len(magic) >= 4 and magic[:4] == b"\x7fELF"

    # Kernel module: ELF with ET_REL and .ko extension.
    if lname.endswith(".ko") and is_elf and _is_elf_relocatable(magic):
        pm = pattern_match(name)
        if pm is not None and pm.format == "ko":
            return Classification(
                category=pm.category,
                vendor=pm.vendor,
                format="ko",
                confidence=pm.confidence,
                product=pm.product,
            )
        return Classification("kernel_module", "unknown", "ko", "high")

    # ELF: secondary inspection via filename/path
    if is_elf:
        if _ADRENO_RE.match(name):
            return Classification("gpu", "qualcomm", "elf", "high")
        if _is_qcom_filename(name):
            cat = _category_from_qcom_name(name)
            return Classification(cat, "qualcomm", "qcom_mbn", "high")
        pm = pattern_match(name)
        if pm is not None:
            return Classification(
                category=pm.category,
                vendor=pm.vendor,
                format="elf",
                confidence=pm.confidence,
                product=pm.product,
            )
        if _VENUS_RE.match(name) or _IPA_RE.match(name):
            return Classification("other", "qualcomm", "elf", "medium")
        if any(hint in lpath for hint in _FW_PARTITION_HINTS):
            return Classification("other", "qualcomm", "elf", "low")
        if _is_firmware_path(lpath):
            return Classification("other", "unknown", "elf", "low")
        return None

    # Qualcomm split PIL pieces (.b00..b0F, .mdt) even if magic didn't hit ELF
    if _is_qcom_filename(name):
        cat = _category_from_qcom_name(name)
        return Classification(cat, "qualcomm", "qcom_mbn", "medium")

    # YAML-driven filename pipeline.
    pm = pattern_match(name)
    if pm is not None:
        return Classification(
            category=pm.category,
            vendor=pm.vendor,
            format=pm.format,
            confidence=pm.confidence,
            product=pm.product,
        )

    # Kinibi TA by extension (.tlbin) when magic didn't match TRUS
    if _TLBIN_RE.search(lname) or "mcregistry" in lpath:
        return Classification("tee", "unknown", "kinibi_mclf", "medium")

    # DTB/DTBO files by extension without matching magic
    if lname.endswith(".dtb") or lname.endswith(".dtbo"):
        fmt = "dtbo" if lname.endswith(".dtbo") else "dtb"
        return Classification("dtb", "unknown", fmt, "medium")

    # Fallback: anything in a known firmware-partition directory.
    if _is_firmware_path(lpath):
        return Classification("other", "unknown", "raw_bin", "low")

    return None
