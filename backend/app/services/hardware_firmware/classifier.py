from __future__ import annotations

import os
import re
from dataclasses import dataclass

from app.services.hardware_firmware.patterns_loader import VENDORS
from app.services.hardware_firmware.patterns_loader import match as pattern_match
from app.services.hardware_firmware.patterns_loader import (
    match_path_context as _path_context_match,
)

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
    "mbn_v3",
    "mbn_v5",
    "mbn_v6",
    "elf",
    "dtb",
    "dtbo",
    "ko",
    "fw_bcm",
    "raw_bin",
    "tzbsp",
    "kinibi_mclf",
    "optee_ta",
    "shannon_toc",
    # Phase 3 — MediaTek + Awinic native parsers
    "mtk_lk",
    "mtk_preloader",
    "mtk_modem",
    "mtk_wifi_hdr",
    # Phase C — MediaTek subsystem-specific parsers (strip LK container
    # + route to role-aware analysis). All share the 0x58881688 outer
    # magic; dispatch is by the partition name embedded in the LK header.
    "mtk_atf",
    "mtk_geniezone",
    "mtk_tinysys",
    "awinic_acf",
    # MCU / kernel / opaque-archive placeholders
    "imxrt_bin",
    "zImage",
    "uImage",
    "vmlinuz",
    "signed_archive",
    # Bluetooth firmware banner-string parser (content-evidence vendor
    # attribution — QCA Rome BTFM, Broadcom HCD, MediaTek WMT). Routes
    # via firmware_patterns.yaml ``format: bt_fw_banner`` entries so
    # the parser auto-fires on BTFM.bin / bt_fw / .hcd / .tlv inputs.
    "bt_fw_banner",
}


# Re-export VENDORS from patterns_loader so callers that used to import the
# hard-coded constant keep working.  The loader seeds the Wairz core set
# (qualcomm, mediatek, samsung, broadcom, nvidia, imagination, arm, apple,
# cypress, unisoc, hisilicon, intel, realtek, unknown) even when YAML is
# absent, so nothing downstream loses vendors.
__all__ = ["CATEGORIES", "FORMATS", "VENDORS", "Classification", "classify"]


@dataclass
class Classification:
    """Result of classifying a firmware blob candidate."""

    category: str
    vendor: str
    format: str
    confidence: str  # high|medium|low
    product: str | None = None


# Qualcomm PIL filename patterns (stems + extensions).  Case-insensitive.
# These stay hand-rolled: the Qualcomm stem list is already comprehensive and
# the category inference (_category_from_qcom_name) depends on substring
# semantics that don't map cleanly to per-blob YAML rules.
_QCOM_EXT = re.compile(r"\.(mbn|mdt|b0[0-9a-f])$", re.IGNORECASE)
_QCOM_STEMS = {
    "xbl.elf",
    "xbl_config.elf",
    "tz.mbn",
    "hyp.mbn",
    "aop.mbn",
    "adsp.mbn",
    "cdsp.mbn",
    "modem.mbn",
    "slpi.mbn",
    "wlanmdsp.mbn",
    "mba.mbn",
    "abl.elf",
    "rpm.mbn",
    "sbl1.mbn",
    "aboot.mbn",
    "devcfg.mbn",
    "cmnlib.mbn",
    "cmnlib64.mbn",
    "keymaster.mbn",
    "qupfw.mbn",
    "tzbsp.mbn",
}

# Qualcomm Adreno GPU firmware (aNNN_zap/sqe/gmu) — kept as a fallback so
# the ELF-as-Adreno path in classify() stays symmetrical with the pre-YAML
# behaviour.  Raw-bin Adreno blobs are caught by firmware_patterns.yaml.
_ADRENO_RE = re.compile(r"^a\d+_(zap|sqe|gmu)\b", re.IGNORECASE)

# Qualcomm Venus video codec / IPA network accelerator — ELF-only heuristic.
_VENUS_RE = re.compile(r"^(venus\.mbn|video-firmware\.elf)$", re.IGNORECASE)
_IPA_RE = re.compile(r"^(ipa_fws\.elf|ipa_uc\.elf)$", re.IGNORECASE)

# Kinibi TA by extension — raw-bin fallback when TRUS magic doesn't match.
_TLBIN_RE = re.compile(r"\.tlbin$", re.IGNORECASE)

# Firmware-partition directory hints (Qualcomm-specific — keeps the
# fallback-to-qualcomm ELF behaviour for .b00/.b01/.bNN chunks).
_FW_PARTITION_HINTS = (
    "/vendor/firmware_mnt/",
    "/firmware/image/",
)

# "This is a firmware blob" path signals — must be specific enough NOT to
# match the container storage root (e.g. /data/firmware/) or other
# coincidental substrings.  We require a partition-style prefix.
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
    # e_type is at offset 16-17, little-endian for ELFCLASS32/64 on LE hosts.
    # Android kernel modules are always LE in practice.
    if magic[5] == 1:  # EI_DATA = 1 => little-endian
        return magic[16] == 0x01 and magic[17] == 0x00
    return magic[16] == 0x00 and magic[17] == 0x01


def _classify_by_magic(magic: bytes) -> Classification | None:
    """First pass: classify by the first 64 bytes."""
    if len(magic) < 4:
        return None

    # Device tree blob (flat DTB)
    if magic[:4] == b"\xd0\x0d\xfe\xed":
        return Classification("dtb", "unknown", "dtb", "high")

    # Android DTBO container
    if magic[:4] == b"\xd7\xb7\xab\x1e":
        return Classification("dtb", "unknown", "dtbo", "high")

    # Samsung Shannon TOC (modem)
    if magic[:4] == b"TOC\x00":
        return Classification("modem", "samsung", "shannon_toc", "high")

    # Kinibi MCLF (TrustZone TA — Samsung Exynos or MediaTek)
    if magic[:4] == b"TRUS":
        return Classification("tee", "unknown", "kinibi_mclf", "high")

    # MediaTek LK partition record (magic 0x58881688, little-endian).
    # Dispatch by partition-name to the right Wairz category AND to a
    # role-specific parser (mtk_atf / mtk_geniezone / mtk_tinysys) when
    # one exists. Unrecognised names fall back to mtk_lk.
    if magic[:4] == b"\x88\x16\x88\x58":
        from app.services.hardware_firmware.parsers.mediatek_gfh import (
            lookup_partition,
            parse_lk_header,
        )
        hdr = parse_lk_header(magic)
        if hdr is not None and hdr.name:
            name_lower = hdr.name.lower()
            dispatch = lookup_partition(hdr.name)
            # Category comes from the authoritative name→category table;
            # format comes from whether a role-specific parser exists.
            # scp → ("mcu", "tinysys") → format=mtk_tinysys
            # sspm → ("mcu", "tinysys") → format=mtk_tinysys
            # atf → ("tee", "atf") → format=mtk_atf
            # gz → ("tee", "geniezone") → format=mtk_geniezone
            if name_lower == "atf":
                cat = dispatch[0] if dispatch else "tee"
                return Classification(cat, "mediatek", "mtk_atf", "high")
            if name_lower == "gz":
                cat = dispatch[0] if dispatch else "tee"
                return Classification(cat, "mediatek", "mtk_geniezone", "high")
            if (
                name_lower in ("scp", "sspm", "mcupm", "dpm", "spmfw")
                or name_lower.startswith("tinysys")
            ):
                cat = dispatch[0] if dispatch else "mcu"
                return Classification(cat, "mediatek", "mtk_tinysys", "high")
            # Everything else — logo, cam_vpu, md1rom, lk — routes
            # through the generic mtk_lk parser with category from the
            # name-lookup table.
            if dispatch is not None:
                category, _component = dispatch
                return Classification(category, "mediatek", "mtk_lk", "high")
        return Classification("bootloader", "mediatek", "mtk_lk", "high")

    # MediaTek preloader: MMM\x01 header, second byte starts with 0x38
    if len(magic) >= 5 and magic[:4] == b"MMM\x01" and magic[4] == 0x38:
        return Classification("bootloader", "mediatek", "mtk_preloader", "high")

    # Linux ARM zImage: magic 0x016F2818 at offset 0x24 (Documentation/arm/booting.rst)
    if len(magic) >= 0x28 and magic[0x24:0x28] == b"\x18\x28\x6f\x01":
        return Classification("kernel", "unknown", "zImage", "high")

    # Vendor-specific signed archive (seen on RespArray / Edan firmware bundles).
    # Header is opaque — separable from their .signature sidecar files — so we
    # surface a placeholder entry rather than skipping the file silently.
    if magic[:4] == b"\xa3\xdf\xbb\xbf":
        return Classification("other", "unknown", "signed_archive", "medium")

    return None


def _apply_path_context(
    path: str, result: Classification | None
) -> Classification | None:
    """Apply YAML-driven path_contexts rules to refine or rescue a result.

    Two modes:
      1. **Refine** — when ``result.category == "other"``, a matching
         path-context rule replaces the category (e.g. "other" → "modem").
         Vendor is taken from the rule unless it says "unknown" (then the
         filename-inferred vendor is preserved). Format is ALWAYS preserved
         from the filename match — it captures content shape (qcom_mbn /
         raw_bin / elf / …) which the path doesn't know about. Confidence
         and product come from the rule.
      2. **Rescue** — when ``result is None`` (filename + magic produced no
         match), a matching path-context rule builds a Classification from
         scratch with ``format="raw_bin"`` (path alone gives no format hint)
         and the rule's vendor/category/confidence/product.

    When no path_contexts entry matches, returns the input unchanged
    (refine → original "other" classification; rescue → ``None``).

    Path-context CANNOT demote a specific (non-"other") filename match —
    that contract preserves the precedence of filename evidence over path
    evidence, which is the right call when both signals are available.
    """
    if result is not None and result.category != "other":
        return result
    pcm = _path_context_match(path)
    if pcm is None:
        return result
    if result is None:
        # Rescue: no filename match, but path tells us where it lives.
        new_vendor = pcm.vendor if pcm.vendor and pcm.vendor != "unknown" else "unknown"
        return Classification(
            category=pcm.category,
            vendor=new_vendor,
            format="raw_bin",
            confidence=pcm.confidence,
            product=pcm.product,
        )
    # Refine: category="other" → specific via path-context.
    # Reviewer A M1 (2026-05-15): preserve filename-inferred vendor
    # when it's a known specific vendor. Path-context vendor wins only
    # when the filename inferred vendor was "unknown" / unset. This
    # prevents a `radio.img` rule (vendor:qualcomm) from clobbering a
    # filename that was matched as `vendor:broadcom` with
    # category="other" — filename evidence beats path evidence for
    # vendor, mirroring the same precedence rule used for category.
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

    Order of precedence (each step short-circuits on match):
      1. Kernel module — ELF + ET_REL + ``.ko`` extension.
      2. Magic-byte — DTB, DTBO, Shannon TOC, Kinibi MCLF, MTK LK, MTK preloader.
      3. Qualcomm PIL — comprehensive stem/extension list (Adreno + PIL).
      4. Filename patterns — YAML-driven classifier (broad vendor coverage).
      5. Kinibi ``.tlbin`` / MCRegistry — fallback when TRUS magic is absent.
      6. DTB/DTBO by extension — fallback when magic bytes are missing.
      7. Path fallback — any file in a known firmware partition is captured.
      8. Path-context refinement — for blobs whose filename matched with
         ``category="other"``, a YAML-driven path_contexts rule can rescue
         them into a specific category (modem / audio / dsp / bluetooth /
         gpu / wifi / …) based on the extraction-tree path. See
         :func:`_refine_via_path_context` for the contract. Data-driven and
         vendor-agnostic — extend by editing firmware_patterns.yaml's
         ``path_contexts:`` section, no Python change required.
    """
    name = os.path.basename(path)
    lname = name.lower()
    lpath = path.replace(os.sep, "/").lower()

    def _classify_filename_only() -> Classification | None:
        return _classify_inner(path, name, lname, lpath, magic)

    result = _classify_filename_only()
    # Step 8 — path-context: rescue (None → Classification) AND refine
    # ("other" → specific category). See :func:`_apply_path_context` for
    # the precedence contract.
    return _apply_path_context(lpath, result)


def _classify_inner(
    path: str, name: str, lname: str, lpath: str, magic: bytes
) -> Classification | None:
    """Filename + magic-only classification (Steps 1–7).

    Extracted so :func:`classify` can wrap the result in a path-context
    refinement step (Step 8) without per-return entanglement. Returns
    ``None`` when no classifier rule matches.
    """
    primary = _classify_by_magic(magic)
    is_elf = len(magic) >= 4 and magic[:4] == b"\x7fELF"

    # Kernel module: ELF with ET_REL and .ko extension.  We still need the
    # ELF + ET_REL check — YAML can only match on filename, but many .ko
    # files in Android trees are actually shared-object plug-ins or stub
    # firmware renamed with a .ko suffix.
    if lname.endswith(".ko") and is_elf and _is_elf_relocatable(magic):
        # Pattern table may supply vendor/category/product (e.g. mali_kbase_*,
        # bmi160_*, stk3x1x*).  Fall back to "unknown" / "kernel_module" if
        # no YAML entry catches it.
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
    if is_elf and primary is None:
        # Adreno GPU firmware (kept as a fast-path over YAML)
        if _ADRENO_RE.match(name):
            return Classification("gpu", "qualcomm", "elf", "high")
        # Qualcomm PIL (single-file or split .b0X)
        if _is_qcom_filename(name):
            cat = _category_from_qcom_name(name)
            return Classification(cat, "qualcomm", "qcom_mbn", "high")
        # YAML pattern lookup — runs BEFORE the Venus/firmware-path/etc.
        # fallbacks so vendor-specific ELF firmware (lib3a.ccu, vendor
        # camera/audio/codec ELFs) get their proper category instead of
        # bucket-defaulting to ``other``.  Force format="elf" since we
        # already verified the magic; the YAML pattern's default
        # "raw_bin" would otherwise misreport the container.
        pm = pattern_match(name)
        if pm is not None:
            return Classification(
                category=pm.category,
                vendor=pm.vendor,
                format="elf",
                confidence=pm.confidence,
                product=pm.product,
            )
        # Venus video codec / IPA network accel (Qualcomm)
        if _VENUS_RE.match(name) or _IPA_RE.match(name):
            return Classification("other", "qualcomm", "elf", "medium")
        # In Qualcomm firmware-mount partition — likely PIL ELF
        if any(hint in lpath for hint in _FW_PARTITION_HINTS):
            return Classification("other", "qualcomm", "elf", "low")
        # Any other ELF under /vendor/firmware/ etc. is still worth capturing
        if _is_firmware_path(lpath):
            return Classification("other", "unknown", "elf", "low")
        # Regular system/vendor binaries (e.g. /system/bin/*, /vendor/lib/*.so)
        # are NOT hardware firmware — skip them so we don't flood the UI.
        return None

    # Qualcomm split PIL pieces (.b00..b0F, .mdt) even if magic didn't hit ELF
    # at .bNN start.  Keep this above the YAML pipeline — the PIL split-file
    # heuristic requires the stem-table lookup, which is hard to express in
    # YAML without false positives.
    if primary is None and _is_qcom_filename(name):
        cat = _category_from_qcom_name(name)
        return Classification(cat, "qualcomm", "qcom_mbn", "medium")

    # YAML-driven filename pipeline.  Handles vendor Wi-Fi, BT, touch,
    # sensors, NFC, modem, audio, USB-PD, etc.
    if primary is None:
        pm = pattern_match(name)
        if pm is not None:
            return Classification(
                category=pm.category,
                vendor=pm.vendor,
                format=pm.format,
                confidence=pm.confidence,
                product=pm.product,
            )

    # Kinibi TA by extension (.tlbin) when magic didn't match TRUS (some variants)
    if primary is None and (_TLBIN_RE.search(lname) or "mcregistry" in lpath):
        return Classification("tee", "unknown", "kinibi_mclf", "medium")

    # DTB/DTBO files by extension without matching magic (unlikely but cheap)
    if primary is None and (lname.endswith(".dtb") or lname.endswith(".dtbo")):
        fmt = "dtbo" if lname.endswith(".dtbo") else "dtb"
        return Classification("dtb", "unknown", fmt, "medium")

    if primary is not None:
        return primary

    # Fallback: anything in a known firmware-partition directory that didn't
    # match a specific pattern is almost certainly some form of hardware
    # firmware (vendor chipset blobs without explicit extensions, config
    # blobs, patch files, etc.).  Low confidence, but captured.
    if _is_firmware_path(lpath):
        return Classification("other", "unknown", "raw_bin", "low")

    # Nothing matched — skip.
    return None
