"""Linux kernel image parser (zImage / uImage / vmlinuz / Image).

Extracts the embedded IKCFG ``.config`` (when present, i.e. the kernel
was built with ``CONFIG_IKCONFIG=y``) plus the ``Linux version`` banner
SemVer.  Populates ``HardwareFirmwareBlob.metadata`` so the downstream
``linux_kernel_hardening_walker`` (separate PR) can emit Findings for
insecure / weak / missing kernel hardening configs.

Architecture (per Scout B + Scout D synthesis)
----------------------------------------------
Parser stays **parse-only** per Rule #45 — surface metadata, NEVER act
on the kernel binary (no subprocess invocation, no kernel image gets
``argv[0]``'d).  The walker is a separate PR that consumes
``metadata.kernel_config`` and emits Findings via ``FindingService``.

Multi-format dispatch follows the ``dtb.py`` precedent: one ``parse()``
body + 4 subclasses with distinct ``FORMAT`` strings so the existing
``firmware_patterns.yaml`` classifier entries (``zImage`` / ``uImage`` /
``vmlinuz`` / ``Image``) all dispatch to this parser.

Wave-2 critique mitigations applied here
----------------------------------------
- Attack D (OOM on 100 MB+ blob): ``_MAX_KERNEL_BYTES = 64 MB`` cap
  (matches ``dtb.py`` precedent + the detector's 128 MB outer cap).
- Attack F (gzip-bomb IKCFG payload): handled in the shared helper.
- Attack E (license): AGPL-3.0 wairz + the helper's pure-stdlib code →
  no transitive license risk.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

from app.services.hardware_firmware.parsers._kernel_ikconfig import (
    extract_ikconfig,
    find_linux_banner,
    parse_kernel_config_lines,
)
from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)

# Per Scout B: detector caps blobs at 128 MB; parsers should re-cap
# tighter to bound their own working set.  Real kernel images run
# 10-40 MB; 64 MB is comfortable headroom.
_MAX_KERNEL_BYTES = 64 * 1024 * 1024  # 64 MB

# Filename-driven kernel vendor inference.  Mirrors the kmod.py
# precedent: most-specific to most-generic.  Filename is the strongest
# vendor signal for kernel-Image blobs (the banner gcc build-host
# string is a SECONDARY signal we capture in metadata but don't use
# for the canonical vendor field).
_KERNEL_VENDOR_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # NVIDIA Tegra L4T family (the original DS1 use case)
    (re.compile(r"(tegra|l4t|jetson)", re.IGNORECASE), "nvidia"),
    # MediaTek
    (re.compile(r"^(mtk|mt[0-9]{4})", re.IGNORECASE), "mediatek"),
    # Qualcomm
    (re.compile(r"(qcom|msm|sdm|sm[0-9]{4})", re.IGNORECASE), "qualcomm"),
    # Broadcom
    (re.compile(r"(bcm[0-9]{3,5}|broadcom)", re.IGNORECASE), "broadcom"),
    # Samsung Exynos
    (re.compile(r"(exynos|samsung)", re.IGNORECASE), "samsung"),
]


def _infer_kernel_vendor(path: str, banner: str | None) -> str | None:
    """Derive a vendor string from filename + banner content.

    Returns ``None`` when no signal — the classifier's filename-derived
    vendor (already set on ``Classification``) will be used.  Returning
    a value OVERRIDES the classifier vendor per Rule #19 content-evidence
    discipline (see kmod.py + the BTFM→Broadcom 2026-05-15 postmortem).
    """
    basename = os.path.basename(path).lower()
    for pattern, vendor in _KERNEL_VENDOR_PATTERNS:
        if pattern.search(basename):
            return vendor
    if banner:
        for pattern, vendor in _KERNEL_VENDOR_PATTERNS:
            if pattern.search(banner):
                return vendor
    return None


def _parse_kernel_image(path: str, magic: bytes, size: int) -> ParsedBlob:
    """Single ``parse()`` body shared by all four FORMAT subclasses.

    Returns ``ParsedBlob`` with:

    - ``version``: ``kernel_semver`` (e.g. ``"4.9.140"``) if banner found
    - ``vendor``: filename / banner-driven inference (Rule #19 override)
    - ``metadata``:
      * ``kernel_banner`` — full banner string (e.g. ``"Linux version
        4.9.140-tegra (buildbrain@mobile-u64-1935) (gcc 7.3.1) ..."``)
      * ``kernel_semver`` — leading SemVer for CVE matcher
      * ``ikconfig_present`` — bool; True when IKCFG markers extracted
      * ``ikconfig_size`` — decompressed .config size in bytes
      * ``kernel_config`` — dict[str, str] of CONFIG_FOO → 'y'|'m'|'n'|value
      * ``kernel_config_count`` — len(kernel_config)
      * ``error`` — only set on internal exception per base.py contract
    """
    meta: dict[str, Any] = {}
    version: str | None = None
    vendor: str | None = None

    try:
        # Bounded read — even a 30 MB Image fits in well under our cap;
        # the parser reads the full image because the IKCFG marker can
        # be anywhere (Tegra: at offset 15M; Yocto: typically later).
        read_size = min(size, _MAX_KERNEL_BYTES)
        with open(path, "rb") as f:
            data = f.read(read_size)
    except OSError as exc:
        return ParsedBlob(metadata={"error": f"open/read: {exc}"})

    # Banner extraction first — cheaper than IKCFG scan + tells us
    # whether this is plausibly a Linux kernel at all (the
    # firmware_patterns.yaml classifier matches FILENAMES, which can
    # produce false positives for non-kernel files with kernel-like
    # names; the banner is content-evidence).
    try:
        banner_result = find_linux_banner(data)
    except Exception as exc:  # noqa: BLE001
        logger.debug("kernel_image: find_linux_banner failed on %s: %s", path, exc)
        banner_result = None

    if banner_result is not None:
        meta["kernel_banner"] = banner_result["banner"]
        if banner_result.get("kernel_semver"):
            meta["kernel_semver"] = banner_result["kernel_semver"]
            version = banner_result["kernel_semver"]

    # IKCFG extraction — only when CONFIG_IKCONFIG=y was set at build.
    # Returns None for the common case (most distros / vendors strip
    # IKCFG for size); not an error, just no embedded config.
    try:
        config_text = extract_ikconfig(data)
    except Exception as exc:  # noqa: BLE001
        logger.debug("kernel_image: extract_ikconfig failed on %s: %s", path, exc)
        config_text = None

    if config_text is not None:
        try:
            config_map = parse_kernel_config_lines(config_text)
        except Exception as exc:  # noqa: BLE001
            logger.debug("kernel_image: parse_kernel_config_lines failed on %s: %s", path, exc)
            config_map = {}
        meta["ikconfig_present"] = True
        meta["ikconfig_size"] = len(config_text)
        meta["kernel_config"] = config_map
        meta["kernel_config_count"] = len(config_map)
        # LOCALVERSION can refine the version field if no banner SemVer.
        if version is None:
            localver = config_map.get("CONFIG_LOCALVERSION", "").strip('"').strip()
            if localver:
                meta["kernel_localversion"] = localver
    else:
        meta["ikconfig_present"] = False

    # Vendor inference is filename-first, banner-second.  Only set when
    # we have a non-None signal — leaving it None lets the classifier's
    # filename-derived vendor flow through unchanged.
    vendor = _infer_kernel_vendor(path, meta.get("kernel_banner"))

    return ParsedBlob(
        version=version,
        vendor=vendor,
        metadata=meta,
    )


class _KernelImageParserBase:
    """Common ``parse()`` body shared by all four FORMAT-specific subclasses."""

    FORMAT: str  # set on each concrete subclass

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        return _parse_kernel_image(path, magic, size)


class ZimageParser(_KernelImageParserBase):
    FORMAT = "zImage"


class UimageParser(_KernelImageParserBase):
    FORMAT = "uImage"


class VmlinuzParser(_KernelImageParserBase):
    FORMAT = "vmlinuz"


class ImageParser(_KernelImageParserBase):
    """ARM64 raw kernel Image (Tegra, OpenWrt-arm64, generic aarch64)."""

    FORMAT = "Image"


# Self-register all four on import (mirrors dtb.py precedent).
register_parser(ZimageParser())
register_parser(UimageParser())
register_parser(VmlinuzParser())
register_parser(ImageParser())
