"""Kernel module (.ko) parser.

Reads the ``.modinfo`` ELF section (NUL-separated ``key=value`` strings)
and the optional appended CMS signature magic ``~Module signature appended~``
to classify as ``signed`` / ``unknown``.

Extracts:

* ``license``, ``vermagic``, ``srcversion``, ``depends`` (list), ``alias``
  (list), and every ``firmware=<name>`` entry.
* ``version`` = the ``version`` field if present, else ``srcversion``.
* ``chipset_target`` — best-effort from ``vermagic`` / ``alias`` patterns.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from app.services.hardware_firmware.parsers.base import ParsedBlob, register_parser

logger = logging.getLogger(__name__)


# Magic that ``modinfo`` / kmod use to detect an appended CMS signature.
_MODSIG_MAGIC = b"~Module signature appended~"
_MODSIG_TAIL_BYTES = 256

# Chipset indicators commonly seen in vermagic / alias strings.
_CHIPSET_RES = (
    re.compile(r"(sm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(msm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(sdm[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(exynos[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(mt[0-9]{3,4})", re.IGNORECASE),
    re.compile(r"(bcm[0-9]{3,5})", re.IGNORECASE),
)

# Kernel semver prefix on a vermagic string (e.g. "6.6.102-android15-8-g...").
_KERNEL_SEMVER_RE = re.compile(r"^(\d+\.\d+\.\d+)")


def _extract_kernel_semver(vermagic: str | None) -> str | None:
    """Return the leading ``major.minor.patch`` from a vermagic string.

    Examples::

        "6.6.102-android15-8-g... SMP preempt ..." -> "6.6.102"
        "5.10.0 SMP preempt mod_unload aarch64"    -> "5.10.0"
        None / no-match                             -> None
    """
    if not vermagic:
        return None
    m = _KERNEL_SEMVER_RE.match(vermagic)
    return m.group(1) if m else None


def _parse_modinfo(data: bytes) -> list[tuple[str, str]]:
    """Split a ``.modinfo`` section into ``(key, value)`` pairs."""
    pairs: list[tuple[str, str]] = []
    for chunk in data.split(b"\x00"):
        if not chunk or b"=" not in chunk:
            continue
        try:
            text = chunk.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        if "=" not in text:
            continue
        key, _, value = text.partition("=")
        pairs.append((key.strip(), value.strip()))
    return pairs


def _infer_chipset(vermagic: str | None, aliases: list[str]) -> str | None:
    candidates: list[str] = []
    if vermagic:
        candidates.append(vermagic)
    candidates.extend(aliases)
    for s in candidates:
        if not s:
            continue
        for rx in _CHIPSET_RES:
            m = rx.search(s)
            if m:
                return m.group(1).lower()
    return None


def _has_appended_signature(path: str, size: int) -> bool:
    """Check the last ``_MODSIG_TAIL_BYTES`` bytes for the CMS appendix magic."""
    try:
        with open(path, "rb") as f:
            if size > _MODSIG_TAIL_BYTES:
                f.seek(size - _MODSIG_TAIL_BYTES)
            tail = f.read(_MODSIG_TAIL_BYTES)
    except OSError:
        return False
    return _MODSIG_MAGIC in tail


class KmodParser:
    """Parser for Linux ``.ko`` kernel modules."""

    FORMAT = "ko"

    def parse(self, path: str, magic: bytes, size: int) -> ParsedBlob:
        meta: dict[str, Any] = {}
        version: str | None = None
        signed: str = "unknown"
        signature_algorithm: str | None = None
        chipset_target: str | None = None

        try:
            from elftools.elf.elffile import ELFFile  # type: ignore
        except Exception as exc:  # noqa: BLE001
            return ParsedBlob(signed="unknown", metadata={"error": f"pyelftools import: {exc}"})

        try:
            with open(path, "rb") as f:
                try:
                    elf = ELFFile(f)
                except Exception as exc:  # noqa: BLE001
                    return ParsedBlob(
                        signed="unknown",
                        metadata={"error": f"ELFFile parse: {exc}"},
                    )

                section = elf.get_section_by_name(".modinfo")
                if section is None:
                    meta["note"] = ".modinfo section missing"
                else:
                    data = section.data()
                    pairs = _parse_modinfo(data)
                    license_val: str | None = None
                    vermagic: str | None = None
                    srcversion: str | None = None
                    version_raw: str | None = None
                    depends: list[str] = []
                    aliases: list[str] = []
                    firmware_deps: list[str] = []
                    for key, value in pairs:
                        if key == "license":
                            license_val = value
                        elif key == "vermagic":
                            vermagic = value
                        elif key == "srcversion":
                            srcversion = value
                        elif key == "version":
                            version_raw = value
                        elif key == "depends":
                            depends.extend(v for v in value.split(",") if v)
                        elif key == "alias":
                            aliases.append(value)
                        elif key == "firmware":
                            firmware_deps.append(value)
                    version = version_raw or srcversion
                    chipset_target = _infer_chipset(vermagic, aliases)
                    meta.update(
                        {
                            "license": license_val,
                            "vermagic": vermagic,
                            "srcversion": srcversion,
                            "depends": depends,
                            "alias": aliases,
                            "firmware_deps": firmware_deps,
                            "version_raw": version_raw,
                        }
                    )
                    # Expose only the leading semver so the CVE matcher can
                    # correlate this kmod against a linux_kernel CPE row.
                    kernel_semver = _extract_kernel_semver(vermagic)
                    if kernel_semver:
                        meta["kernel_semver"] = kernel_semver
        except Exception as exc:  # noqa: BLE001
            logger.debug("KmodParser failed on %s: %s", path, exc)
            meta["error"] = str(exc)

        # Detect appended CMS signature.
        if _has_appended_signature(path, size):
            signed = "signed"
            signature_algorithm = "CMS (kernel module)"

        # Vendor inference from filename + modinfo metadata. The kmod parser
        # historically left `vendor=NULL` on all .ko blobs, which structurally
        # blocked vendor-narrowed curated CVE pins (MediaTek WLAN
        # CVE-2024-20100, BleedingTooth Linux LKM, NVDLA Tegra) from firing
        # against blobs that are CLEARLY from those vendors (e.g. `wlan_drv_gen3.ko`
        # = MediaTek MT76xx-family naming convention). Filename-driven
        # inference is universal (works for any firmware) — adding a new
        # vendor = add a regex pattern to the dict below, NOT touching the
        # cve_matcher or pin YAML.
        vendor = _infer_kmod_vendor(path, meta)

        return ParsedBlob(
            version=version,
            signed=signed,
            signature_algorithm=signature_algorithm,
            chipset_target=chipset_target,
            vendor=vendor,
            metadata=meta,
        )


# Filename-driven kernel module vendor inference.
# Patterns ordered most-specific to most-generic. Each entry maps a
# regex against the .ko file basename (or vermagic / alias substrings)
# to a canonical vendor string that matches curated CVE pin vendor:
# values.
import re as _re

_KMOD_VENDOR_PATTERNS: list[tuple[_re.Pattern[str], str]] = [
    # MediaTek wireless family
    (_re.compile(r"^(wlan_drv_gen\d|wifi_drv|mt76\d+|mtk_wmt|mtkfb|mtk_lcd|mtk_battery|mtk_iommu|mtk_cqdma|mtk_clk|mtk_pmic|mtk_efuse|mtk_kpd|mt\d{4,5}_)", _re.IGNORECASE), "mediatek"),
    # NVIDIA Tegra family
    (_re.compile(r"^(nvgpu|nvidia|nvmap|nvhost|nvdla|tegra_)", _re.IGNORECASE), "nvidia"),
    # Qualcomm family (msm-, ath10k/ath11k/ath12k from QC platform, etc.)
    (_re.compile(r"^(msm_|qcom_|q[cd]\w*_|wcnss_|cnss_|ath\d+k|wlan_q\w*)", _re.IGNORECASE), "qualcomm"),
    # Broadcom
    (_re.compile(r"^(brcm|bcm_|wl_brcm)", _re.IGNORECASE), "broadcom"),
    # Realtek
    (_re.compile(r"^(rtl\w+|r8\d{3}|rtw_|rtw88|rtw89)", _re.IGNORECASE), "realtek"),
    # Intel
    (_re.compile(r"^(i915|iwlwifi|iwlmvm|iwldvm|e1000e?|ixgbe|i40e|igb)$", _re.IGNORECASE), "intel"),
    # AMD
    (_re.compile(r"^(amdgpu|amd_pmc|radeon|amdkfd)", _re.IGNORECASE), "amd"),
    # Samsung
    (_re.compile(r"^(samsung_|s5p_|exynos_|sec_)", _re.IGNORECASE), "samsung"),
]


def _infer_kmod_vendor(path: str, meta: dict[str, Any]) -> str | None:
    """Derive a vendor string from .ko filename + modinfo metadata.

    Filename-driven (most reliable for kmods named after their SoC family).
    Falls through to vermagic / alias substring match. Returns None when
    no signal — preserves the legacy "unknown vendor" surface for generic
    Linux modules like `bluetooth.ko` (which IS BlueZ Linux but matches
    no specific vendor; the BleedingTooth advisory pin uses `vendor=unknown`).
    """
    import os as _os
    basename = _os.path.basename(path).lower()
    # Strip .ko suffix if present
    if basename.endswith(".ko"):
        basename = basename[:-3]
    for pattern, vendor_name in _KMOD_VENDOR_PATTERNS:
        if pattern.match(basename):
            return vendor_name
    # Fall through to vermagic / alias substring (less reliable but
    # covers vendor-specific kernel builds where stock names like
    # `bluetooth.ko` are recompiled for a specific platform).
    vermagic = (meta.get("vermagic") or "").lower()
    for pattern, vendor_name in _KMOD_VENDOR_PATTERNS:
        if pattern.search(vermagic):
            return vendor_name
    aliases = meta.get("alias") or []
    for alias in aliases:
        for pattern, vendor_name in _KMOD_VENDOR_PATTERNS:
            if pattern.search(str(alias).lower()):
                return vendor_name
    return None


register_parser(KmodParser())
