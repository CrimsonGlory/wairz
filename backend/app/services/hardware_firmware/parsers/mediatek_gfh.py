"""MediaTek LK / GFH shared utilities.

Two pieces live here so the outer LK-record parser (``mediatek_lk``), the
classifier, and future subsystem parsers (``mtk_atf``, ``mtk_geniezone``,
``mtk_tinysys``) all agree on:

1. **LK partition-record header parsing** — both the 512-byte *legacy*
   layout (name at 0x20) and the 16-byte *compact* layout (name at 0x08)
   used on newer MTK SoCs (MT6785/MT6853/MT8788+). Disambiguation is done
   by probing offset 0x08 for a valid ASCII name.

2. **Partition-name → (category, component, vendor)** lookup — the
   dispatch table distilled from U-Boot ``tools/mtk_image.c``,
   bkerler/mtkclient ``partitions.py``, and LineageOS MTK device trees.
   This is what turns ``cam_vpu1`` / ``atf`` / ``md1rom`` / ``spmfw`` /
   ``gz`` into the right Wairz category instead of defaulting every
   LK-wrapped blob to ``bootloader``.

The GFH "MMM\\x01" chain walker isn't implemented here — on the DPCS10
packages we observed, the outer LK record is followed directly by an
``LK_FILE_INFO`` (0x58891689) block and a trailer, not an MMM chain.
Add the chain walker if/when a target firmware exposes it.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

_LK_MAGIC = 0x58881688
_LK_FILE_INFO_MAGIC = 0x58891689
# Outer container header is 512 bytes total: 48-byte LK record + GFH_FILE_INFO
# record at 0x30 + 0xFF padding to 0x200. Every parser strips 0x200 to reach
# the real payload.
LK_CONTAINER_HEADER_SIZE = 0x200
# Sub-image alignment inside a multi-payload container (observed on SCP where
# the next sub-image starts at the next 16-byte boundary after size bytes).
_SUBIMAGE_ALIGNMENT = 16

# Compact (16-byte) vs legacy (512-byte) layouts are distinguished at
# runtime by whether offset 0x08 holds a plausible ASCII name.  Valid
# partition names are short, start with a letter or digit, and contain
# only [A-Za-z0-9_-].
_NAME_RE = re.compile(rb"^[A-Za-z][A-Za-z0-9_\-]{0,30}$")


@dataclass
class LkHeader:
    """Parsed MediaTek LK partition-record header."""

    name: str                    # partition name (e.g. "lk", "atf", "md1rom")
    layout: str                  # "compact" (16-byte) | "legacy" (512-byte)
    file_info_offset: int        # u32 at offset 0x04
    has_file_info_magic: bool    # whether 0x58891689 lives inside the header


def parse_lk_header(data: bytes) -> LkHeader | None:
    """Parse an LK partition-record header from the first 64+ bytes.

    Returns ``None`` if magic doesn't match or header is too short.
    Never raises on truncated input.
    """
    if len(data) < 16:
        return None
    try:
        magic_u32, file_info_offset = struct.unpack_from("<II", data, 0)
    except struct.error:
        return None
    if magic_u32 != _LK_MAGIC:
        return None

    # Compact variant: 8-byte name at 0x08
    compact_name = _decode_cstr(data[8:16])
    if compact_name and _NAME_RE.match(compact_name.encode("ascii", "ignore")):
        has_fi = (
            len(data) >= 0x34
            and struct.unpack_from("<I", data, 0x30)[0] == _LK_FILE_INFO_MAGIC
        )
        return LkHeader(
            name=compact_name,
            layout="compact",
            file_info_offset=file_info_offset,
            has_file_info_magic=has_fi,
        )

    # Legacy variant: 32-byte name at 0x20
    if len(data) >= 0x40:
        legacy_name = _decode_cstr(data[0x20:0x40])
        if legacy_name and _NAME_RE.match(legacy_name.encode("ascii", "ignore")):
            return LkHeader(
                name=legacy_name,
                layout="legacy",
                file_info_offset=file_info_offset,
                has_file_info_magic=False,
            )

    # Magic matched but no usable name — return minimal header so callers
    # can still flag "bad/stub" without crashing.
    return LkHeader(
        name="",
        layout="compact" if file_info_offset < 64 else "legacy",
        file_info_offset=file_info_offset,
        has_file_info_magic=False,
    )


@dataclass
class SubImage:
    """One sub-image inside an LK container (the primary payload, a trailing
    `cert2` signature, or a secondary payload like `atf_dram` / `unmap2`)."""

    name: str
    offset: int        # offset of the LK header within the file
    payload_size: int  # payload bytes, excluding the 0x200 header
    payload_offset: int  # offset of the first payload byte (== offset + 0x200)
    is_signature: bool   # True for cert2 and similar 1008-byte signature blocks


def walk_sub_images(data: bytes, max_subimages: int = 16) -> list[SubImage]:
    """Enumerate every LK sub-image inside a container.

    Every MediaTek subsystem blob observed on DPCS10 / AIoT8788 ships as a
    sequence of LK records: primary payload, a 0x3F0-byte ``cert2``
    signature, optionally a secondary payload (``atf_dram``, ``unmap2``,
    ``tinysys-scp-CM4_A``) + its own ``cert2``. Walking the chain lets us
    hand the right stripped payload to each per-role parser instead of
    misreading the secondary payload as part of the primary's byte stream.

    Sub-image alignment: payload starts at header + 0x200, next header
    starts at ``payload_end`` rounded up to a 16-byte boundary. This
    matches the empirical layout on every blob we've seen.
    """
    out: list[SubImage] = []
    offset = 0
    safety = 0
    while offset + 0x40 <= len(data) and safety < max_subimages:
        safety += 1
        try:
            magic_u32, size_u32 = struct.unpack_from("<II", data, offset)
        except struct.error:
            break
        if magic_u32 != _LK_MAGIC:
            break
        name = _decode_cstr(data[offset + 8 : offset + 0x20])
        is_sig = name == "cert2"
        out.append(SubImage(
            name=name,
            offset=offset,
            payload_size=size_u32,
            payload_offset=offset + LK_CONTAINER_HEADER_SIZE,
            is_signature=is_sig,
        ))
        # Next header starts at payload_end, aligned up to 16.
        payload_end = offset + LK_CONTAINER_HEADER_SIZE + size_u32
        next_off = (payload_end + _SUBIMAGE_ALIGNMENT - 1) & ~(_SUBIMAGE_ALIGNMENT - 1)
        if next_off <= offset:  # defensive — never loop forever
            break
        offset = next_off
    return out


def _decode_cstr(raw: bytes) -> str:
    nul = raw.find(b"\x00")
    if nul >= 0:
        raw = raw[:nul]
    try:
        return raw.decode("ascii", errors="ignore").strip()
    except Exception:  # noqa: BLE001
        return ""


# ─────────────────────────────────────────────────────────────────────
# Partition-name → (category, component, vendor) dispatch
# ─────────────────────────────────────────────────────────────────────
#
# category: the Wairz CATEGORIES value for classifier output
# component: a stable subcomponent tag usable for CVE matching; mirrors
#            the "Subcomponent" column in MediaTek's monthly Product
#            Security Bulletins (e.g. "geniezone", "atf", "tinysys",
#            "modem", etc.)
# vendor: always "mediatek" for these names
#
# Sources:
#   - U-Boot tools/mtk_image.c (GPL-2.0)
#   - bkerler/mtkclient partitions.py (GPL-3.0)
#   - AOSP device/mediatek/*/BoardConfig.mk
#   - MediaTek monthly Product Security Bulletin subcomponent tags
#   - cyrozap/mediatek-lte-baseband-re
_MTK_PARTITIONS: dict[str, tuple[str, str]] = {
    # Bootloader family
    "preloader": ("bootloader", "preloader"),
    "lk": ("bootloader", "lk"),
    "lk_a": ("bootloader", "lk"),
    "lk_b": ("bootloader", "lk"),
    "lk2": ("bootloader", "lk"),
    "boot": ("bootloader", "android_boot"),
    "boot_a": ("bootloader", "android_boot"),
    "boot_b": ("bootloader", "android_boot"),
    "recovery": ("bootloader", "android_recovery"),
    "vbmeta": ("bootloader", "vbmeta"),

    # Trusted execution
    "atf": ("tee", "atf"),
    "tee": ("tee", "tee"),
    "tee1": ("tee", "tee"),
    "tee2": ("tee", "tee"),
    "gz": ("tee", "geniezone"),

    # Power / coprocessors.  All tinysys-family blobs are Cortex-M
    # microcontrollers (SCP=Cortex-M4 system controller, SSPM/MCUPM/DPM=
    # power managers, SPMFW=PCM microcode).  Categorize as ``mcu`` so
    # they bucket together in the hardware listing and so curated_yaml
    # entries keyed on category=mcu fire across the whole tinysys family.
    # (Audio DSP and APU/MDLA stay under ``dsp`` below — those really
    # are signal-processor cores, not microcontrollers.)
    "spmfw": ("mcu", "spmfw"),
    "sspm": ("mcu", "tinysys"),
    "mcupm": ("mcu", "mcupm"),
    "dpm": ("mcu", "dpm"),
    "scp": ("mcu", "tinysys"),
    "scp1": ("mcu", "tinysys"),
    "scp2": ("mcu", "tinysys"),

    # Camera
    "cam_vpu1": ("camera", "cam_vpu"),
    "cam_vpu2": ("camera", "cam_vpu"),
    "cam_vpu3": ("camera", "cam_vpu"),
    "ccu": ("camera", "ccu"),
    "ccu1": ("camera", "ccu"),

    # AI / neural accelerators
    "vpu": ("dsp", "apu"),
    "apu": ("dsp", "apu"),

    # Modem (MD1 / MD2)
    "md1rom": ("modem", "modem"),
    "md1dsp": ("modem", "modem_dsp"),
    "md1drdi": ("modem", "modem_drdi"),
    "md1img": ("modem", "modem"),
    "md2img": ("modem", "modem"),
    "cert_md": ("modem", "modem_cert"),
    "dsp_bl": ("dsp", "modem_dsp_bl"),
    "md1_filter": ("modem", "modem_filter"),
    "md1_filter_hw": ("modem", "modem_filter"),

    # Display / GPU
    "logo": ("display", "logo"),
    "gpueb": ("gpu", "mali_fw"),

    # Audio
    "audio_dsp": ("audio", "adsp"),
    "adsp": ("audio", "adsp"),

    # Device tree
    "dtb": ("dtb", "dtb"),
    "dtbo": ("dtb", "dtbo"),

    # Connectivity combo (Wi-Fi/BT/FM/GPS)
    "wifi": ("wifi", "connsys"),
    "connsys": ("wifi", "connsys"),
    "wmt": ("wifi", "connsys"),
}

# Names that ship as tiny partition-descriptor stubs when the corresponding
# die is depopulated (common on modem-less SKUs of the Genio 700 / AIoT8788
# platform). When we see one of these with a suspiciously small file, flag
# it so the UI can surface "partition placeholder — no firmware payload".
_STUB_CANDIDATES = frozenset({"md1rom", "md1dsp", "md1drdi", "cert_md"})
_STUB_SIZE_THRESHOLD = 4096


def lookup_partition(name: str) -> tuple[str, str] | None:
    """Return ``(category, component)`` for a known MTK partition name,
    or ``None`` if the name is unrecognised (classifier falls back to
    the generic ``bootloader`` / ``mtk_lk`` default).

    Also handles ``tinysys-<suffix>`` compact names by mapping the
    ``tinysys-`` prefix to SCP/SSPM category.
    """
    if not name:
        return None
    key = name.lower().strip()
    hit = _MTK_PARTITIONS.get(key)
    if hit is not None:
        return hit
    # Newer bundles name scp/sspm/mcupm as "tinysys-scp" etc.  All
    # tinysys cores are Cortex-M microcontrollers (see _MTK_PARTITIONS
    # comment above).
    if key.startswith("tinysys"):
        return ("mcu", "tinysys")
    return None


def is_stub_descriptor(name: str, file_size: int) -> bool:
    """True when the blob is a known-stubbable partition AND the file is
    below the size that would hold any real payload.

    Used to suppress nonsense struct-field reads on files that are
    actually scatter-config placeholders (e.g. `md1rom` = 528 B on
    modem-less SKUs).
    """
    if not name:
        return False
    return name.lower() in _STUB_CANDIDATES and file_size < _STUB_SIZE_THRESHOLD


# MTK SoC IDs: 4-5 digit numbers prefixed by ``mt`` (kernel/TF-A source
# convention) or by ``aiot`` on Genio AIoT SKUs (board name embeds the
# underlying SoC, e.g. ``aiot8788ep1`` → MT8788).
#
# Leading lookbehind rejects a preceding letter/digit so we don't
# match ``kmt6771`` or ``ymt8788``; trailing negative lookahead rejects
# a following digit so we don't truncate ``mt67711`` to ``mt6771``.
# Compound identifiers like ``mt8195_proj`` or ``mt6771-bsp-k66``
# still match cleanly because ``_`` and ``-`` are not digits.
_MTK_CHIPSET_RE = re.compile(r"(?<![A-Za-z0-9])mt(\d{4,5})(?!\d)", re.IGNORECASE)
_AIOT_CHIPSET_RE = re.compile(r"(?<![A-Za-z0-9])aiot(\d{4,5})(?!\d)", re.IGNORECASE)


def derive_chipset(metadata: dict) -> str | None:
    """Derive the canonical MTK SoC chipset (e.g. ``mt6771``) from a
    parser's metadata dict, or None when no hint is present.

    Scans string-typed values for an explicit ``mt\\d{4,5}`` token first
    (kernel/TF-A platform paths, GZ banner sources). Falls back to the
    AIoT board-name encoding (``aiot8788…`` → ``mt8788``) used on Genio
    boards where the only visible identifier is the board tag.

    Returned in lowercase to match the chipset_regex patterns shipped in
    ``known_firmware.yaml`` (case-insensitive but normalised).
    """
    for value in metadata.values():
        if not isinstance(value, str) or not value:
            continue
        m = _MTK_CHIPSET_RE.search(value)
        if m:
            return f"mt{m.group(1).lower()}"
        m = _AIOT_CHIPSET_RE.search(value)
        if m:
            return f"mt{m.group(1).lower()}"
    return None


def signed_from_subimages(subimages: list) -> str:
    """Translate the LK container's sub-image walk into a signed verdict.

    MTK LK containers (gz/atf/scp/sspm/spmfw) interleave payload sub-
    images with ``cert2`` signature blocks at well-known offsets.  When
    ``walk_sub_images`` returns at least one ``is_signature=True`` entry
    alongside a non-empty primary payload, the container IS signed by
    MTK -- the signature parser already validated the cert chain layout
    even if we don't verify the cryptographic chain ourselves.

    Returns:
        ``"signed"`` when a non-empty ``cert2`` block accompanies a real
            payload (the common case for gz/atf/tinysys subsystems)
        ``"unsigned"`` when sub-images exist but no signature block does
            (rare; would indicate a stripped or malformed container)
        ``"unknown"`` when ``subimages`` is empty (parser failure path
            or non-LK container -- don't claim a verdict we can't back)
    """
    if not subimages:
        return "unknown"
    has_payload = any(
        not getattr(s, "is_signature", False) and getattr(s, "payload_size", 0) > 0
        for s in subimages
    )
    has_signature = any(
        getattr(s, "is_signature", False) and getattr(s, "payload_size", 0) > 0
        for s in subimages
    )
    if has_payload and has_signature:
        return "signed"
    if has_payload and not has_signature:
        return "unsigned"
    return "unknown"
