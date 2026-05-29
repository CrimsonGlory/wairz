"""Stage B — Android boot image (``boot.img``) header parser (v0-v4).

Parses the ``boot_img_hdr`` structure that prefixes an Android
``boot.img`` (magic ``ANDROID!``) and returns the page-aligned offset +
size of the embedded kernel so the C1 walker can carve it and hand the
bytes to Stage D (``kernel_decompress``).

This is a PARSE-ONLY byte reader (Rule #36 + Rule #45): it reads header
fields and computes offsets; it NEVER invokes the kernel or any extracted
artefact. It is consumed directly by ``kernel_config_walker`` (NOT
registered as a classifier FORMAT parser — the walker finds boot images
by content-rescan, not by filename classification).

Header layout reference (AOSP ``system/tools/mkbootimg/include/bootimg/bootimg.h``).
Offsets VERIFIED against the real Moto G32 boot.img during the C1
real-data validation (2026-05-29) — see the note below.

* **v0/v1/v2** (``boot_img_hdr_v0``): magic@0 (8 bytes), ``kernel_size``@8
  (u32 LE), ``kernel_addr``@12, ``ramdisk_size``@16, ..., ``page_size``@36
  (u32 LE), ``header_version``@40 (u32 LE), ``os_version``@44 (u32 LE).
  The kernel begins at the first page boundary AFTER the header
  (``page_size``), i.e. ``kernel_offset = page_size``.

* **v3/v4** (``boot_img_hdr_v3``): magic@0 (8 bytes), ``kernel_size``@8
  (u32 LE), ``ramdisk_size``@12, ``os_version``@16 (u32 LE),
  ``header_size``@20, ``reserved``..., ``header_version``@40 (u32 LE).
  ``page_size`` is FIXED at 4096 in v3/v4 (the field was removed). The
  kernel begins at offset 4096 (one 4096-byte page for the header).
  NB: ``kernel_size`` is at @8 in BOTH layouts — the v3 ``boot_img_hdr_v3``
  reorders the LATER fields but keeps ``kernel_size`` first.

``os_version`` packing (AOSP mkbootimg): top 25 bits = ``((a<<14)|(b<<7)|c)
<< 11`` (the A.B.C release), low 11 bits = ``((year-2000)<<4) | month``
(7-bit year offset, 4-bit month).

Moto G32 phone reference (``A-phone-ikconfig-result.md`` §2 / §3, CONFIRMED
against the real boot.img): v3 header, ``kernel_size=14,873,776`` (@8),
``ramdisk_size=12,430,826`` (@12), kernel at offset 4096, ``os_version``
(@16, packed ``369099122``) decodes to Android ``11.0.0`` + security patch
``2023-02``. This parser reproduces those exactly.
"""
from __future__ import annotations

import logging
import struct
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_BOOT_MAGIC = b"ANDROID!"
_BOOT_MAGIC_SIZE = 8

# A sane page size; v0/v1/v2 store it explicitly, v3/v4 fix it at 4096.
_DEFAULT_PAGE_SIZE = 4096
# Reject absurd kernel sizes early (a boot.img kernel slice is bounded by
# the partition; 256 MB is a generous upper bound — any larger is a parse
# error, not a real kernel).
_MAX_KERNEL_SIZE = 256 * 1024 * 1024
# A page_size field outside this range is a corrupt/misparsed header.
_MIN_PAGE_SIZE = 256
_MAX_PAGE_SIZE = 1024 * 1024


@dataclass(frozen=True)
class BootImageLayout:
    """Carve geometry + identity recovered from a boot_img_hdr.

    ``kernel_offset`` / ``kernel_size`` are the byte slice of the embedded
    kernel relative to the start of the boot.img buffer. ``os_version`` /
    ``security_patch`` are decoded from the packed ``os_version`` u32 when
    present (Stage F fallback identity for the BLOCKED path).
    """

    header_version: int
    kernel_offset: int
    kernel_size: int
    page_size: int
    os_version: str | None  # e.g. "11.0.0"
    security_patch: str | None  # e.g. "2023-02"


def _decode_os_version(packed: int) -> tuple[str | None, str | None]:
    """Decode the AOSP packed ``os_version`` u32 into (os_version, security_patch).

    Layout (AOSP ``mkbootimg``): the high 25 bits encode A.B.C (7 bits
    each), the low 11 bits encode (year-2000)*12 + (month-1). A zero field
    means "not set".
    """
    if packed == 0:
        return None, None
    try:
        version = packed >> 11
        a = (version >> 14) & 0x7F
        b = (version >> 7) & 0x7F
        c = version & 0x7F
        # AOSP patch packing: low 11 bits = ((year-2000) << 4) | month
        # (7-bit year offset, 4-bit month) — NOT (year-2000)*12 + month.
        # Verified against the Moto G32 boot.img (packed 369099122 →
        # patch_field 370 → 2023-02).
        patch_field = packed & 0x7FF
        year = 2000 + (patch_field >> 4)
        month = patch_field & 0xF
        os_version = f"{a}.{b}.{c}"
        # Guard against obviously-bogus decodes (e.g. month 0 / huge year).
        if not (2000 <= year <= 2100) or not (1 <= month <= 12):
            security_patch = None
        else:
            security_patch = f"{year}-{month:02d}"
        return os_version, security_patch
    except Exception:  # noqa: BLE001 — pure-arithmetic, but defensive
        return None, None


def parse_boot_image(data: bytes) -> BootImageLayout | None:
    """Parse an Android boot.img header; return the kernel carve geometry.

    Returns ``None`` when ``data`` is not an ``ANDROID!`` boot image or the
    header is too short / corrupt to yield a sane kernel slice. Idempotent
    + side-effect free.

    Per-version field map:

    * **v3/v4**: ``kernel_size``@12, fixed ``page_size=4096``,
      ``os_version``@20, ``kernel_offset=4096``.
    * **v0/v1/v2**: ``kernel_size``@8, ``page_size``@36, ``os_version``@44,
      ``kernel_offset=page_size``.
    """
    if data[:_BOOT_MAGIC_SIZE] != _BOOT_MAGIC:
        return None
    if len(data) < 44:
        return None

    # header_version lives at offset 40 in BOTH layouts.
    try:
        (header_version,) = struct.unpack_from("<I", data, 40)
    except struct.error:
        return None

    if header_version >= 3:
        # v3/v4 layout: kernel_size@8, ramdisk_size@12, os_version@16.
        try:
            (kernel_size,) = struct.unpack_from("<I", data, 8)
            (os_version_packed,) = struct.unpack_from("<I", data, 16)
        except struct.error:
            return None
        page_size = _DEFAULT_PAGE_SIZE
        kernel_offset = _DEFAULT_PAGE_SIZE
    else:
        # v0/v1/v2 layout.
        if len(data) < 48:
            return None
        try:
            (kernel_size,) = struct.unpack_from("<I", data, 8)
            (page_size,) = struct.unpack_from("<I", data, 36)
            (os_version_packed,) = struct.unpack_from("<I", data, 44)
        except struct.error:
            return None
        if not (_MIN_PAGE_SIZE <= page_size <= _MAX_PAGE_SIZE):
            # Corrupt / misparsed page size — refuse rather than carve garbage.
            logger.debug(
                "parse_boot_image: implausible page_size=%d in v%d header",
                page_size,
                header_version,
            )
            return None
        kernel_offset = page_size

    if kernel_size <= 0 or kernel_size > _MAX_KERNEL_SIZE:
        logger.debug(
            "parse_boot_image: implausible kernel_size=%d in v%d header",
            kernel_size,
            header_version,
        )
        return None

    os_version, security_patch = _decode_os_version(os_version_packed)

    return BootImageLayout(
        header_version=header_version,
        kernel_offset=kernel_offset,
        kernel_size=kernel_size,
        page_size=page_size,
        os_version=os_version,
        security_patch=security_patch,
    )


def carve_kernel(data: bytes, layout: BootImageLayout) -> bytes | None:
    """Return the kernel byte-slice from a boot.img buffer + parsed layout.

    Returns ``None`` when the buffer is shorter than
    ``kernel_offset + kernel_size`` (header-only carved chunk — the phone
    case where unblob consumed the kernel body; the walker then falls back
    to re-extracting from the original upload archive). Pure slice; no I/O.
    """
    end = layout.kernel_offset + layout.kernel_size
    if len(data) < end:
        return None
    return data[layout.kernel_offset : end]


__all__ = ["BootImageLayout", "carve_kernel", "parse_boot_image"]
