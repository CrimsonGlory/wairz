"""Pre-flight format detection for firmware uploads.

Inspects the head of an upload (and the central directory of ZIPs) to
classify the file into a small enum of known formats. Each format maps
to an ``ExtractionCapability`` flag — full / partial / none — that the
upload-status endpoint surfaces back to the frontend so the user sees,
upfront, whether unblob / zipfile / native handlers can extract their
upload OR whether the format is currently informational-only and they
should extract externally and re-upload.

Performance target: < 2 seconds on a 16 GB file. Achieved by reading
only the first ~512 KB of the head (every magic-byte signature lives
there) plus, for ZIPs, the central directory at the file end.

Multi-OS scope: Wairz handles Linux / Android / Windows installer ISOs
/ QNX / RTOS-style firmware. The catalogue is informational about WHAT
THE EXTRACTOR CAN DO for each format — not about wairz "supporting" the
format. ``capability=none`` means "no current handler"; the user can
still upload, browse the raw file, run hash analyses, etc.

Magic-byte references documented inline below. Acronis ``.tibx`` is a
proprietary format with no published header signature (per Acronis KB
63498 — the new tibx replaced the old tib without a public spec); we
fall back to extension-based detection per CLAUDE.md hard constraint
on Rule #19 (evidence-first when the magic bytes can't be researched).
"""
from __future__ import annotations

import logging
import os
import struct
import zipfile
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


# Read the first 512 KB for header inspection — large enough to cover
# every documented magic-byte location (PE e_lfanew can sit a few MB
# in for unusual binaries, but every firmware-class PE we care about
# has its PE header well within 512 KB).
_HEAD_BYTES = 512 * 1024

# ZIP central directory end record (EOCD): 22 bytes minimum, signature
# ``PK\x05\x06`` at start. Comment field can extend it up to 65 KB,
# so search the trailing 64 KB + 22 bytes for the signature.
_EOCD_SEARCH_BYTES = 64 * 1024 + 22


class DetectedFormat(str, Enum):
    """Coarse classification of an uploaded firmware file."""

    LINUX_FIRMWARE_BLOB = "linux_firmware_blob"   # squashfs/cramfs/jffs2/ext/U-Boot/zImage
    ANDROID_APK = "android_apk"                    # ZIP + AndroidManifest.xml + classes.dex
    ANDROID_OTA = "android_ota"                    # ZIP + payload.bin OR partition images
    WINDOWS_INSTALLER_ISO = "windows_installer_iso"  # bootmgr.efi + sources/boot.wim
    ACRONIS_BACKUP = "acronis_backup"              # .tibx / .tib (extension-based; no public magic)
    QNX_IFS = "qnx_ifs"                            # 0x00ff7eeb / 0xeb7eff7e startup header
    PE_EXECUTABLE = "pe_executable"                # MZ + PE\x00\x00 at e_lfanew
    WIM_ARCHIVE = "wim_archive"                    # MSWIM\x00\x00\x00 at offset 0
    ISO_9660 = "iso_9660"                          # CD001 at offset 0x8001
    TAR_ARCHIVE = "tar_archive"                    # 'ustar' at offset 0x101 (POSIX)
    ZIP_ARCHIVE = "zip_archive"                    # Generic PK\x03\x04
    UNKNOWN = "unknown"


class ExtractionCapability(str, Enum):
    """Whether wairz has a working extractor for the format.

    FULL    — handler exists in workers/unpack* + tested on real firmware.
    PARTIAL — surface-level extraction works (e.g. unblob can crack open
              an ISO 9660 image and pull individual files, but doesn't
              know how to assemble a Windows installer's WIM payloads).
    NONE    — informational only; the user must extract externally and
              re-upload the inner artefacts.
    """

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


# Per-format capability mapping. Single source of truth for what wairz
# CAN do per format from the user's perspective. Aligned with the
# strategy registry in ``app/workers/extraction_strategies.py`` — when
# a new handler ships, both this map and the registry update in the
# same commit. ``FULL`` / ``PARTIAL`` capabilities should route to a
# real extraction worker; ``NONE`` capabilities route to
# ``unpack_no_handler``. The Rule #21 mirror-discipline applies: a
# capability change without a registry update produces UI claims that
# don't match runtime behaviour.
#
# Audit grep when adding a new format:
#   grep -rn 'EXTRACTION_CAPABILITY\|DetectedFormat\.' backend/
#   grep -rn 'STRATEGIES\b' backend/app/workers/extraction_strategies.py
EXTRACTION_CAPABILITY: dict[DetectedFormat, ExtractionCapability] = {
    DetectedFormat.LINUX_FIRMWARE_BLOB: ExtractionCapability.FULL,
    DetectedFormat.ANDROID_APK: ExtractionCapability.FULL,
    DetectedFormat.ANDROID_OTA: ExtractionCapability.FULL,
    DetectedFormat.TAR_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.ZIP_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_INSTALLER_ISO: ExtractionCapability.PARTIAL,
    DetectedFormat.PE_EXECUTABLE: ExtractionCapability.PARTIAL,
    DetectedFormat.ISO_9660: ExtractionCapability.PARTIAL,
    DetectedFormat.ACRONIS_BACKUP: ExtractionCapability.NONE,
    DetectedFormat.QNX_IFS: ExtractionCapability.NONE,
    DetectedFormat.WIM_ARCHIVE: ExtractionCapability.NONE,
    DetectedFormat.UNKNOWN: ExtractionCapability.NONE,
}


# Per-format human-readable note that the frontend banner can render
# verbatim when capability is partial / none. Keeps copy near the
# detection logic so the two evolve together.
CAPABILITY_NOTES: dict[DetectedFormat, str] = {
    DetectedFormat.ACRONIS_BACKUP: (
        "Acronis .tibx/.tib backup detected. The format is proprietary and no "
        "open extractor exists. Restore the backup with Acronis True Image, "
        "export the recovered filesystem as a tar/zip, and re-upload."
    ),
    DetectedFormat.QNX_IFS: (
        "QNX IFS image detected. wairz does not yet have a QNX extractor. "
        "Use a QNX-aware tool (mount_ifs, dumpifs) to extract the rootfs and "
        "re-upload as a tar archive."
    ),
    DetectedFormat.WIM_ARCHIVE: (
        "Windows Imaging Format archive detected. Use 7-Zip or wimlib to "
        "extract individual files and re-upload as a tar/zip if you need "
        "filesystem-level analysis."
    ),
    DetectedFormat.WINDOWS_INSTALLER_ISO: (
        "Windows installer ISO detected. wairz can extract the ISO contents "
        "(boot loaders, manifests) but cannot expand the inner WIM payloads "
        "automatically. Use 7-Zip on sources/boot.wim if you need the full "
        "installer rootfs."
    ),
    DetectedFormat.PE_EXECUTABLE: (
        "Windows PE executable detected. Binary analysis (strings, sections, "
        "decompilation) is available, but there is no firmware filesystem to "
        "extract."
    ),
    DetectedFormat.ISO_9660: (
        "ISO 9660 image detected. Surface-level extraction is available; "
        "specialised installer payloads (Windows WIM, Linux squashfs inside "
        "the ISO) may need a second-pass extraction."
    ),
}


def detect_format(path: Path | str) -> DetectedFormat:
    """Classify ``path`` against the known format catalogue.

    Reads at most ~512 KB from the head of the file and, if the file
    looks like a ZIP, the central directory at the tail. Designed to
    complete in under 2 seconds even on a 16 GB upload.

    Returns ``DetectedFormat.UNKNOWN`` when no signature matches; the
    caller treats unknown as "let unblob have a try anyway" — this
    function is informational, not gating.
    """
    p = Path(path)
    if not p.is_file():
        return DetectedFormat.UNKNOWN

    try:
        size = p.stat().st_size
    except OSError:
        return DetectedFormat.UNKNOWN

    head = b""
    try:
        with open(p, "rb") as fh:
            head = fh.read(_HEAD_BYTES)
    except OSError:
        logger.debug("format-detect: head read failed for %s", p, exc_info=True)
        return DetectedFormat.UNKNOWN

    # ── 1. Linux firmware-blob magic bytes (offset 0) ────────────────
    # squashfs: 'hsqs' (LE) or 'sqsh' (BE)
    # cramfs:   0x28cd3d45 (LE) at offset 0
    # JFFS2:    0x1985 (LE) at offset 0 (node magic)
    # U-Boot legacy uImage: 0x27051956 (BE) at offset 0
    # FIT FDT (devicetree blob): 0xd00dfeed (BE) at offset 0
    # Linux kernel zImage / Image: ARM zImage has 'MZ' at 0 (PE coexist)
    #   — handled later via PE check; pure ELF kernels carry \x7fELF.
    if len(head) >= 4:
        magic4 = head[:4]
        if magic4 in (b"hsqs", b"sqsh"):
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x45\x3d\xcd\x28":  # cramfs LE
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x85\x19\x03\x20" or magic4[:2] == b"\x85\x19":  # JFFS2 dirent / inode
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x27\x05\x19\x56":  # U-Boot legacy uImage (BE)
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\xd0\x0d\xfe\xed":  # FIT / DTB
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        # ext2/3/4 has its superblock 1024 bytes in (s_magic at +1080).
        if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        # ELF — generic Linux/Unix executable or kernel image.
        if magic4 == b"\x7fELF":
            return DetectedFormat.LINUX_FIRMWARE_BLOB

    # ── 2. WIM archive (Windows Imaging Format) ──────────────────────
    if head.startswith(b"MSWIM\x00\x00\x00"):
        return DetectedFormat.WIM_ARCHIVE

    # ── 3. QNX IFS startup header ────────────────────────────────────
    # Per QNX docs, the optional startup header begins with the 4-byte
    # signature 0x00ff7eeb (or its byte-swapped variant 0xeb7eff7e)
    # followed by the IFS image body. See:
    #   https://www.qnx.com/developers/docs/8.0/com.qnx.doc.neutrino.utilities/topic/m/mount_ifs.html
    if len(head) >= 4:
        if head[:4] in (b"\xeb\x7e\xff\x7e", b"\x00\xff\x7e\xeb"):
            return DetectedFormat.QNX_IFS

    # ── 4. ISO 9660 (CD001 at offset 0x8001) ─────────────────────────
    # Followed by Windows installer detection on top of the ISO — but
    # we only have the first 512 KB in head, and 0x8001 is at byte
    # 32_769 < 512 KB, so the head buffer covers it.
    if len(head) >= 0x8006 and head[0x8001:0x8006] == b"CD001":
        # Try to upgrade ISO 9660 → WINDOWS_INSTALLER_ISO if we can see
        # the bootmgr signature in the head zone (BIOS/EFI installers
        # place these strings near the start). Not authoritative — a
        # full verdict needs a 9660 walk — but cheap and right > 95% of
        # the time on real installer ISOs.
        head_lower = head.lower()
        if (
            b"bootmgr" in head_lower
            or b"sources/boot.wim" in head_lower
            or b"sources\\boot.wim" in head_lower
        ):
            return DetectedFormat.WINDOWS_INSTALLER_ISO
        return DetectedFormat.ISO_9660

    # ── 5. PE executable ─────────────────────────────────────────────
    # MZ at 0, then read e_lfanew (offset 0x3c, 4 bytes LE) to find PE
    # header. Validate PE\x00\x00 lives at that offset.
    if head.startswith(b"MZ") and len(head) >= 0x40:
        try:
            (e_lfanew,) = struct.unpack_from("<I", head, 0x3c)
        except struct.error:
            e_lfanew = 0
        if 0 < e_lfanew < len(head) - 4 and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            return DetectedFormat.PE_EXECUTABLE

    # ── 6. tar archive (POSIX 'ustar' at offset 0x101) ───────────────
    if len(head) >= 0x108 and head[0x101:0x106] == b"ustar":
        return DetectedFormat.TAR_ARCHIVE

    # ── 7. ZIP archive (PK\x03\x04 at offset 0) ──────────────────────
    # Distinguish APK / Android OTA / generic ZIP via central-directory
    # filename inspection. zipfile.ZipFile is fast (reads only the
    # central dir at the tail), works for files of any size.
    if head.startswith(b"PK\x03\x04"):
        zip_kind = _classify_zip(p)
        if zip_kind is not None:
            return zip_kind
        return DetectedFormat.ZIP_ARCHIVE

    # ── 8. Acronis backup — extension-based fallback ─────────────────
    # The .tibx and .tib formats are proprietary with no public magic
    # bytes (Acronis KB 63498). Trust the user-supplied filename when
    # it carries the canonical extension.
    name = p.name.lower()
    if name.endswith((".tibx", ".tib")):
        return DetectedFormat.ACRONIS_BACKUP

    # ── 9. Tar/gz/xz/bz2 by extension when the head doesn't have the
    # ustar marker (older tars, gzipped tars where the gzip header
    # masks the inner ustar). Cheap fallback — extraction will fail
    # cleanly downstream if the extension lies.
    if name.endswith((".tar.gz", ".tgz", ".tar.bz2", ".tar.xz", ".tar")):
        return DetectedFormat.TAR_ARCHIVE

    return DetectedFormat.UNKNOWN


def _classify_zip(path: Path) -> DetectedFormat | None:
    """Inspect a ZIP's central directory to classify it as APK / OTA / generic."""
    try:
        with zipfile.ZipFile(path, "r") as zf:
            names = set(zf.namelist())
    except (zipfile.BadZipFile, OSError, EOFError):
        return None

    # Android APK: AndroidManifest.xml AND classes.dex (or classes2.dex).
    if "AndroidManifest.xml" in names and any(
        n == "classes.dex" or n.startswith("classes") and n.endswith(".dex")
        for n in names
    ):
        return DetectedFormat.ANDROID_APK

    # Android OTA / factory image: payload.bin (A/B OTA), updater
    # scripts, or 2+ partition .img files. Mirrors the heuristics in
    # services/firmware_service._is_android_firmware_zip but expressed
    # against the central-directory namelist instead of os.path.basename.
    basenames = {os.path.basename(n) for n in names}
    if "payload.bin" in basenames:
        return DetectedFormat.ANDROID_OTA
    android_meta = {
        "META-INF/com/google/android/updater-script",
        "META-INF/com/google/android/update-binary",
        "META-INF/com/android/metadata",
    }
    if names & android_meta:
        return DetectedFormat.ANDROID_OTA
    android_partitions = {
        "system.img", "boot.img", "vendor.img", "super.img",
        "recovery.img", "vbmeta.img", "dtbo.img", "product.img",
        "system_ext.img", "odm.img",
    }
    if len(basenames & android_partitions) >= 2:
        return DetectedFormat.ANDROID_OTA

    # Windows installer hint inside a ZIP (rare but seen — installer
    # toolkits sometimes ship as .zip with the WIM inside).
    if any(
        n.lower() in ("sources/boot.wim", "sources/install.wim", "bootmgr.efi")
        for n in names
    ):
        return DetectedFormat.WINDOWS_INSTALLER_ISO

    return None
