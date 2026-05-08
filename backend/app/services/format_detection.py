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

PE arch-view detection (Phase β.5): :func:`detect_pe_arch_view` complements
the magic-byte path with a lief-backed introspection of ARM64EC / ARM64X
bimorphic markers. It is decoupled from :func:`detect_format` (which runs
on every upload and must stay lief-free) and called only by
``authenticode_service.verify_pe_file`` for binaries already classified
as PE. lief is lazy-imported inside the function for the same reason
(Rule #30 — keep cheap-detection paths import-cheap).
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
    # ── Windows ecosystem god-mode coverage (Phase α handlers 1-7) ───
    WINDOWS_CAB = "windows_cab"                    # MSCF magic at offset 0 (Cabinet)
    WINDOWS_MSI = "windows_msi"                    # OLE2 CFB magic + .msi/.msp filename
    WINDOWS_MSIX = "windows_msix"                  # ZIP + AppxManifest.xml or AppxBundleManifest.xml
    WINDOWS_MSU = "windows_msu"                    # MSCF magic + .msu filename (CAB-of-CABs)
    WINDOWS_PSF = "windows_psf"                    # PA30/PA19/PA17 magic at offset 0 (Express delta)
    WINDOWS_VHDX = "windows_vhdx"                  # 'vhdxfile' magic at offset 0 (Hyper-V/WSL2)
    WINDOWS_DRIVER_PACKAGE = "windows_driver_package"  # MSCF + INF/SYS/CAT (operator-hint for Phase α)
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
    DetectedFormat.WINDOWS_INSTALLER_ISO: ExtractionCapability.FULL,
    DetectedFormat.PE_EXECUTABLE: ExtractionCapability.PARTIAL,
    DetectedFormat.ISO_9660: ExtractionCapability.FULL,
    DetectedFormat.WIM_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.ACRONIS_BACKUP: ExtractionCapability.NONE,
    DetectedFormat.QNX_IFS: ExtractionCapability.PARTIAL,
    # Windows ecosystem god-mode coverage (Phase α handlers 1-7).
    # PSF is PARTIAL because Phase α ships a magic-validation stub —
    # full reconstruction needs a baseline + the gated psfextract
    # toolchain (Phase α.6 ARG INCLUDE_PSF=1).
    DetectedFormat.WINDOWS_CAB: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSI: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSIX: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSU: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_PSF: ExtractionCapability.PARTIAL,
    DetectedFormat.WINDOWS_VHDX: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_DRIVER_PACKAGE: ExtractionCapability.FULL,
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
        "Listing-only via jtang613/qnx_dumpers; for full extraction use "
        "host-side QNX SDP dumpifs."
    ),
    # WIM_ARCHIVE has no note — capability is FULL via wimlib-imagex
    # (Phase 2 handler 2). The full image list goes into the per-upload
    # unpack_log; the user-facing capability surface stays clean.
    # WINDOWS_INSTALLER_ISO has no note — capability is FULL via the
    # recursive ISO+WIM composite worker (Phase 2 handler 3). The
    # outer 7z extraction + per-WIM expansion details land in the
    # per-upload unpack_log, including counts of sibling extraction
    # trees produced by the inner-WIM pass.
    DetectedFormat.PE_EXECUTABLE: (
        "Windows PE executable detected. Binary analysis (strings, sections, "
        "decompilation) is available, but there is no firmware filesystem to "
        "extract."
    ),
    # ISO_9660 has no note — capability is FULL via 7z (Phase 2 handler 1).
    # Inner-WIM caveats live on WINDOWS_INSTALLER_ISO's note instead, which
    # is the format users actually need a workaround for.
    # WINDOWS_CAB / MSI / MSIX / MSU / VHDX / DRIVER_PACKAGE have no notes
    # — capabilities are FULL via Phase α handlers 1-4, 6, 7.
    DetectedFormat.WINDOWS_PSF: (
        "Windows PSF (Express install delta) detected. Phase α ships a "
        "magic-validation stub — full reconstruction requires a baseline "
        "file and the gated psfextract toolchain (Phase α.6 Dockerfile "
        "ARG INCLUDE_PSF=1). The unpack_psf worker preserves the .psf at "
        "the upload path; the windows_update MCP tools (Phase β) read "
        "the PSF header to identify the target binary's RSDS GUID, "
        "which the operator can use to locate the baseline. PSF deltas "
        "embedded in MSU packages are auto-detected by unpack_msu."
    ),
    DetectedFormat.WINDOWS_DRIVER_PACKAGE: (
        "Windows driver package detected via operator hint. Phase α "
        "auto-detection routes generic CABs to WINDOWS_CAB; if the "
        "uploaded CAB is a driver package (INF + SYS + CAT bundle), "
        "use the windows_archive MCP tool `reclassify_as_driver_package` "
        "(Phase α.4) to re-route. Auto-detection by CAB-content peek "
        "is a Phase β enhancement."
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

    # ── 2b. VHDX (Hyper-V / WSL2 virtual disk) ───────────────────────
    # Magic ``vhdxfile`` at offset 0. Verified per Microsoft MS-VHDX spec.
    # Distinct from legacy VHD (cookie ``conectix`` at last 512-byte block);
    # this detector handles VHDX only — VHD support is a future enum value.
    if head.startswith(b"vhdxfile"):
        return DetectedFormat.WINDOWS_VHDX

    # ── 2c. PSF (Patch Storage File / Express install delta) ─────────
    # Magic ``PA30`` (Win10/11), ``PA19`` (Win7/8), ``PA17`` (earliest).
    # Persona-E #1 — without PSF detection, MSU contents are ~80% opaque.
    if len(head) >= 4 and head[:4] in (b"PA30", b"PA19", b"PA17"):
        return DetectedFormat.WINDOWS_PSF

    # ── 2d. CAB family (CAB / MSU / driver package) ──────────────────
    # MSCF magic at offset 0. Subtype routing uses filename heuristics
    # for Phase α; CAB-content peek for driver-package auto-detection
    # is a Phase β enhancement (Persona-D #4 deferred).
    if head.startswith(b"MSCF"):
        name_lower = p.name.lower()
        if name_lower.endswith(".msu"):
            return DetectedFormat.WINDOWS_MSU
        return DetectedFormat.WINDOWS_CAB

    # ── 2e. MSI installer (OLE2 CFB + .msi/.msp filename) ────────────
    # OLE2 magic ``D0 CF 11 E0 A1 B1 1A E1`` is shared with Office DOC/
    # XLS/PPT — disambiguate via filename. The `unpack_msi` worker's
    # msiinfo probe is the authoritative validator at extraction time.
    if (
        len(head) >= 8
        and head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    ):
        name_lower = p.name.lower()
        if name_lower.endswith((".msi", ".msp")):
            return DetectedFormat.WINDOWS_MSI

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

    # MSIX / AppX / MSIXBundle — ZIP container with AppxManifest.xml or
    # AppxBundleManifest.xml at the root or under AppxMetadata/.
    # Persona-E #7+#8 — block-map verification + multi-package signing
    # chain validation are MCP-tool jobs (Phase α.4 / Phase β).
    msix_signal_files = {
        "AppxManifest.xml",
        "AppxBundleManifest.xml",
        "AppxMetadata/AppxBundleManifest.xml",
    }
    if names & msix_signal_files:
        return DetectedFormat.WINDOWS_MSIX

    return None


# ── PE arch-view (ARM64EC / ARM64X bimorphic) ────────────────────────────────
#
# Phase β.5. Persona-E #2 + #3: ARM64EC is a Windows 11 emulator-layer ABI
# where ARM64 native code presents an x64-compatible call surface (the
# binary's machine type in the PE header is ARM64EC). ARM64X is a true
# bimorphic image — ARM64 and AMD64 code coexist in one PE, switched at
# runtime via a CHPE dispatch table; system DLLs in 11-on-ARM use this
# shape so a single shipped DLL serves both x64 emulation and native ARM64
# callers. Bug classes can hide in only one half of an ARM64X binary —
# triaging without the discriminator means a vulnerability lives in the
# AMD64 path while the analyst reads the ARM64 path (or vice versa). The
# arch_view JSONB on ``windows_pe_signatures`` carries this discriminator.
#
# Output shape mirrors the ``WindowsPESignature.arch_view`` column docstring:
#   {
#     "primary":          "arm64x" | "arm64ec",
#     "secondary":        "amd64"  | "x64_abi",
#     "divergence_score": int,    # ARM64X: # of ARM64X dynamic-fixup
#                                 #   relocations (proxy for amount of
#                                 #   bimorphic code-flow surface).
#                                 # ARM64EC: # of CHPE redirection
#                                 #   metadata entries (proxy for
#                                 #   x64↔ARM64EC dispatch surface).
#                                 # 0 when the underlying load-config /
#                                 #   CHPE structures aren't readable.
#   }
# Single-arch PEs (regular ARM64 / AMD64 / I386 / etc.) return ``None`` —
# the column is nullable, and ``arch_view IS NULL`` is the durable signal
# for "single-architecture image, no bimorphic discriminator needed".


# Mapping from is_arm64ec / is_arm64x predicates to arch_view payload.
# Documented as a constant so the test file can iterate the discriminator
# table verbatim and the writer can stay declarative.
_ARM64X_PAYLOAD: dict[str, str] = {
    "primary": "arm64x",
    "secondary": "amd64",
}
_ARM64EC_PAYLOAD: dict[str, str] = {
    "primary": "arm64ec",
    "secondary": "x64_abi",
}


def _count_arm64x_dynamic_fixups(load_configuration) -> int:
    """Count ARM64X dynamic-fixup relocations on a parsed PE.

    Each ARM64X dynamic-relocation table entry carries a list of fixups;
    we count fixups whose class name matches the ARM64X family. Defensive:
    any attribute-miss yields 0 so the verdict still ships even if the
    LoadConfiguration shape varies between lief versions.
    """
    try:
        relocs = getattr(load_configuration, "dynamic_relocations", None) or []
    except Exception:
        return 0
    count = 0
    for reloc in relocs:
        try:
            fixups = getattr(reloc, "fixups", None) or []
            for fixup in fixups:
                cls = type(fixup).__name__
                if "ARM64X" in cls:
                    count += 1
        except Exception:
            continue
    return count


def _count_arm64ec_redirections(load_configuration) -> int:
    """Count CHPE redirection-metadata entries on a parsed PE.

    The CHPE metadata structure carries a ``redirection_metadata_count``
    that records how many x64↔ARM64EC dispatch entries the binary
    declares — a proxy for the size of the interop surface. Defensive
    against missing attributes; 0 on any miss.
    """
    try:
        chpe = getattr(load_configuration, "chpe_metadata", None)
        if chpe is None:
            return 0
        return int(getattr(chpe, "redirection_metadata_count", 0) or 0)
    except Exception:
        return 0


def detect_pe_arch_view(path: Path | str) -> dict | None:
    """Inspect a PE binary for ARM64EC / ARM64X bimorphic markers.

    Returns a dict ``{primary, secondary, divergence_score}`` for binaries
    whose ``is_arm64x`` or ``is_arm64ec`` predicates are true; ``None``
    for single-arch PEs and for non-PE / unreadable inputs.

    Used by :func:`app.services.authenticode_service.verify_pe_file` —
    the value lands on the ``WindowsPESignature.arch_view`` JSONB column
    (NULL for single-arch). The Phase β.4 verdict shape gains an
    ``arch_view`` field so the boundary between PE introspection and
    Authenticode validation stays drift-detectable (the
    ``test_verdict_maps_to_windows_pe_signature_columns`` shape check).

    lief is imported lazily because (a) format_detection's hot path
    (:func:`detect_format`) runs on every upload and stays lief-free, and
    (b) the only caller of this function — the Authenticode validator —
    runs in the worker container after the upload landed (Rule #30
    lazy-import discipline applies).
    """
    p = Path(path)
    if not p.is_file():
        return None

    # Lazy import so detect_format()'s hot path stays lief-free.
    try:
        import lief  # noqa: PLC0415 — see docstring.
    except Exception:
        logger.debug("lief unavailable; skipping arch_view detection")
        return None

    try:
        binary = lief.PE.parse(str(p))
    except Exception:
        logger.debug("lief PE parse failed for %s", p, exc_info=True)
        return None
    if binary is None:
        return None

    load_configuration = getattr(binary, "load_configuration", None)

    # is_arm64x is the strongest bimorphic signal — a binary actively
    # carrying ARM64X dynamic-fixup relocations has both code paths
    # cohabiting. Check before is_arm64ec because the ARM64X machine
    # type can be reported as ARM64 or ARM64EC depending on which half
    # the loader is preferring; the predicate is the authoritative gate.
    if getattr(binary, "is_arm64x", False):
        return {
            **_ARM64X_PAYLOAD,
            "divergence_score": _count_arm64x_dynamic_fixups(load_configuration),
        }

    if getattr(binary, "is_arm64ec", False):
        return {
            **_ARM64EC_PAYLOAD,
            "divergence_score": _count_arm64ec_redirections(load_configuration),
        }

    # Single-arch PE — caller persists arch_view=NULL.
    return None
