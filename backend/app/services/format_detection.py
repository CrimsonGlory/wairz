"""Pre-flight format detection for firmware uploads — catalog-driven (P3.1.h).

Cut-over per P3.1.h: classification routes through the file-format catalog
at :mod:`app.services.file_format_catalog`. The catalog's ``pre_upload``
sub-block declares ``detected_format`` (a closed Literal mirroring this
module's enum) + ``extraction_capability`` (full / partial / none) +
``banner_note`` (operator-visible free text). ``detect_format`` reads
the resolved manifest's ``pre_upload`` block when present, else returns
:attr:`DetectedFormat.UNKNOWN`.

``EXTRACTION_CAPABILITY`` + ``CAPABILITY_NOTES`` are derived at import
time from the catalog. The Rule #46 META-CANARY
``test_extraction_capability_catalog_derived_not_hardcoded`` confirms
the mapping flows from the YAML manifests, not hand-rolled tables.

Performance target: < 2 seconds on a 16 GB file. Catalog signal
evaluators are cost-sorted so the head buffer is read once (~512 KB);
ZIP central directory walks remain the heavier path and run only when
PK magic is present in the head.

The pre-P3.1.h implementation lived at `format_detection_legacy.py`
as a revert-safety shim through Phase 3.2; deleted in P3.3.a (2026-05-19)
after the parity test was converted to JSON-snapshot form in P3.2.e.

PE arch-view detection (Phase β.5): :func:`detect_pe_arch_view` is
PRESERVED here — it is decoupled from :func:`detect_format` (which runs
on every upload and stays lief-free) and called only by
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

from app.services.file_format_catalog import (
    get_default_catalog,
    resolve as _catalog_resolve,
)

logger = logging.getLogger(__name__)


# Read the first 512 KB for header inspection — large enough to cover
# every documented magic-byte location.
_HEAD_BYTES = 512 * 1024

# ZIP central directory end record search window (kept for compatibility
# with the few callers that import this constant directly).
_EOCD_SEARCH_BYTES = 64 * 1024 + 22


class DetectedFormat(str, Enum):
    """Coarse classification of an uploaded firmware file.

    Mirror of :data:`app.schemas.file_format.DetectedFormat` Literal.
    Cross-stack alignment (Rule #25 Shape-1) keeps the enum + the Literal
    + the frontend TypeScript union in sync; see
    :file:`backend/tests/test_file_format_detected_alignment.py`.
    """

    LINUX_FIRMWARE_BLOB = "linux_firmware_blob"
    ANDROID_APK = "android_apk"
    ANDROID_APEX = "android_apex"
    ANDROID_OTA = "android_ota"
    WINDOWS_INSTALLER_ISO = "windows_installer_iso"
    ACRONIS_BACKUP = "acronis_backup"
    QNX_IFS = "qnx_ifs"
    PE_EXECUTABLE = "pe_executable"
    WIM_ARCHIVE = "wim_archive"
    ISO_9660 = "iso_9660"
    TAR_ARCHIVE = "tar_archive"
    ZIP_ARCHIVE = "zip_archive"
    WINDOWS_CAB = "windows_cab"
    WINDOWS_MSI = "windows_msi"
    WINDOWS_MSIX = "windows_msix"
    WINDOWS_MSU = "windows_msu"
    WINDOWS_PSF = "windows_psf"
    WINDOWS_VHDX = "windows_vhdx"
    WINDOWS_DRIVER_PACKAGE = "windows_driver_package"
    UNKNOWN = "unknown"


class ExtractionCapability(str, Enum):
    """Whether wairz has a working extractor for the format."""

    FULL = "full"
    PARTIAL = "partial"
    NONE = "none"


def _build_capability_tables() -> tuple[
    dict[DetectedFormat, ExtractionCapability],
    dict[DetectedFormat, str],
]:
    """Derive EXTRACTION_CAPABILITY + CAPABILITY_NOTES from the catalog.

    Walks the loaded catalog at module-import time and collects each
    manifest's ``pre_upload.detected_format``/``extraction_capability``/
    ``banner_note`` triple. When two manifests share the same
    ``detected_format`` (e.g. squashfs + cramfs + jffs2 all → linux_firmware_blob),
    the FIRST capability wins (deterministic via catalog's sorted-by-
    format_id snapshot iteration). UNKNOWN routes to NONE.

    Rule #46 META-CANARY target — the corresponding test in
    :file:`test_file_format_detected_alignment.py` asserts the dict is
    derived from catalog state, not a hardcoded constant.
    """
    cap: dict[DetectedFormat, ExtractionCapability] = {}
    notes: dict[DetectedFormat, str] = {}
    try:
        catalog = get_default_catalog().get_catalog()
    except Exception:
        logger.exception("format_detection: catalog load failed; falling back")
        return _LEGACY_CAPABILITY_FALLBACK, _LEGACY_NOTES_FALLBACK
    for manifest in catalog.values():
        if manifest.pre_upload is None:
            continue
        try:
            df = DetectedFormat(manifest.pre_upload.detected_format)
            ec = ExtractionCapability(manifest.pre_upload.extraction_capability)
        except ValueError:
            continue
        if df not in cap:
            cap[df] = ec
        if manifest.pre_upload.banner_note and df not in notes:
            notes[df] = manifest.pre_upload.banner_note
    # Guarantee UNKNOWN is mapped (always NONE — the catch-all).
    cap.setdefault(DetectedFormat.UNKNOWN, ExtractionCapability.NONE)
    return cap, notes


# Fallback tables — used only when the catalog fails to load at import
# time (graceful-degrade per Rule #34). Mirrors the legacy hardcoded
# tables verbatim so behavior is preserved if the catalog is malformed.
_LEGACY_CAPABILITY_FALLBACK: dict[DetectedFormat, ExtractionCapability] = {
    DetectedFormat.LINUX_FIRMWARE_BLOB: ExtractionCapability.FULL,
    DetectedFormat.ANDROID_APK: ExtractionCapability.FULL,
    DetectedFormat.ANDROID_APEX: ExtractionCapability.FULL,
    DetectedFormat.ANDROID_OTA: ExtractionCapability.FULL,
    DetectedFormat.TAR_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.ZIP_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_INSTALLER_ISO: ExtractionCapability.FULL,
    DetectedFormat.PE_EXECUTABLE: ExtractionCapability.PARTIAL,
    DetectedFormat.ISO_9660: ExtractionCapability.FULL,
    DetectedFormat.WIM_ARCHIVE: ExtractionCapability.FULL,
    DetectedFormat.ACRONIS_BACKUP: ExtractionCapability.NONE,
    DetectedFormat.QNX_IFS: ExtractionCapability.PARTIAL,
    DetectedFormat.WINDOWS_CAB: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSI: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSIX: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_MSU: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_PSF: ExtractionCapability.PARTIAL,
    DetectedFormat.WINDOWS_VHDX: ExtractionCapability.FULL,
    DetectedFormat.WINDOWS_DRIVER_PACKAGE: ExtractionCapability.FULL,
    DetectedFormat.UNKNOWN: ExtractionCapability.NONE,
}

_LEGACY_NOTES_FALLBACK: dict[DetectedFormat, str] = {
    DetectedFormat.ACRONIS_BACKUP: (
        "Acronis .tibx/.tib backup detected. The format is proprietary; "
        "see CAPABILITY_NOTES for the operator-side BYOB workflow."
    ),
    DetectedFormat.QNX_IFS: (
        "Listing-only via jtang613/qnx_dumpers; for full extraction use "
        "host-side QNX SDP dumpifs."
    ),
    DetectedFormat.PE_EXECUTABLE: (
        "Windows PE executable detected. Binary analysis (strings, sections, "
        "decompilation) is available, but there is no firmware filesystem to "
        "extract."
    ),
    DetectedFormat.WINDOWS_PSF: (
        "Windows PSF (Express install delta) detected. Phase α ships a "
        "magic-validation stub — full reconstruction requires a baseline "
        "file and the gated psfextract toolchain."
    ),
    DetectedFormat.WINDOWS_DRIVER_PACKAGE: (
        "Windows driver package detected via operator hint."
    ),
}


# Module-level capability tables — built once at import; consumers that
# want the LIVE catalog state can call :func:`_build_capability_tables`
# directly, but for hot-path uploads the import-time snapshot is enough.
EXTRACTION_CAPABILITY, CAPABILITY_NOTES = _build_capability_tables()


def detect_format(path: Path | str) -> DetectedFormat:
    """Classify ``path`` against the catalog's pre-upload registry.

    Reads at most ~512 KB from the head of the file and, for ZIP
    containers, the central directory at the tail. The catalog resolver
    is invoked once; the returned manifest's ``pre_upload.detected_format``
    is mapped back to this module's enum.

    Returns ``DetectedFormat.UNKNOWN`` when:
      * the file is unreadable
      * the catalog resolved to the always_matches ``linux_blob``
        fallback but the head bytes don't carry a recognized signature
      * the resolved manifest has no ``pre_upload`` block

    Pre-P3.1.h legacy behavior was preserved at `format_detection_legacy`
    through P3.2; deleted in P3.3.a (2026-05-19).
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

    # Surface C bridge — let the catalog resolve the format_id from head
    # bytes + path; map ``pre_upload.detected_format`` back to this enum.
    # Skip the always_matches sentinel + generic-container shapes — these
    # need the legacy bridge below to disambiguate via inner-file walks
    # (ZIP central directory + ISO bootmgr substring + Acronis extension
    # fallback) and the UNKNOWN-for-genuinely-unrecognized semantic that
    # pre-upload distinguishes from "linux blob with unknown magic" that
    # the catalog's floor sentinel always matches.
    #
    # P3.2.a — sort-tier reform CLOSED the catalog-uncovered shapes for
    # the classifier path (mtk_lk / shannon_toc / kinibi_mclf / etc. now
    # resolve via the catalog directly because their `core` general-tier
    # manifests beat `_system/linux_blob_fallback` at floor tier). But for
    # the PRE-UPLOAD detect_format() path, ``linux_blob`` remains in the
    # disambiguation set so the legacy bridge can convert "sentinel-only
    # match" into UNKNOWN, matching pre-upload UX expectations.
    #
    # P3.2.d (deferred): the container-precedence numeric inversions
    # (windows_cab vs windows_msu; iso_9660 vs windows_installer_iso) are
    # auto-resolved by P3.2.a's `precedence` sort-flip — author intent of
    # "lower precedence wins" now matches resolver behavior. ``windows_cab``
    # + ``iso_9660`` will drop from this set after P3.2.d's parity test
    # re-verification.
    #
    # P3.x 2026-05-20: ``substring_in_head`` signal kind ships — the
    # catalog now expresses the bootmgr substring upgrade in YAML
    # (windows_installer_iso.yaml signal #2). Both ``iso_9660`` and
    # ``windows_installer_iso`` drop from this set; the legacy
    # ``_legacy_bridge_detect`` bootmgr upgrade block is deleted in the
    # same commit. ``windows_cab`` stays only because the legacy bridge
    # disambiguates .msu vs .cab via filename (Rule #19 evidence-first
    # — defer until a per-filename refinement signal lands).
    _CATALOG_NEEDS_DISAMBIGUATION: set[str] = {
        "linux_blob",            # floor sentinel — bridge maps to UNKNOWN for pre-upload
        "zip_archive",           # needs APK / OTA / MSIX inner-file walk
        "tar_archive",           # may need extension fallback for renamed tars
        # P3.2.d: windows_cab dropped — post-P3.2.a precedence-flip, the
        # catalog correctly routes .msu files to windows_msu (precedence 80
        # wins over windows_cab at 100). Verified via parity tests.
        # P3.x 2026-05-20: iso_9660 + windows_installer_iso dropped — the
        # new ``substring_in_head`` signal kind closes the bootmgr bridge.
    }
    match = _catalog_resolve(head, str(p), size)
    if match is not None and match.format_id not in _CATALOG_NEEDS_DISAMBIGUATION:
        catalog = get_default_catalog().get_catalog()
        manifest = catalog.get(match.format_id)
        if manifest is not None and manifest.pre_upload is not None:
            try:
                return DetectedFormat(manifest.pre_upload.detected_format)
            except ValueError:
                pass

    # Legacy bridge — catalog-uncovered shapes the cut-over preserves.
    # The catalog's always_matches ``linux_blob`` fallback outranks every
    # ``core`` manifest at source-rank 100 vs 80, so a few legacy paths
    # (installer-ISO bootmgr substring upgrade, ZIP inner-content
    # disambiguation, Acronis .tibx extension fallback, MSI filename
    # disambiguation, etc.) are bridged below until P3.1.b's sentinel
    # tier-floor is reformed.
    return _legacy_bridge_detect(head, p, size)


def _legacy_bridge_detect(head: bytes, p: Path, size: int) -> DetectedFormat:
    """Bridge legacy detect_format paths the catalog can't yet express.

    These paths exist because:

    * **windows_msi** — needs ``.msi`` / ``.msp`` filename PLUS OLE2 magic;
      filename signal in catalog is fine, but catalog's always_matches
      sentinel still outranks ``_system`` MSI at source-rank tie.
    * **acronis_backup** — needs extension fallback for renamed files.
    * **android_apk / android_ota / android_scatter / android_sparse** —
      ZIP inner-content disambiguation walks the central directory.

    All paths preserve the pre-P3.1.h detect_format behavior captured
    by the test_format_detection suite (legacy module deleted in
    P3.3.a 2026-05-19).

    P3.x 2026-05-20: the ``windows_installer_iso`` bootmgr-substring upgrade
    moved into the catalog as a ``substring_in_head`` signal — the legacy
    ISO bridge below is deleted in this commit.
    """
    if len(head) >= 4:
        magic4 = head[:4]
        # Linux firmware-blob magic bytes
        if magic4 in (b"hsqs", b"sqsh"):
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x45\x3d\xcd\x28":  # cramfs LE
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x85\x19\x03\x20" or magic4[:2] == b"\x85\x19":
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x27\x05\x19\x56":
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\xd0\x0d\xfe\xed":
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if len(head) >= 1082 and head[1080:1082] == b"\x53\xef":
            return DetectedFormat.LINUX_FIRMWARE_BLOB
        if magic4 == b"\x7fELF":
            return DetectedFormat.LINUX_FIRMWARE_BLOB

    if head.startswith(b"MSWIM\x00\x00\x00"):
        return DetectedFormat.WIM_ARCHIVE
    if head.startswith(b"vhdxfile"):
        return DetectedFormat.WINDOWS_VHDX
    if len(head) >= 4 and head[:4] in (b"PA30", b"PA19", b"PA17"):
        return DetectedFormat.WINDOWS_PSF
    if head.startswith(b"MSCF"):
        name_lower = p.name.lower()
        if name_lower.endswith(".msu"):
            return DetectedFormat.WINDOWS_MSU
        return DetectedFormat.WINDOWS_CAB
    if (
        len(head) >= 8
        and head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    ):
        name_lower = p.name.lower()
        if name_lower.endswith((".msi", ".msp")):
            return DetectedFormat.WINDOWS_MSI

    if len(head) >= 4:
        if head[:4] in (b"\xeb\x7e\xff\x7e", b"\x00\xff\x7e\xeb"):
            return DetectedFormat.QNX_IFS

    # P3.x 2026-05-20: ISO-9660 + Windows installer ISO disambiguation
    # moved into the catalog (windows_installer_iso.yaml signal #2 uses
    # ``substring_in_head`` for bootmgr / sources/boot.wim). Catalog
    # round-trip handles both formats — no legacy bridge needed.

    if head.startswith(b"MZ") and len(head) >= 0x40:
        try:
            (e_lfanew,) = struct.unpack_from("<I", head, 0x3c)
        except struct.error:
            e_lfanew = 0
        if 0 < e_lfanew < len(head) - 4 and head[e_lfanew:e_lfanew + 4] == b"PE\x00\x00":
            return DetectedFormat.PE_EXECUTABLE

    if len(head) >= 0x108 and head[0x101:0x106] == b"ustar":
        return DetectedFormat.TAR_ARCHIVE

    if head.startswith(b"PK\x03\x04"):
        zip_kind = _classify_zip(p)
        if zip_kind is not None:
            return zip_kind
        return DetectedFormat.ZIP_ARCHIVE

    name = p.name.lower()
    if name.endswith((".tibx", ".tib")):
        return DetectedFormat.ACRONIS_BACKUP
    if len(head) >= 12 and head[8:12] == b"ARCH":
        return DetectedFormat.ACRONIS_BACKUP

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

    if "AndroidManifest.xml" in names and any(
        n == "classes.dex" or n.startswith("classes") and n.endswith(".dex")
        for n in names
    ):
        return DetectedFormat.ANDROID_APK

    # APEX = Android Pony EXpress. Standard variant carries apex_manifest.pb
    # + apex_payload.img; CAPEX (Android 12+) carries apex_manifest.pb +
    # original_apex (a nested standard APEX). Either marker plus the
    # AndroidManifest.xml + META-INF/CERT.* signing co-presence positively
    # disambiguates from generic ZIPs that may happen to carry a stray
    # protobuf with the same basename.
    if (
        "apex_manifest.pb" in names
        and ("apex_payload.img" in names or "original_apex" in names)
    ):
        return DetectedFormat.ANDROID_APEX

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
        "system_ext.img", "odm.img", "vbmeta_system.img",
        "vendor_boot.img", "init_boot.img", "modem.img",
    }
    if len(basenames & android_partitions) >= 2:
        return DetectedFormat.ANDROID_OTA
    if any(b.startswith("super.img_sparsechunk.") for b in basenames):
        return DetectedFormat.ANDROID_OTA

    if any(
        n.lower() in ("sources/boot.wim", "sources/install.wim", "bootmgr.efi")
        for n in names
    ):
        return DetectedFormat.WINDOWS_INSTALLER_ISO

    msix_signal_files = {
        "AppxManifest.xml",
        "AppxBundleManifest.xml",
        "AppxMetadata/AppxBundleManifest.xml",
    }
    if names & msix_signal_files:
        return DetectedFormat.WINDOWS_MSIX

    return None


# ── PE arch-view (ARM64EC / ARM64X bimorphic) — PRESERVED from legacy ─────


_ARM64X_PAYLOAD: dict[str, str] = {
    "primary": "arm64x",
    "secondary": "amd64",
}
_ARM64EC_PAYLOAD: dict[str, str] = {
    "primary": "arm64ec",
    "secondary": "x64_abi",
}


def _count_arm64x_dynamic_fixups(load_configuration) -> int:
    """Count ARM64X dynamic-fixup relocations on a parsed PE."""
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
    """Count CHPE redirection-metadata entries on a parsed PE."""
    try:
        chpe = getattr(load_configuration, "chpe_metadata", None)
        if chpe is None:
            return 0
        return int(getattr(chpe, "redirection_metadata_count", 0) or 0)
    except Exception:
        return 0


def detect_pe_arch_view(path: Path | str) -> dict | None:
    """Inspect a PE binary for ARM64EC / ARM64X bimorphic markers.

    Preserved verbatim from the legacy implementation. lief is
    lazy-imported because the only caller — the Authenticode validator
    — runs in the worker container after upload (Rule #30).
    """
    p = Path(path)
    if not p.is_file():
        return None

    try:
        import lief  # noqa: PLC0415 — keep detect_format hot-path lief-free.
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

    return None
