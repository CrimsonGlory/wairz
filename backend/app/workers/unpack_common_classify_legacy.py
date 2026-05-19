"""Legacy ``classify_firmware`` — revert-safety shim for the P3.1.h cut-over.

This module is a frozen extract of the pre-P3.1.h ``classify_firmware``
implementation + its supporting sub-detectors. Kept available for ~1
release as a recovery surface if the catalog cut-over needs to be
rolled back without a git revert. Callers can swap
``from app.workers.unpack_common import classify_firmware`` for
``from app.workers.unpack_common_classify_legacy import classify_firmware``
to reach this code.

The sub-detectors ``_is_uefi_content`` / ``_is_uefi_firmware`` /
``_is_partition_dump_tar`` / ``_is_rootfs_tar`` remain in
:mod:`app.workers.unpack_common` because they are consumed by OTHER
unpack pipelines (UEFI extractor, partition-dump walker, rootfs-tar
worker) — extracting copies here for the legacy shim keeps the
classify_firmware-only path self-contained.

DO NOT add new functionality here. New classification behaviour belongs
in the catalog YAMLs at ``data/file_formats/`` and the resolver at
``app.services.file_format_catalog.resolver.resolve``.
"""
from __future__ import annotations

import os


# EFI capsule GUID: BD86663B-08ED-4816-8FF0-D29BF6426720
_EFI_CAPSULE_GUID = b"\x3b\x66\x86\xbd\xed\x08\x16\x48\x8f\xf0\xd2\x9b\xf6\x42\x67\x20"
# Intel Flash Descriptor signature at offset 0x10
_IFD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
# UEFI Firmware Volume magic: _FVH
_FVH_MAGIC = b"_FVH"


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


def _is_uefi_content(data: bytes) -> bool:
    """Check if raw bytes contain UEFI firmware signatures."""
    if len(data) < 32:
        return False
    if data[:16] == _EFI_CAPSULE_GUID:
        return True
    if len(data) > 0x14 and data[0x10:0x14] == _IFD_SIGNATURE:
        return True
    search_region = data[:4096]
    if _FVH_MAGIC in search_region:
        return True
    return False


def _is_uefi_firmware(firmware_path: str, magic: bytes) -> bool:
    """Detect UEFI/BIOS firmware by magic bytes and structure."""
    if len(magic) >= 16 and magic[:16] == _EFI_CAPSULE_GUID:
        return True
    try:
        with open(firmware_path, "rb") as f:
            f.seek(0x10)
            ifd = f.read(4)
            if ifd == _IFD_SIGNATURE:
                return True
            f.seek(0)
            head = f.read(65536)
            if _FVH_MAGIC in head:
                return True
    except OSError:
        pass
    ext = os.path.splitext(firmware_path)[1].lower()
    if ext in (".rom", ".cap", ".fd", ".upd"):
        try:
            size = os.path.getsize(firmware_path)
            if 2 * 1024 * 1024 <= size <= 64 * 1024 * 1024:
                return True
        except OSError:
            pass
    return False


def _is_partition_dump_tar(firmware_path: str) -> bool:
    """Check if the file is a tar of raw partition images (EDL/MTKClient dump)."""
    import tarfile as _tarfile

    try:
        if not _tarfile.is_tarfile(firmware_path):
            return False
    except Exception:
        return False

    qualcomm_markers = {"aboot", "rpm", "tz", "hyp", "modem", "sbl1"}
    mtk_markers = {"lk", "tee", "preloader", "md1img", "spmfw", "sspm"}
    generic_markers = {"boot", "recovery", "system", "vendor", "super", "vbmeta", "dtbo"}
    all_markers = qualcomm_markers | mtk_markers | generic_markers

    try:
        with _tarfile.open(firmware_path) as tf:
            img_count = 0
            matched = 0
            for member in tf:
                name = os.path.basename(member.name)
                stem, ext = os.path.splitext(name)
                if ext.lower() == ".img":
                    img_count += 1
                    if stem.lower() in all_markers:
                        matched += 1
                if img_count >= 20:
                    break
            return img_count >= 3 and matched >= 2
    except Exception:
        return False


def _is_rootfs_tar(firmware_path: str) -> bool:
    """Check if the file is a tar archive containing a Linux rootfs."""
    import tarfile as _tarfile

    try:
        if not _tarfile.is_tarfile(firmware_path):
            return False
    except Exception:
        return False

    linux_dirs = {"etc", "usr", "bin", "lib", "sbin", "var", "tmp", "dev", "proc"}
    try:
        with _tarfile.open(firmware_path) as tf:
            top_names: set[str] = set()
            second_names: set[str] = set()
            count = 0
            for member in tf:
                parts = member.name.strip("/").split("/")
                if len(parts) >= 1:
                    top_names.add(parts[0])
                if len(parts) >= 2:
                    second_names.add(parts[1])
                count += 1
                if len(top_names & linux_dirs) >= 3:
                    return True
                if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                    return True
                if count >= 5000:
                    break
            if len(top_names & linux_dirs) >= 3:
                return True
            if len(top_names) <= 3 and len(second_names & linux_dirs) >= 3:
                return True
    except Exception:
        return False

    return False


def classify_firmware(firmware_path: str) -> str:
    """Classify firmware file type to determine the analysis pipeline.

    Legacy implementation preserved verbatim. New classification logic
    belongs in the catalog YAMLs at ``data/file_formats/``.
    """
    import zipfile as _zipfile

    if _zipfile.is_zipfile(firmware_path):
        try:
            with _zipfile.ZipFile(firmware_path, "r") as zf:
                names = set(zf.namelist())
                android_markers = {
                    "META-INF/com/google/android/updater-script",
                    "META-INF/com/google/android/update-binary",
                    "META-INF/com/android/metadata",
                    "payload.bin", "system.img", "boot.img", "vendor.img",
                }
                if len(names & android_markers) >= 2:
                    return "android_ota"
                if "payload.bin" in names or "system.img" in names:
                    return "android_ota"
                basenames = {os.path.basename(n) for n in names}
                android_partitions = {
                    "system.img", "boot.img", "vendor.img", "super.img",
                    "recovery.img", "vbmeta.img", "dtbo.img", "product.img",
                    "system_ext.img", "odm.img", "vbmeta_system.img",
                    "vendor_boot.img", "init_boot.img", "modem.img",
                }
                if len(basenames & android_partitions) >= 2:
                    return "android_ota"
                if any(b.startswith("super.img_sparsechunk.") for b in basenames):
                    return "android_ota"
                has_scatter = any(
                    n.endswith("_scatter.txt") or n.endswith("_Android_scatter.txt")
                    for n in names
                )
                has_super = any(n.endswith("/super.img") or n == "super.img" for n in names)
                if has_scatter and has_super:
                    return "android_scatter"
                has_manifest = "AndroidManifest.xml" in names
                has_dex = any(n.endswith(".dex") for n in names)
                if has_manifest and has_dex:
                    return "android_apk"
                uefi_zip_markers = {".cap", ".rom", ".fd", ".bin"}
                for name in names:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in uefi_zip_markers:
                        try:
                            inner = zf.read(name)
                            if _is_uefi_content(inner):
                                return "uefi_firmware"
                        except Exception:
                            pass
        except Exception:
            pass

    magic = _read_magic(firmware_path, 16)

    if magic[:4] == b"\x3a\xff\x26\xed":
        return "android_sparse"

    if magic[:8] == b"ANDROID!":
        return "android_boot"

    if _is_uefi_firmware(firmware_path, magic):
        return "uefi_firmware"

    if _is_partition_dump_tar(firmware_path):
        return "partition_dump_tar"

    if _is_rootfs_tar(firmware_path):
        return "linux_rootfs_tar"

    if magic[:4] == b"\x7fELF":
        try:
            from app.services.rtos_detection_service import detect_rtos
            rtos = detect_rtos(firmware_path)
            if rtos:
                rtos_name = rtos["rtos_name"]
                return f"{rtos_name}_elf"
        except Exception:
            pass
        return "elf_binary"

    if magic[:1] == b":" and all(
        c in b"0123456789ABCDEFabcdef:\r\n" for c in magic
    ):
        try:
            with open(firmware_path, errors="replace") as fh:
                first_line = fh.readline().strip()
            if (
                first_line.startswith(":")
                and len(first_line) >= 11
                and all(c in "0123456789ABCDEFabcdef" for c in first_line[1:])
            ):
                return "intel_hex"
        except OSError:
            pass

    if magic[:2] == b"MZ":
        return "pe_binary"

    try:
        from app.services.rtos_detection_service import detect_rtos
        rtos = detect_rtos(firmware_path)
        if rtos:
            return "rtos_blob"
    except Exception:
        pass

    return "linux_blob"


__all__ = ["classify_firmware"]
