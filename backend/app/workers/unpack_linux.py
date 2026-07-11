"""Linux-specific firmware detection and analysis."""

import os

from elftools.elf.elffile import ELFFile

from app.workers.unpack_common import (
    _ELF_ARCH_MAP,
    _FS_IMAGE_EXTENSIONS,
    _FS_ROOT_NAMES,
    _KERNEL_NAME_PATTERNS,
    _read_magic,
)


_UIMAGE_ARCH_MAP = {
    2: ("arm", "little"),
    21: ("aarch64", "little"),
    3: ("x86", "little"),
    23: ("x86_64", "little"),
    5: ("mips", "big"),
    6: ("mips64", "big"),
    7: ("ppc", "big"),
    9: ("sh", "little"),
    10: ("sparc", "big"),
    11: ("sparc64", "big"),
    25: ("riscv", "little"),
}

_UBOOT_MAGIC = b"\x27\x05\x19\x56"


def detect_architecture_from_uboot(firmware_path: str) -> tuple[str | None, str | None]:
    """Last-resort arch detection from a U-Boot uImage header.

    When no ELF binary can be found in the extracted tree (e.g. the rootfs
    didn't reconstruct, or only a kernel/RTOS blob was carved), the uImage
    header on the raw image still declares the target architecture. The
    header doesn't carry target endianness, so we fall back to the
    conventional default per architecture (see ``_UIMAGE_ARCH_MAP``).

    Returns (None, None) if no uImage header is present.
    """
    try:
        with open(firmware_path, "rb") as f:
            head = f.read(256 * 1024)
    except OSError:
        return None, None

    idx = 0 if head[:4] == _UBOOT_MAGIC else head.find(_UBOOT_MAGIC)
    if idx < 0 or idx + 30 > len(head):
        return None, None

    # The architecture lives in byte 29 (ih_arch) of the 64-byte header.
    ih_arch = head[idx + 29]
    return _UIMAGE_ARCH_MAP.get(ih_arch, (None, None))


def detect_architecture(fs_root: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness by examining ELF binaries.

    Uses majority voting across all ELF binaries found in common directories.
    """
    from collections import Counter

    search_dirs = ["bin", "usr/bin", "sbin", "usr/sbin", "lib"]
    votes: Counter[tuple[str, str]] = Counter()
    max_scan = 50

    for search_dir in search_dirs:
        search_path = os.path.join(fs_root, search_dir)
        if not os.path.isdir(search_path):
            continue

        try:
            entries = os.listdir(search_path)
        except OSError:
            continue

        for entry in entries:
            if sum(votes.values()) >= max_scan:
                break

            full_path = os.path.join(search_path, entry)
            if not os.path.isfile(full_path):
                continue
            try:
                with open(full_path, "rb") as f:
                    magic = f.read(4)
                    if magic != b"\x7fELF":
                        continue
                    f.seek(0)
                    elf = ELFFile(f)
                    arch = _ELF_ARCH_MAP.get(elf.header.e_machine, elf.header.e_machine)
                    endianness = "little" if elf.little_endian else "big"

                    if arch == "mips" and endianness == "little":
                        arch = "mipsel"

                    votes[(arch, endianness)] += 1
            except Exception:
                continue

    if not votes:
        return None, None

    (arch, endianness), _count = votes.most_common(1)[0]
    return arch, endianness


def detect_os_info(fs_root: str) -> str | None:
    """Read OS info from standard release files."""
    release_files = [
        "etc/os-release",
        "etc/openwrt_release",
        "etc/lsb-release",
        "etc/version",
        "etc/issue",
        "system/build.prop",
        "build.prop",
    ]
    for rel_file in release_files:
        full_path = os.path.join(fs_root, rel_file)
        if os.path.isfile(full_path):
            try:
                with open(full_path) as f:
                    content = f.read(1024)
                content = content.replace("\x00", "").strip()
                if content:
                    return content
            except Exception:
                continue
    return None


def detect_architecture_from_elf(path: str) -> tuple[str | None, str | None]:
    """Detect architecture and endianness from a single ELF file."""
    try:
        with open(path, "rb") as f:
            elf = ELFFile(f)
            machine = elf.header.e_machine
            arch = _ELF_ARCH_MAP.get(machine)
            endian = "little" if elf.little_endian else "big"
            return arch, endian
    except Exception:
        return None, None


# ARM 32-bit zImage header: arch/arm/boot/compressed/head.S
# 0x24: magic 0x016F2818 (LE)  |  0x30: endian marker
_ZIMAGE_ARM_MAGIC = 0x016F2818
_ZIMAGE_ENDIAN_LE = 0x04030201
_ZIMAGE_ENDIAN_BE = 0x01020304
# ARM64 Image header: Documentation/arm64/booting.rst
# 0x38: "ARM\x64" magic  |  0x30: flags (bit 0 = endianness)
_ARM64_IMAGE_MAGIC = b"ARM\x64"
_KERNEL_IMAGE_PREFIXES = (
    "zimage", "vmlinuz", "vmlinux", "uimage", "kernel", "image",
)


def _parse_kernel_header(data: bytes) -> tuple[str | None, str | None] | None:
    """Parse an ARM/ARM64 kernel image header for arch + endianness.

    Returns (arch, endianness) on recognised header, else None. Reads only
    the first 64 bytes — no decompression needed.
    """
    if len(data) < 0x40:
        return None
    # ARM 32-bit zImage
    magic_arm = int.from_bytes(data[0x24:0x28], "little")
    if magic_arm == _ZIMAGE_ARM_MAGIC:
        endian_word = int.from_bytes(data[0x30:0x34], "little")
        if endian_word == _ZIMAGE_ENDIAN_BE:
            return "arm", "big"
        return "arm", "little"
    # ARM64 Image
    if data[0x38:0x3C] == _ARM64_IMAGE_MAGIC:
        flags = int.from_bytes(data[0x30:0x38], "little")
        return "aarch64", "big" if flags & 1 else "little"
    return None


def detect_architecture_from_kernel(
    scan_dirs: list[str], max_scan: int = 30, max_depth: int = 6,
) -> tuple[str | None, str | None]:
    """Fallback arch detection by scanning for kernel image headers.

    Walks ``scan_dirs`` (non-recursively following symlinks) looking for
    files named like ``zImage``/``vmlinuz``/``uImage``/``Image``. Parses
    their headers with ``_parse_kernel_header`` and returns on the first
    match.

    This exists so firmware with an encrypted / missing rootfs — common on
    signed medical-device updates — still yields an ``architecture`` value
    when the ELF-voting path in ``detect_architecture`` finds nothing.
    """
    seen = 0
    for scan_dir in scan_dirs:
        if not scan_dir or not os.path.isdir(scan_dir):
            continue
        real_scan = os.path.realpath(scan_dir)
        for root, dirs, files in os.walk(scan_dir, followlinks=False):
            try:
                rel_depth = os.path.relpath(root, scan_dir).count(os.sep)
            except ValueError:
                rel_depth = 0
            if rel_depth >= max_depth:
                dirs[:] = []
                continue
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for name in files:
                low = name.lower()
                if not any(low.startswith(p) for p in _KERNEL_IMAGE_PREFIXES):
                    continue
                full = os.path.join(root, name)
                # Skip symlinks escaping the scan_dir
                try:
                    if os.path.islink(full):
                        target = os.path.realpath(full)
                        if not target.startswith(real_scan):
                            continue
                    with open(full, "rb") as fh:
                        head = fh.read(0x40)
                except OSError:
                    continue
                seen += 1
                parsed = _parse_kernel_header(head)
                if parsed:
                    return parsed
                if seen >= max_scan:
                    return None, None
    return None, None


def detect_kernel(extraction_dir: str, fs_root: str | None) -> str | None:
    """Scan the extraction directory for a kernel image."""
    if fs_root:
        scan_dir = os.path.dirname(fs_root)
    else:
        scan_dir = extraction_dir

    if not os.path.isdir(scan_dir):
        return None

    candidates: list[tuple[str, int]] = []

    for entry in os.scandir(scan_dir):
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        if name_lower in _FS_ROOT_NAMES:
            continue
        if name_lower.endswith(".json") or name_lower.endswith(".txt"):
            continue
        _, ext = os.path.splitext(name_lower)
        if ext in _FS_IMAGE_EXTENSIONS:
            continue

        try:
            file_size = entry.stat().st_size
        except OSError:
            continue

        if file_size < 500_000:
            continue

        if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
            candidates.append((entry.path, 100))
            continue

        magic = _read_magic(entry.path, 4)

        if magic == b"\x7fELF":
            try:
                with open(entry.path, "rb") as f:
                    elf = ELFFile(f)
                    if elf.header.e_type == "ET_EXEC" and file_size > 1_000_000:
                        candidates.append((entry.path, 95))
                        continue
            except Exception:
                pass

        if magic == b"\x27\x05\x19\x56":
            candidates.append((entry.path, 90))
            continue

        if file_size > 1_000_000:
            try:
                with open(entry.path, "rb") as f:
                    f.seek(0x24)
                    arm_magic = f.read(4)
                    if arm_magic == b"\x18\x28\x6f\x01":
                        candidates.append((entry.path, 92))
                        continue
            except OSError:
                pass

        if magic[:2] == b"\x1f\x8b" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

        if magic[:3] == b"\x5d\x00\x00" and file_size > 1_000_000:
            candidates.append((entry.path, 70))
            continue

    if not candidates:
        return None

    candidates.sort(key=lambda x: x[1], reverse=True)
    return candidates[0][0]


def check_tar_bomb(
    tar_path: str, max_size_bytes: int, max_files: int, max_ratio: int
) -> str | None:
    """Inspect a tar archive for zip-bomb indicators without extracting.

    Returns an error message string if any limit is exceeded, or None if OK.
    """
    import tarfile as _tarfile

    try:
        archive_size = os.path.getsize(tar_path)
    except OSError:
        return None

    total_size = 0
    file_count = 0

    try:
        with _tarfile.open(tar_path) as tf:
            for member in tf:
                file_count += 1
                if member.isreg():
                    total_size += member.size

                if file_count > max_files:
                    return (
                        f"Tar bomb detected: file count ({file_count}) "
                        f"exceeds limit ({max_files})"
                    )
                if total_size > max_size_bytes:
                    return (
                        f"Tar bomb detected: declared size "
                        f"({total_size // (1024*1024)}MB) exceeds limit "
                        f"({max_size_bytes // (1024*1024)}MB)"
                    )
    except Exception:
        return None  # Can't inspect — let extraction proceed

    if archive_size > 0 and total_size > 0:
        ratio = total_size / archive_size
        if ratio > max_ratio:
            return (
                f"Tar bomb detected: compression ratio ({ratio:.1f}:1) "
                f"exceeds limit ({max_ratio}:1)"
            )

    return None


def _firmware_tar_filter(member, dest_path):
    """Custom tar extraction filter for firmware rootfs archives."""
    import tarfile as _tarfile

    name = member.name.lstrip("/")
    if name != member.name:
        member = member.replace(name=name, deep=False)

    resolved = os.path.realpath(os.path.join(dest_path, name))
    real_dest = os.path.realpath(dest_path)
    if not resolved.startswith(real_dest + os.sep) and resolved != real_dest:
        raise _tarfile.AbsolutePathError(member)

    if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
        return None

    # Validate hard link targets stay within the extraction directory
    if member.islnk():
        link_target = member.linkname.lstrip("/")
        resolved_link = os.path.realpath(os.path.join(dest_path, link_target))
        if not resolved_link.startswith(real_dest + os.sep) and resolved_link != real_dest:
            raise _tarfile.AbsolutePathError(member)

    return member
