"""Common utilities for firmware unpacking — shared by Linux and Android paths."""

import asyncio
import logging
import os
import re as _re
import shutil as _shutil
import stat as _stat
import subprocess as _subprocess
import tarfile as _tarfile
import zipfile as _zipfile
from dataclasses import dataclass

logger = logging.getLogger(__name__)


def widen_read_perms(root: str) -> int:
    """Ensure every regular file and directory under ``root`` is readable
    (and dirs are traversable) by the backend user.

    Firmware tarballs frequently ship files with vendor-restrictive modes
    (e.g. ``rwxr-x---`` root:root for credential-generation scripts). When
    the Wairz backend runs as a non-root user it gets EPERM on such files,
    and the file-explorer API returns "no access" despite the file
    sitting happily on disk.

    This helper ORs ``0o044`` into file modes (group+other read) and
    ``0o055`` into directory modes (group+other read+execute). Does not
    touch execute bits on files, so scripts stay marked executable.
    Symlinks are skipped — chmod on a symlink affects the target, not
    the link, and some firmwares contain symlinks pointing outside the
    extraction sandbox.

    Returns the count of entries whose mode was changed.
    """
    changed = 0
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
            except OSError:
                continue
            if _stat.S_ISLNK(st.st_mode):
                continue
            is_dir = _stat.S_ISDIR(st.st_mode)
            mask = 0o055 if is_dir else 0o044
            new_mode = st.st_mode | mask
            if new_mode == st.st_mode:
                continue
            try:
                os.chmod(p, new_mode)
                changed += 1
            except OSError:
                continue
    return changed


# File extensions that indicate a nested archive worth recursively expanding.
# Matched case-insensitively against the full filename (so we can detect
# double-suffixes like .tar.gz / .tar.lz4 without relying on os.path.splitext).
_NESTED_ARCHIVE_SUFFIXES: tuple[str, ...] = (
    ".tar.md5",
    ".tar.gz",
    ".tar.xz",
    ".tar.bz2",
    ".tar.lz4",
    ".tar",
    ".zip",
    ".lz4",
)


def _recursive_extract_nested(root: str, max_depth: int = 3) -> list[str]:
    """Walk ``root`` and expand nested archives into sibling ``_extracted/``
    directories, recursively up to ``max_depth`` levels.

    Motivation: Samsung Odin packages wrap a ``.tar.md5`` that wraps a
    ``.tar.lz4`` that wraps the partitions.  Android OTA zips occasionally
    contain their own nested archives.  Before this helper we processed only
    the top-level zip and left the inner archives as opaque blobs.

    Args:
        root: Directory to walk.
        max_depth: Maximum recursion depth (default 3 covers
            ``.tar.md5 → tar → .tar.lz4``).

    Returns:
        Paths of new extraction directories, ordered parent-before-child.
        Callers may append these to their walk set.

    Safety:
        - Never follows symlinks.
        - Zip and tar extraction use member sanitisation that rejects
          absolute paths, parent traversal (..), and links that escape the
          destination.  Uses ``tarfile.data_filter`` (Python 3.12+) where
          available for extra defence-in-depth.
    """
    new_dirs: list[str] = []
    _recursive_extract_nested_inner(root, max_depth, new_dirs, depth=0)
    return new_dirs


def _recursive_extract_nested_inner(
    current: str,
    max_depth: int,
    new_dirs: list[str],
    depth: int,
) -> None:
    if depth >= max_depth:
        return
    try:
        entries = list(os.scandir(current))
    except OSError:
        return

    to_recurse: list[str] = []

    for entry in entries:
        # Never follow symlinks when walking or when identifying targets
        if entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            # Recurse into subdirs AFTER processing archives at this level
            to_recurse.append(entry.path)
            continue
        if not entry.is_file(follow_symlinks=False):
            continue

        lname = entry.name.lower()
        matched_suffix: str | None = None
        for suffix in _NESTED_ARCHIVE_SUFFIXES:
            if lname.endswith(suffix):
                matched_suffix = suffix
                break
        if matched_suffix is None:
            continue

        archive_path = entry.path
        out_dir = archive_path + "_extracted"
        if os.path.exists(out_dir):
            # Already extracted on a previous run
            continue

        try:
            extracted = _extract_single_archive(archive_path, out_dir, matched_suffix)
        except Exception as e:
            logger.info("Nested archive extract failed for %s: %s", archive_path, e)
            # Clean up partial output to avoid polluting future walks
            if os.path.isdir(out_dir):
                _shutil.rmtree(out_dir, ignore_errors=True)
            continue

        if extracted:
            new_dirs.append(out_dir)
            to_recurse.append(out_dir)

    for child in to_recurse:
        _recursive_extract_nested_inner(child, max_depth, new_dirs, depth + 1)


def _extract_single_archive(
    archive_path: str, out_dir: str, matched_suffix: str,
) -> bool:
    """Extract one nested archive. Returns True on success."""
    os.makedirs(out_dir, exist_ok=True)

    # .lz4 (plain, non-tar) → decompress to a single file
    if matched_suffix == ".lz4":
        # Fast path: if the upstream named it foo.tar.lz4 we want the tar.
        # For bare foo.bin.lz4, just write foo.bin.
        base = os.path.basename(archive_path)
        if base.lower().endswith(".tar.lz4"):
            inner_name = base[: -len(".lz4")]
        else:
            inner_name = base[: -len(".lz4")] or "payload.bin"
        inner_path = os.path.join(out_dir, inner_name)
        _decompress_lz4(archive_path, inner_path)
        # If the decompressed file is itself a tar, expand it in place.
        if inner_name.lower().endswith(".tar") and _tarfile.is_tarfile(inner_path):
            _extract_tar_safe(inner_path, out_dir)
            try:
                os.remove(inner_path)
            except OSError:
                pass
        return True

    # .tar.lz4 → decompress to tar, then extract
    if matched_suffix == ".tar.lz4":
        tar_path = os.path.join(out_dir, "inner.tar")
        _decompress_lz4(archive_path, tar_path)
        if _tarfile.is_tarfile(tar_path):
            _extract_tar_safe(tar_path, out_dir)
        try:
            os.remove(tar_path)
        except OSError:
            pass
        return True

    # .zip
    if matched_suffix == ".zip":
        if not _zipfile.is_zipfile(archive_path):
            return False
        _extract_zip_safe(archive_path, out_dir)
        return True

    # All remaining: tar family (.tar / .tar.gz / .tar.xz / .tar.bz2 / .tar.md5)
    # .tar.md5 is just a regular tar with an MD5 checksum appended at EOF;
    # tarfile silently ignores the trailing junk when `ignore_zeros=True`.
    if _tarfile.is_tarfile(archive_path):
        _extract_tar_safe(archive_path, out_dir)
        return True

    return False


def _decompress_lz4(src: str, dst: str) -> None:
    """Decompress an LZ4 file to dst using the system `lz4` CLI.

    We don't depend on a Python lz4 binding because it's not currently in
    the backend's pyproject.toml.  The `lz4` CLI ships with the container
    image (see Dockerfile).  If it's missing we raise a RuntimeError so
    the caller logs and skips — we never silently fail.
    """
    if not _shutil.which("lz4"):
        raise RuntimeError("lz4 CLI not available; cannot decompress .lz4 archive")

    # lz4 -dc src > dst (stdin/stdout avoids a weird -f behaviour on some
    # distros where an existing dst triggers a prompt).
    with open(dst, "wb") as out:
        proc = _subprocess.run(
            ["lz4", "-dc", src],
            stdout=out,
            stderr=_subprocess.PIPE,
            check=False,
            timeout=600,
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"lz4 decompression failed (rc={proc.returncode}): "
            f"{proc.stderr.decode(errors='replace')[:500]}"
        )


def _extract_tar_safe(tar_path: str, out_dir: str) -> None:
    """Extract a tar archive, rejecting symlink-escape and absolute paths.

    Uses tarfile.data_filter where available (Python 3.12+), else a
    hand-rolled filter matching the _firmware_tar_filter in unpack_linux.
    """
    with _tarfile.open(tar_path, mode="r:*", ignore_zeros=True) as tf:
        filter_fn = getattr(_tarfile, "data_filter", None)
        if filter_fn is not None:
            try:
                tf.extractall(out_dir, filter=filter_fn)
                return
            except Exception:
                pass
        # Fallback: manual per-member sanitisation
        real_dest = os.path.realpath(out_dir)
        for member in tf.getmembers():
            name = member.name.lstrip("/")
            if name != member.name:
                member = member.replace(name=name, deep=False)
            dest_resolved = os.path.realpath(os.path.join(out_dir, name))
            if not (
                dest_resolved == real_dest
                or dest_resolved.startswith(real_dest + os.sep)
            ):
                continue
            if not (member.isreg() or member.isdir() or member.issym() or member.islnk()):
                continue
            if member.islnk():
                link_target = member.linkname.lstrip("/")
                link_resolved = os.path.realpath(os.path.join(out_dir, link_target))
                if not (
                    link_resolved == real_dest
                    or link_resolved.startswith(real_dest + os.sep)
                ):
                    continue
            if member.issym():
                # Skip symlinks entirely — can escape even with relative targets
                continue
            try:
                tf.extract(member, out_dir, set_attrs=False)
            except Exception:
                continue


def _extract_zip_safe(zip_path: str, out_dir: str) -> None:
    """Extract a zip archive with zipslip, bomb, and symlink defences.

    Delegates to ``safe_extract_zip`` which enforces all three checks:
    per-entry realpath containment, running uncompressed-size cap (4 GiB),
    and rejection of Unix-symlink entries.
    """
    from app.workers.safe_extract import safe_extract_zip
    safe_extract_zip(zip_path, out_dir)


# Known vendor-encrypted container magics — first 16 bytes.
# When an archive-named file starts with one of these, it's NOT a real
# tar.xz/zip; it's a signed/encrypted vendor container. Wairz records the
# fact in device_metadata so the UI can surface "partial extraction".
_VENDOR_CONTAINER_MAGICS: dict[bytes, dict[str, str]] = {
    # EDAN Instruments — Multi-Parameter Monitor (AM43xx Sitara) signed
    # firmware container. Observed on RespArray/CX/iV/iX/uX/Vista300
    # update packages. 16 bytes of magic+schema+key-id, body is
    # AES-encrypted, paired with a 256-byte RSA-2048 `.signature` sidecar.
    bytes.fromhex("a3dfbbbf4e947c6649859f5e45d273ed"): {
        "format": "edan_mpm_signed",
        "vendor": "edan",
        "note": (
            "EDAN MPM signed firmware container (AM43xx platform). "
            "Payload is vendor-encrypted; decryption key must be "
            "recovered from nxapp/nxcore via Ghidra."
        ),
    },
}


def _identify_vendor_container(path: str) -> dict[str, str] | None:
    """Return vendor-container metadata when ``path``'s first 16 bytes match a
    known vendor-encrypted container signature, else ``None``.
    """
    try:
        with open(path, "rb") as fh:
            head = fh.read(16)
    except OSError:
        return None
    return _VENDOR_CONTAINER_MAGICS.get(head)


def _read_magic_hex(path: str, n: int = 16) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read(n).hex()
    except OSError:
        return ""


def diagnose_failed_archives(scan_dirs: list[str], max_depth: int = 6) -> dict:
    """Walk ``scan_dirs`` for archive-named files that are NOT valid archives.

    An archive-named file (``.tar.xz``, ``.zip``, ``.lz4``, etc.) that fails
    ``tarfile.is_tarfile`` / ``zipfile.is_zipfile`` is either a
    vendor-encrypted container (matched via ``_VENDOR_CONTAINER_MAGICS``)
    or an unrecognised format. Either way, Wairz's recursive extractor
    silently dropped it — the diagnostic surfaces that fact.

    Returns a dict suitable for merging into
    ``Firmware.device_metadata["extraction_diagnostics"]`` or an empty dict
    when every archive in scope extracted cleanly.
    """
    encrypted: list[dict] = []
    unrecognised: list[dict] = []
    seen_paths: set[str] = set()
    for scan_dir in scan_dirs:
        if not scan_dir or not os.path.isdir(scan_dir):
            continue
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
                lname = name.lower()
                matched_suffix: str | None = None
                for suffix in _NESTED_ARCHIVE_SUFFIXES:
                    if lname.endswith(suffix):
                        matched_suffix = suffix
                        break
                if matched_suffix is None:
                    continue
                full = os.path.join(root, name)
                if full in seen_paths or os.path.islink(full):
                    continue
                seen_paths.add(full)
                # Skip if the archive did extract successfully (content
                # present in the sibling _extracted/ dir).
                sibling = full + "_extracted"
                if os.path.isdir(sibling):
                    try:
                        if any(os.scandir(sibling)):
                            continue
                    except OSError:
                        pass
                # Verify NOT a real archive before flagging.
                try:
                    if matched_suffix == ".zip":
                        if _zipfile.is_zipfile(full):
                            continue
                    elif _tarfile.is_tarfile(full):
                        continue
                except (OSError, _tarfile.ReadError):
                    pass
                try:
                    size = os.path.getsize(full)
                except OSError:
                    size = 0
                entry: dict = {
                    "path": os.path.relpath(full, scan_dir),
                    "size_bytes": size,
                    "suffix": matched_suffix,
                    "magic_hex": _read_magic_hex(full, 16),
                }
                ident = _identify_vendor_container(full)
                if ident:
                    entry.update(ident)
                    encrypted.append(entry)
                else:
                    unrecognised.append(entry)
    total = len(encrypted) + len(unrecognised)
    if not total:
        return {}
    parts: list[str] = []
    if encrypted:
        vendors = sorted({e.get("vendor", "?") for e in encrypted})
        parts.append(f"{len(encrypted)} vendor-encrypted ({'/'.join(vendors)})")
    if unrecognised:
        parts.append(f"{len(unrecognised)} unrecognised")
    return {
        "partial_extraction": True,
        "encrypted_archives": encrypted,
        "unrecognised_archives": unrecognised,
        "summary": f"{total} archive(s) not extracted: " + ", ".join(parts),
    }


@dataclass
class UnpackResult:
    extracted_path: str | None = None
    extraction_dir: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    os_info: str | None = None
    kernel_path: str | None = None
    binary_info: dict | None = None
    unpack_log: str = ""
    success: bool = False
    error: str | None = None
    # Vendor-AES auto-decrypt audit: one entry per encrypted archive that
    # the decrypt pass found a working key for. Consumed by the background
    # unpack runner to populate firmware.device_metadata['vendor_decryption'].
    vendor_decryption: list[dict] | None = None
    # Absolute paths of the _extract/ directories produced by the vendor-AES
    # decrypt pass. Written to firmware.device_metadata['detection_roots']
    # by the DB runner so the file-explorer virtual-root walker surfaces
    # them (its *-root regex filter hides them otherwise).
    decryption_output_dirs: list[str] | None = None


# Map ELF machine types to friendly names
_ELF_ARCH_MAP = {
    "EM_MIPS": "mips",
    "EM_ARM": "arm",
    "EM_AARCH64": "aarch64",
    "EM_386": "x86",
    "EM_X86_64": "x86_64",
    "EM_PPC": "ppc",
    "EM_PPC64": "ppc64",
    "EM_SH": "sh",
    "EM_SPARC": "sparc",
}

# Known filesystem root directory names produced by binwalk extraction
_FS_ROOT_NAMES = frozenset({
    "ext-root", "squash-root", "squashfs-root", "ubifs-root",
    "cpio-root", "jffs2-root", "cramfs-root", "romfs-root",
})

# Filename patterns that strongly indicate a kernel image
_KERNEL_NAME_PATTERNS = ("vmlinux", "zimage", "uimage", "bzimage")

# File extensions for filesystem images — NOT kernels
_FS_IMAGE_EXTENSIONS = frozenset({
    ".ext", ".ext2", ".ext3", ".ext4",
    ".yaffs", ".yaffs2",
    ".jffs2",
    ".squashfs", ".sqfs",
    ".cramfs",
    ".ubifs", ".ubi",
    ".romfs",
    ".cpio",
})

_ROOT_DIR_RE = _re.compile(r"^[a-z0-9]+-root(-\d+)?$")

# Unblob chunk suffixes that indicate successfully processed content
_EXTRACT_DIR_SUFFIXES = ("_extract",)


def cleanup_unblob_artifacts(extraction_dir: str) -> int:
    """Remove only truly-junk artifacts left by unblob/binwalk.

    Unblob splits firmware images into named chunks.  Successfully
    identified chunks get an ``_extract`` sibling directory with their
    contents.  We keep:

    - ``.unknown`` chunks: unblob didn't recognise them, but hw-firmware
      parsers (GFH / HMBN / Qualcomm MBN, etc.) commonly do.  Previously
      we deleted these, silently dropping vendor bootloader tails.

    We remove:

    - Zero-byte files (e.g. ``empty.unknown``) — no parser will ever help.
    - ``.test`` and ``.backup`` files — unblob's intermediate test scratch.
    - Raw chunk files that already have a corresponding ``_extract`` dir
      (the content survives in the extracted dir).

    Returns the number of files removed.
    """
    removed = 0
    try:
        entries = list(os.scandir(extraction_dir))
    except OSError:
        return 0

    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue

        name_lower = entry.name.lower()

        # Always drop zero-byte files — truly empty.
        try:
            if entry.stat(follow_symlinks=False).st_size == 0:
                os.unlink(entry.path)
                removed += 1
                continue
        except OSError:
            continue

        # Drop clear test/backup scratch files.
        if name_lower.endswith(".test") or name_lower.endswith(".backup"):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass
            continue

        # Keep non-empty .unknown chunks — hw-firmware parsers use them.
        if name_lower.endswith(".unknown"):
            continue

        # Remove raw chunk files that have a corresponding _extract dir
        # e.g. "53742118-282966566.squashfs_v4_le" when
        #      "53742118-282966566.squashfs_v4_le_extract/" exists
        extract_dir = entry.path + "_extract"
        if os.path.isdir(extract_dir):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass

    return removed


def check_extraction_limits(
    extraction_dir: str, firmware_size: int, settings=None
) -> str | None:
    """Walk the extraction directory and enforce zip-bomb prevention limits.

    Returns an error message string if any limit is exceeded, or None if OK.
    """
    if settings is None:
        from app.config import get_settings
        settings = get_settings()

    max_bytes = settings.max_extraction_size_mb * 1024 * 1024
    max_files = settings.max_extraction_files
    max_ratio = settings.max_compression_ratio

    total_size = 0
    file_count = 0

    def _walk(path: str) -> str | None:
        nonlocal total_size, file_count
        try:
            entries = os.scandir(path)
        except OSError:
            return None
        for entry in entries:
            try:
                if entry.is_file(follow_symlinks=False):
                    file_count += 1
                    total_size += entry.stat(follow_symlinks=False).st_size
                elif entry.is_dir(follow_symlinks=False):
                    result = _walk(entry.path)
                    if result is not None:
                        return result
            except OSError:
                continue

            if file_count > max_files:
                return (
                    f"Extraction bomb detected: file count ({file_count}) "
                    f"exceeds limit ({max_files})"
                )
            if total_size > max_bytes:
                return (
                    f"Extraction bomb detected: total size "
                    f"({total_size // (1024*1024)}MB) exceeds limit "
                    f"({settings.max_extraction_size_mb}MB)"
                )
        return None

    error = _walk(extraction_dir)
    if error:
        return error

    # Check compression ratio
    if firmware_size > 0 and total_size > 0:
        ratio = total_size / firmware_size
        if ratio > max_ratio:
            return (
                f"Extraction bomb detected: compression ratio ({ratio:.1f}:1) "
                f"exceeds limit ({max_ratio}:1)"
            )

    return None


def remove_extraction_escape_symlinks(extraction_dir: str) -> int:
    """Remove top-level symlinks whose target escapes extraction_dir.

    ``binwalk3 -e -C output_dir input.bin`` ALWAYS creates a top-level
    symlink ``output_dir/<input_basename>`` that points back at the
    absolute path of the input file — regardless of whether it found
    anything to extract.  When nothing is extracted that symlink is the
    only artifact in ``extraction_dir``, and:

      1. :func:`find_filesystem_root`'s fallback pass (pick the dir
         with the most entries) counts it as "rootfs with 1 file"
         and marks the extraction successful.
      2. The file tree API exposes the symlink to the UI.
      3. When a user clicks it, the sandbox (``_resolve_within_root``)
         rewrites the absolute symlink target as root-relative —
         yielding a nonexistent path inside ``extraction_dir`` that
         404s.  User sees "can't access" for a file that visually
         exists in the tree.

    We scan ONLY the top level of ``extraction_dir`` — rootfs-internal
    symlinks such as ``etc/passwd -> /usr/etc/passwd`` live deeper in
    the tree and are preserved (the sandbox's chroot emulation handles
    those correctly).  Broken symlinks (target missing) are also
    removed — they are always extraction leftovers.

    Safe to call multiple times: idempotent on an already-clean tree.

    Returns the number of symlinks removed.
    """
    try:
        real_root = os.path.realpath(extraction_dir)
    except OSError:
        return 0

    try:
        entries = list(os.scandir(extraction_dir))
    except OSError:
        return 0

    removed = 0
    for entry in entries:
        if not entry.is_symlink():
            continue
        try:
            target_real = os.path.realpath(entry.path)
        except OSError:
            # Broken symlink — target doesn't exist on disk at all.
            # Always an extraction artifact; remove.
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass
            continue

        # Escape check: realpath must equal real_root or be a prefix
        # under it.  Anything else points outside the sandbox.
        if target_real != real_root and not target_real.startswith(
            real_root + os.sep
        ):
            try:
                os.unlink(entry.path)
                removed += 1
            except OSError:
                pass
    return removed


async def run_binwalk_extraction(firmware_path: str, output_dir: str, timeout: int = 600) -> str:  # noqa: ASYNC109 — caller-supplied per-call timeout passed through to asyncio.wait_for (Rule #29)
    """Run binwalk3 -e to extract firmware contents. Returns stdout+stderr."""
    proc = await asyncio.create_subprocess_exec(
        "binwalk3", "-e", "-C", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"binwalk extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


async def run_unblob_extraction(firmware_path: str, output_dir: str, timeout: int = 1200) -> str:  # noqa: ASYNC109 — caller-supplied per-call timeout passed through to asyncio.wait_for (Rule #29)
    """Run unblob to extract firmware — handles 78+ formats.

    Unblob handles Rockchip RKFW, MediaTek, Qualcomm, and many proprietary
    container formats that binwalk cannot. Used as fallback when binwalk
    fails or times out.
    """
    from shutil import which

    if not which("unblob"):
        raise RuntimeError("unblob is not installed")

    # --no-sandbox: unblob's Landlock sandbox induces EXDEV on sasquatch's
    # link() calls when extracting squashfs with hardlinks (every Linux
    # rootfs). sasquatch FATAL-aborts mid-extract leaving most files as
    # 0-byte stubs. Container-level isolation is the actual security
    # boundary — Landlock here is redundant and breaks correctness.
    proc = await asyncio.create_subprocess_exec(
        "unblob", "--no-sandbox", "--extract-dir", output_dir, firmware_path,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"unblob extraction timed out after {timeout}s")

    return stdout.decode(errors="replace").replace("\x00", "")


async def run_uefi_extraction(firmware_path: str, output_dir: str, timeout: int = 300) -> str:  # noqa: ASYNC109 — caller-supplied per-call timeout passed through to asyncio.wait_for (Rule #29)
    """Run UEFIExtract to parse and extract UEFI/BIOS firmware.

    UEFIExtract produces a hierarchical .dump/ directory with all firmware
    volumes, DXE drivers, PEI modules, NVRAM, and other components extracted
    and decompressed. Each component gets header.bin, body.bin, and info.txt.
    """
    from shutil import which

    if not which("UEFIExtract"):
        raise RuntimeError(
            "UEFIExtract is not installed. "
            "Install from https://github.com/LongSoft/UEFITool"
        )

    import shutil

    # UEFIExtract creates output at <input>.dump/ next to the input file.
    # Copy firmware to output_dir so the .dump/ lands there.
    work_copy = os.path.join(output_dir, os.path.basename(firmware_path))
    shutil.copy2(firmware_path, work_copy)

    proc = await asyncio.create_subprocess_exec(
        "UEFIExtract", work_copy, "all",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        raise TimeoutError(f"UEFIExtract timed out after {timeout}s")

    log = stdout.decode(errors="replace").replace("\x00", "")

    # Remove the work copy (keep only the .dump/ directory)
    try:
        os.unlink(work_copy)
    except OSError:
        pass

    return log


def _read_magic(path: str, num_bytes: int = 4) -> bytes:
    """Read the first N bytes of a file for magic number detection."""
    try:
        with open(path, "rb") as f:
            return f.read(num_bytes)
    except OSError:
        return b""


# ---------------------------------------------------------------------------
# Vendor-AES auto-decrypt (firmware packages whose update scripts hardcode an
# openssl key/iv to decrypt sibling archive payloads).
# ---------------------------------------------------------------------------
# The regex accepts both `openssl aes-128-cbc` and `openssl enc -aes-128-cbc`
# shapes, since vendors use both. It also tolerates `-K HEX` in either order
# relative to `-iv HEX`. Restricted to CBC because ECB/CTR/GCM require
# different flag handling; add as separate clauses if needed.
_OPENSSL_AES_CBC_RE = _re.compile(
    r"openssl\s+(?:enc\s+-)?aes-(128|192|256)-cbc\b"
    r"(?:[^\n]*?)"
    r"(?:-K\s+([0-9a-fA-F]{32,64})\b[^\n]*?-iv\s+([0-9a-fA-F]{32})\b"
    r"|-iv\s+([0-9a-fA-F]{32})\b[^\n]*?-K\s+([0-9a-fA-F]{32,64})\b)"
)

# File extensions we attempt to auto-decrypt + their required plaintext magic.
# The magic check after decryption is a strict gate against false positives.
_ARCHIVE_MAGIC: dict[str, bytes] = {
    ".tar.xz": b"\xfd7zXZ\x00",
    ".tar.gz": b"\x1f\x8b",
    ".tgz":    b"\x1f\x8b",
    ".tar.bz2": b"BZh",
    ".zip":    b"PK\x03\x04",
    ".xz":     b"\xfd7zXZ\x00",
}


@dataclass(frozen=True)
class _AesKeyTriple:
    algo: str       # "aes-128-cbc" / "aes-192-cbc" / "aes-256-cbc"
    key_hex: str    # 32 / 48 / 64 hex chars (lower)
    iv_hex: str     # 32 hex chars (lower)
    source: str     # file:line where discovered


def _detect_openssl_key_triples(extraction_dir: str) -> list[_AesKeyTriple]:
    """Walk ``extraction_dir`` for shell scripts that hardcode an AES-CBC
    key+iv for openssl decryption, and return every distinct triple found.

    Shapes matched (case-sensitive; openssl's CLI args are case-sensitive):
        openssl aes-128-cbc -d ... -K <hex32> ... -iv <hex32> ...
        openssl aes-256-cbc -d ... -iv <hex32> ... -K <hex64> ...
        openssl enc -aes-128-cbc -d ... -K <hex32> -iv <hex32>

    Returns an empty list when no script matches — the caller should
    silently skip the auto-decrypt pass in that case.
    """
    found: dict[tuple[str, str, str], _AesKeyTriple] = {}
    for root, dirs, files in os.walk(extraction_dir, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            # Cheap filter: only read files that plausibly contain shell.
            # ".sh", "Makefile", "install*", "update*" — and anything with
            # no extension but small enough to be a shell script.
            lname = name.lower()
            path = os.path.join(root, name)
            try:
                st = os.stat(path, follow_symlinks=False)
            except OSError:
                continue
            if st.st_size > 1_000_000:  # >1 MB unlikely to be a shell script
                continue
            if not (
                lname.endswith(".sh")
                or lname.endswith(".bash")
                or lname in ("makefile",)
                or "update" in lname
                or "install" in lname
                or "." not in name
            ):
                continue
            try:
                with open(path, "rb") as f:
                    data = f.read(st.st_size)
            except OSError:
                continue
            try:
                text = data.decode("utf-8", errors="replace")
            except Exception:
                continue
            for m in _OPENSSL_AES_CBC_RE.finditer(text):
                bits = m.group(1)
                # Groups 2+3 are (-K first, -iv second); groups 4+5 are (-iv first, -K second)
                if m.group(2) and m.group(3):
                    key_hex, iv_hex = m.group(2).lower(), m.group(3).lower()
                else:
                    key_hex, iv_hex = m.group(5).lower(), m.group(4).lower()
                # Sanity: key hex length must match the declared algorithm
                expected_key_nibbles = {"128": 32, "192": 48, "256": 64}[bits]
                if len(key_hex) != expected_key_nibbles:
                    continue
                algo = f"aes-{bits}-cbc"
                key = (algo, key_hex, iv_hex)
                if key not in found:
                    # Compute line number from byte offset
                    line = text.count("\n", 0, m.start()) + 1
                    found[key] = _AesKeyTriple(
                        algo=algo,
                        key_hex=key_hex,
                        iv_hex=iv_hex,
                        source=f"{os.path.relpath(path, extraction_dir)}:{line}",
                    )
    return list(found.values())


def _archive_ext_for(path: str) -> str | None:
    """Return the archive extension for ``path`` (longest match), or None."""
    lname = os.path.basename(path).lower()
    # Prefer the longest match (.tar.xz > .xz)
    for ext in sorted(_ARCHIVE_MAGIC.keys(), key=len, reverse=True):
        if lname.endswith(ext):
            return ext
    return None


def _file_head_matches_magic(path: str, magic: bytes) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(magic)) == magic
    except OSError:
        return False


def _decrypt_vendor_encrypted_archives(
    extraction_dir: str,
    triples: list[_AesKeyTriple],
) -> list[tuple[str, _AesKeyTriple]]:
    """Walk ``extraction_dir`` for archive files whose head bytes do NOT
    match the expected magic for their extension, and try to decrypt each
    with every candidate triple until one produces plaintext whose head
    DOES match. On success, the archive is re-extracted into
    ``<path>_extract/`` (mirroring unblob's sibling convention).

    Returns a list of (archive_path, triple_that_worked) for successes.
    Silently skips unreachable / failed decryption attempts.

    Safety:
        - Never follows symlinks.
        - Refuses to write over an existing ``<path>_extract/`` directory.
        - Requires a strict magic match on decrypted output — no byte in
          common between the ciphertext and a valid archive means a
          miss-keyed decryption cannot pass the gate by coincidence.
    """
    if not triples:
        return []
    results: list[tuple[str, _AesKeyTriple]] = []
    for root, dirs, files in os.walk(extraction_dir, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            path = os.path.join(root, name)
            if os.path.islink(path):
                continue
            ext = _archive_ext_for(path)
            if ext is None:
                continue
            magic = _ARCHIVE_MAGIC[ext]
            if _file_head_matches_magic(path, magic):
                continue  # already plaintext — not our problem
            out_dir = path + "_extract"
            if os.path.exists(out_dir):
                continue  # already handled on a prior run
            # Try each triple. First success wins.
            for triple in triples:
                try:
                    decrypted = _subprocess.run(
                        [
                            "openssl", triple.algo, "-d",
                            "-in", path,
                            "-K", triple.key_hex,
                            "-iv", triple.iv_hex,
                        ],
                        capture_output=True,
                        check=False,
                        timeout=300,
                    )
                except Exception as e:
                    logger.debug("openssl decrypt failed for %s with %s: %s", path, triple.algo, e)
                    continue
                if decrypted.returncode != 0 or not decrypted.stdout.startswith(magic):
                    continue  # magic mismatch — wrong key
                # Success — write decrypted payload to a temp file and extract.
                os.makedirs(out_dir, exist_ok=True)
                tmp_path = os.path.join(out_dir, "__decrypted_tmp")
                try:
                    with open(tmp_path, "wb") as f:
                        f.write(decrypted.stdout)
                    _extract_single_archive(tmp_path, out_dir, ext)
                    results.append((path, triple))
                    logger.info(
                        "Vendor-AES decrypt: %s → %s (key source: %s)",
                        os.path.relpath(path, extraction_dir),
                        os.path.relpath(out_dir, extraction_dir),
                        triple.source,
                    )
                except Exception as e:
                    logger.warning("Post-decrypt extraction failed for %s: %s", path, e)
                    # Leave out_dir in place for diagnostics; don't rmtree
                finally:
                    try:
                        os.unlink(tmp_path)
                    except OSError:
                        pass
                break  # success — don't try other triples
    return results


def _file_looks_like_fs_image(path: str) -> bool:
    """Return True if ``path`` appears to be a raw filesystem image.

    Probes magic bytes for FAT12/16/32, ext2/3/4, squashfs (LE+BE), UBI,
    JFFS2, and CramFS. This is how we tell a "vendor archive that wraps
    a raw partition" (e.g. Eaton Network M3: tar → ``.data_img`` FAT16)
    apart from a pure rootfs tarball.

    Kept deliberately conservative — each magic is a well-known signature
    with no credible false-positive in the firmware-archive context.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(4)
            # squashfs — LE ("hsqs") or BE ("sqsh") at offset 0
            if head in (b"hsqs", b"sqsh"):
                return True
            # UBI at offset 0
            if head == b"UBI!":
                return True
            # CramFS at offset 0 (little-endian signature)
            if head == b"\x45\x3d\xcd\x28":
                return True
            # JFFS2 at offset 0 (either endianness)
            if head[:2] in (b"\x19\x85", b"\x85\x19"):
                return True
            # FAT: "FAT12   ", "FAT16   ", or "FAT32   " at offset 54 (FAT12/16)
            # or offset 82 (FAT32). We check both since the string is
            # distinctive and cannot appear in a plain tar/zip.
            for offset in (54, 82):
                f.seek(offset)
                fs_type = f.read(8)
                if fs_type.startswith((b"FAT12", b"FAT16", b"FAT32")):
                    return True
            # ext2/3/4 superblock magic at offset 0x438
            f.seek(0x438)
            ext_magic = f.read(2)
            if ext_magic == b"\x53\xef":
                return True
    except OSError:
        return False
    return False


def _dir_has_filesystem_image(path: str) -> bool:
    """Return True if ``path`` contains at least one raw filesystem image
    at its top level (non-recursive, non-symlink).

    Used as a gate on ``find_filesystem_root``'s "best-entry-count"
    fallback: if a candidate directory has a raw FS image at top level
    but no Linux markers, the archive is "vendor-wrap-of-image" shape
    and should be re-run through unblob, not treated as a rootfs.
    """
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        continue
                except OSError:
                    continue
                if _file_looks_like_fs_image(entry.path):
                    return True
    except OSError:
        return False
    return False


def _has_linux_markers(path: str) -> bool:
    """Check if a directory has the standard Linux or Android filesystem markers."""
    try:
        all_entries = set(os.listdir(path))
    except OSError:
        return False
    has_etc = "etc" in all_entries or "etc_ro" in all_entries
    has_usr_or_bin = "usr" in all_entries or "bin" in all_entries
    if has_etc and has_usr_or_bin:
        return True
    if "system" in all_entries:
        system_path = os.path.join(path, "system")
        if os.path.isdir(system_path):
            try:
                system_entries = set(os.listdir(system_path))
            except OSError:
                system_entries = set()
            if "build.prop" in system_entries:
                return True
        if "vendor" in all_entries or "product" in all_entries:
            return True
    return False


def _etc_entry_count(path: str) -> int:
    """Count entries in the etc/ (or etc_ro/) directory as a quality signal."""
    for name in ("etc", "etc_ro"):
        etc_path = os.path.join(path, name)
        if os.path.isdir(etc_path):
            try:
                return len(os.listdir(etc_path))
            except OSError:
                pass
        if os.path.islink(etc_path):
            target = os.readlink(etc_path)
            if target.startswith("/"):
                relative_target = os.path.join(path, target.lstrip("/"))
                if os.path.isdir(relative_target):
                    try:
                        return len(os.listdir(relative_target))
                    except OSError:
                        pass
    return 0


def find_filesystem_root(extraction_dir: str) -> str | None:
    """Find the extracted filesystem root by looking for Linux directory markers."""
    candidates: list[tuple[str, int, int, int]] = []

    for root, dirs, _files in os.walk(extraction_dir):
        if not _has_linux_markers(root):
            continue

        dirname = os.path.basename(root)
        priority = 10 if dirname in _FS_ROOT_NAMES else 0
        try:
            entries = set(os.listdir(root))
        except OSError:
            entries = set()
        if "init" in entries and "system" in entries and ("bin" in entries or "apex" in entries):
            priority = 20
        etc_count = _etc_entry_count(root)
        try:
            total_entries = len(os.listdir(root))
        except OSError:
            total_entries = 0
        candidates.append((root, priority, etc_count, total_entries))

    if candidates:
        candidates.sort(key=lambda c: (c[1], c[2], c[3]), reverse=True)
        return candidates[0][0]

    best_dir = None
    best_count = 0
    for root, dirs, files in os.walk(extraction_dir):
        count = len(dirs) + len(files)
        if count > best_count:
            best_count = count
            best_dir = root

    # Reject the "most entries" fallback when the candidate is actually a
    # vendor archive that wraps a raw filesystem image (e.g. Eaton Network
    # M3: tar → {EULA, manifest.json, .data_img(FAT16)}). Returning the
    # container as fs_root would short-circuit unblob and leave the image
    # un-extracted. Returning None instead forces the caller to fall
    # through to the recursive extractor chain, which can handle the
    # nested filesystem format.
    if best_dir and _dir_has_filesystem_image(best_dir):
        return None

    return best_dir


def _find_binwalk_output_dir(
    fs_root_real: str, extraction_dir_real: str
) -> str | None:
    """Walk up from the rootfs to find the binwalk output directory."""
    current = os.path.dirname(fs_root_real)
    rootfs_basename = os.path.basename(fs_root_real)
    best = None

    while current.startswith(extraction_dir_real):
        try:
            entries = os.listdir(current)
        except OSError:
            if current == extraction_dir_real:
                break
            current = os.path.dirname(current)
            continue

        has_other_root = False
        has_large_file = False
        for name in entries:
            if name == rootfs_basename:
                continue
            full = os.path.join(current, name)
            if os.path.isdir(full):
                if _ROOT_DIR_RE.match(name):
                    has_other_root = True
                    break
                try:
                    for child in os.listdir(full):
                        child_full = os.path.join(full, child)
                        if os.path.isdir(child_full) and _ROOT_DIR_RE.match(child):
                            if os.path.realpath(child_full) != fs_root_real:
                                has_other_root = True
                                break
                except OSError:
                    pass
                if has_other_root:
                    break
            elif os.path.isfile(full):
                try:
                    if os.path.getsize(full) >= 100_000:
                        has_large_file = True
                except OSError:
                    pass

        if has_other_root or has_large_file:
            best = current
            break

        if current == extraction_dir_real:
            break
        current = os.path.dirname(current)

    return best


def classify_firmware(firmware_path: str) -> str:
    """Classify firmware file type to determine the analysis pipeline."""
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
                # MediaTek scatter format: zip with *_scatter.txt + super.img
                # (files may be nested under a subdirectory)
                has_scatter = any(
                    n.endswith("_scatter.txt") or n.endswith("_Android_scatter.txt")
                    for n in names
                )
                has_super = any(n.endswith("/super.img") or n == "super.img" for n in names)
                if has_scatter and has_super:
                    return "android_scatter"
                # Standalone APK: ZIP containing AndroidManifest.xml + classes*.dex
                has_manifest = "AndroidManifest.xml" in names
                has_dex = any(n.endswith(".dex") for n in names)
                if has_manifest and has_dex:
                    return "android_apk"
                # Check for UEFI capsule inside ZIP (e.g., Framework BIOS updates)
                uefi_zip_markers = {".cap", ".rom", ".fd", ".bin"}
                for name in names:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in uefi_zip_markers:
                        # Extract and check if inner file is UEFI
                        try:
                            inner = zf.read(name)
                            if _is_uefi_content(inner):
                                return "uefi_firmware"
                        except Exception:
                            pass
        except Exception:
            pass

    magic = _read_magic(firmware_path, 16)

    # Android sparse image
    if magic[:4] == b"\x3a\xff\x26\xed":
        return "android_sparse"

    # Android boot image
    if magic[:8] == b"ANDROID!":
        return "android_boot"

    # UEFI/BIOS firmware detection (before tar/ELF checks)
    if _is_uefi_firmware(firmware_path, magic):
        return "uefi_firmware"

    if _is_partition_dump_tar(firmware_path):
        return "partition_dump_tar"

    if _is_rootfs_tar(firmware_path):
        return "linux_rootfs_tar"

    if magic[:4] == b"\x7fELF":
        # Check if this ELF is an RTOS binary before falling back to generic elf_binary
        try:
            from app.services.rtos_detection_service import detect_rtos
            rtos = detect_rtos(firmware_path)
            if rtos:
                rtos_name = rtos["rtos_name"]
                return f"{rtos_name}_elf"
        except Exception:
            pass
        return "elf_binary"

    if magic[:1] == b":" and all(c in b"0123456789ABCDEFabcdef:\r\n" for c in magic):
        # Validate more thoroughly: read first line and check record structure
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

    # Check for RTOS in raw binaries (non-ELF) via magic bytes and strings
    try:
        from app.services.rtos_detection_service import detect_rtos
        rtos = detect_rtos(firmware_path)
        if rtos:
            return "rtos_blob"
    except Exception:
        pass

    return "linux_blob"


# EFI capsule GUID: BD86663B-08ED-4816-8FF0-D29BF6426720
_EFI_CAPSULE_GUID = b"\x3b\x66\x86\xbd\xed\x08\x16\x48\x8f\xf0\xd2\x9b\xf6\x42\x67\x20"
# Intel Flash Descriptor signature at offset 0x10
_IFD_SIGNATURE = b"\x5a\xa5\xf0\x0f"
# UEFI Firmware Volume magic: _FVH
_FVH_MAGIC = b"_FVH"
# AMI Aptio capsule marker
_AMI_CAPSULE = b"\xB5\x25\x67\x8D"


def _is_uefi_content(data: bytes) -> bool:
    """Check if raw bytes contain UEFI firmware signatures."""
    if len(data) < 32:
        return False
    # EFI capsule GUID at offset 0
    if data[:16] == _EFI_CAPSULE_GUID:
        return True
    # Intel Flash Descriptor at offset 0x10
    if len(data) > 0x14 and data[0x10:0x14] == _IFD_SIGNATURE:
        return True
    # Search first 4KB for _FVH (firmware volume header)
    search_region = data[:4096]
    if _FVH_MAGIC in search_region:
        return True
    return False


def _is_uefi_firmware(firmware_path: str, magic: bytes) -> bool:
    """Detect UEFI/BIOS firmware by magic bytes and structure."""
    # EFI capsule GUID at offset 0
    if len(magic) >= 16 and magic[:16] == _EFI_CAPSULE_GUID:
        return True
    # Intel Flash Descriptor at offset 0x10
    try:
        with open(firmware_path, "rb") as f:
            f.seek(0x10)
            ifd = f.read(4)
            if ifd == _IFD_SIGNATURE:
                return True
            # Search first 64KB for firmware volume header (_FVH)
            f.seek(0)
            head = f.read(65536)
            if _FVH_MAGIC in head:
                return True
    except OSError:
        pass
    # Check file extension as weak signal combined with size
    ext = os.path.splitext(firmware_path)[1].lower()
    if ext in (".rom", ".cap", ".fd", ".upd"):
        try:
            size = os.path.getsize(firmware_path)
            # UEFI firmware is typically 4MB-32MB
            if 2 * 1024 * 1024 <= size <= 64 * 1024 * 1024:
                return True
        except OSError:
            pass
    return False


def _is_partition_dump_tar(firmware_path: str) -> bool:
    """Check if the file is a tar of raw partition images (EDL/MTKClient dump).

    Qualcomm EDL dumps contain partitions like aboot.img, rpm.img, tz.img.
    MTKClient dumps contain partitions like boot.img, recovery.img, super.img, lk.img.
    Device bridge dumps also match this pattern.
    """
    import tarfile as _tarfile

    try:
        if not _tarfile.is_tarfile(firmware_path):
            return False
    except Exception:
        return False

    # Partition names that indicate a raw dump (not a rootfs)
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
            # At least 3 .img files with 2+ matching known partition names
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


def convert_intel_hex_to_binary(hex_path: str, output_path: str) -> dict:
    """Convert Intel HEX (.hex / .ihex) file to raw binary.

    Parses all standard record types (00-05), resolves extended addresses,
    and writes the binary image to *output_path*.  Gaps smaller than 4 KB
    are padded with 0xFF; larger gaps cause a region break.

    Returns metadata dict::

        {
            "base_address": int,     # lowest address in the file
            "entry_point": int|None, # from type 05 (start linear address) record
            "size": int,             # bytes written
            "regions": [{"start": int, "size": int}, ...],
        }
    """
    _GAP_PAD_LIMIT = 4096  # pad gaps up to 4 KB; split beyond that

    extended_addr = 0  # upper 16 bits from type 02/04 records
    entry_point: int | None = None
    # Collect (full_address, data_bytes) tuples
    data_records: list[tuple[int, bytes]] = []

    with open(hex_path, errors="replace") as fh:
        for line_no, raw_line in enumerate(fh, 1):
            line = raw_line.strip()
            if not line:
                continue
            if not line.startswith(":"):
                continue  # skip non-record lines (comments, blank)

            # Minimum valid record: `:LLAAAATT[DD...]CC` = 11 chars (0 data bytes)
            if len(line) < 11:
                continue

            try:
                payload = bytes.fromhex(line[1:])
            except ValueError:
                continue  # malformed hex digits — skip

            if len(payload) < 4:
                continue

            byte_count = payload[0]
            address = (payload[1] << 8) | payload[2]
            record_type = payload[3]
            data = payload[4: 4 + byte_count]

            # Validate checksum (two's complement of sum of all bytes)
            if (sum(payload) & 0xFF) != 0:
                continue  # bad checksum — skip silently

            if record_type == 0x00:
                # Data record
                full_addr = extended_addr + address
                data_records.append((full_addr, data))

            elif record_type == 0x01:
                # EOF
                break

            elif record_type == 0x02:
                # Extended Segment Address — shifts base by (value * 16)
                if len(data) >= 2:
                    extended_addr = ((data[0] << 8) | data[1]) << 4

            elif record_type == 0x03:
                # Start Segment Address (CS:IP) — less common; store as entry
                if len(data) >= 4 and entry_point is None:
                    cs = (data[0] << 8) | data[1]
                    ip = (data[2] << 8) | data[3]
                    entry_point = (cs << 4) + ip

            elif record_type == 0x04:
                # Extended Linear Address — upper 16 bits of 32-bit address
                if len(data) >= 2:
                    extended_addr = ((data[0] << 8) | data[1]) << 16

            elif record_type == 0x05:
                # Start Linear Address — 32-bit entry point
                if len(data) >= 4:
                    entry_point = (
                        (data[0] << 24) | (data[1] << 16) |
                        (data[2] << 8) | data[3]
                    )

    if not data_records:
        # Empty / no data records — write an empty file and return
        with open(output_path, "wb") as out:
            pass
        return {
            "base_address": 0,
            "entry_point": entry_point,
            "size": 0,
            "regions": [],
        }

    # Sort by address
    data_records.sort(key=lambda r: r[0])

    # Build contiguous regions from sorted data records, padding small gaps
    def _build_regions(
        records: list[tuple[int, bytes]],
    ) -> list[tuple[int, bytearray]]:
        """Return list of (start_addr, bytearray) region tuples."""
        regions: list[tuple[int, bytearray]] = []
        buf = bytearray()
        region_start = records[0][0]
        cursor = region_start

        for addr, data in records:
            gap = addr - cursor
            if gap < 0:
                # Overlapping data — trim overlap
                overlap = -gap
                if overlap < len(data):
                    data = data[overlap:]
                    addr += overlap
                    gap = 0
                else:
                    continue  # fully overlapping, skip
            if gap <= _GAP_PAD_LIMIT:
                buf.extend(b"\xff" * gap)
                buf.extend(data)
                cursor = addr + len(data)
            else:
                # Large gap — close current region, start new one
                if buf:
                    regions.append((region_start, buf))
                region_start = addr
                buf = bytearray(data)
                cursor = addr + len(data)

        if buf:
            regions.append((region_start, buf))
        return regions

    region_bufs = _build_regions(data_records)

    # Build metadata regions list
    regions_meta = [
        {"start": start, "size": len(buf)} for start, buf in region_bufs
    ]

    # Pick the largest region for the output binary
    largest_start, largest_buf = max(region_bufs, key=lambda rb: len(rb[1]))
    write_data = bytes(largest_buf)

    with open(output_path, "wb") as out:
        out.write(write_data)

    return {
        "base_address": largest_start,
        "entry_point": entry_point,
        "size": len(write_data),
        "regions": regions_meta,
    }
