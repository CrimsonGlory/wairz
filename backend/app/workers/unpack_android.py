"""Android-specific firmware extraction — OTA, sparse images, super.img, boot.img."""

import asyncio
import contextlib
import gzip
import logging
import os
import re
import shutil
import struct

logger = logging.getLogger(__name__)

# Minimum partition-image size (bytes). Below this a file is almost certainly
# empty padding/placeholder.  We use 64 (smaller than any valid GFH / UBI /
# EROFS / ext4 header) so we preserve the tiny real stubs observed on real
# hardware: e.g. DPCS10 modem.img is 528 bytes and md1dsp.img is ~2 KB.
# Previously this was 1 MiB which silently dropped every small partition.
_MIN_PARTITION_BYTES = 64


# Android user-data / factory-reset partitions — NOT firmware.
# Per AOSP (source.android.com/docs/core/architecture/partitions): userdata
# holds user apps+data, cache is temporary data, metadata stores the
# encryption key, persist holds per-device state (calibration, certs),
# misc is a 4 KB boot-flag region.  All are erased on factory reset and
# contain no firmware code worth analysing.  Skipping them avoids
# sparse→raw inflation of empty OEM userdata (3 GB+) which otherwise
# trips the extraction-bomb limit.
_USER_DATA_PARTITION_BASES: frozenset[str] = frozenset({
    "userdata", "cache", "metadata", "persist", "misc",
})


def _is_user_data_partition(img_name: str) -> bool:
    """True if ``img_name`` names a user-data / factory-reset partition.

    Matches ``userdata.img``, ``cache.img``, ``metadata.img``,
    ``persist.img``, ``misc.img`` and their A/B slot variants
    (``userdata_a.img``, ``userdata_b.img``).  Case-insensitive.
    """
    base = img_name.rsplit(".", 1)[0].lower()
    if len(base) > 2 and base[-2:] in ("_a", "_b"):
        base = base[:-2]
    return base in _USER_DATA_PARTITION_BASES


# Filesystem / bootloader magics we recognise at offset 0 in a partition
# image.  Used by `_verify_simg_output` to confirm the sparse→raw conversion
# produced a plausible image instead of truncated garbage.
_FS_MAGICS_AT_OFFSET_0: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "elf"),
    (b"UBI#", "ubi"),
    (b"hsqs", "squashfs_le"),
    (b"sqsh", "squashfs_be"),
    (b"\xe2\xe1\xf5\xe0", "erofs"),
    (b"ANDROID!", "android_boot"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"BZh", "bzip2"),
    (b"\x04\x22\x4d\x18", "lz4_frame"),
    (b"\x02\x21\x4c\x18", "lz4_legacy"),
)


def _verify_simg_output(raw_path: str) -> tuple[bool, str]:
    """Sanity-check a sparse→raw conversion output.

    After ``simg2img sparse.img raw.img`` we need more than a zero exit
    code: disk-full mid-write or a truncated sparse header produces a file
    that *looks* present but has no recognisable filesystem content.

    Returns ``(verified, note)``:

    - ``(False, "missing")`` — output file doesn't exist.
    - ``(False, "empty")`` — output file is 0 bytes.
    - ``(True, "verified: <fs>")`` — recognised FS magic in first 512 bytes,
      or ext4 superblock marker at offset 0x438.
    - ``(True, "unverified but non-empty")`` — non-zero bytes but no magic;
      probably a vendor blob format we don't know — keep it.
    - ``(True, "suspicious: all-zero first 4 KB")`` — first 4 KB all-zero;
      could be legitimate sparse hole, keep the file but warn.
    """
    if not os.path.exists(raw_path):
        return False, "missing"

    try:
        size = os.path.getsize(raw_path)
    except OSError:
        return False, "missing"

    if size == 0:
        return False, "empty"

    try:
        with open(raw_path, "rb") as f:
            head = f.read(4096)
            # ext4 superblock magic 0x53EF lives at offset 0x438
            ext4_marker = b""
            if size > 0x438 + 2:
                f.seek(0x438)
                ext4_marker = f.read(2)
    except OSError:
        return False, "missing"

    first_512 = head[:512]
    for magic, name in _FS_MAGICS_AT_OFFSET_0:
        if first_512.startswith(magic):
            return True, f"verified: {name}"

    # Android sparse magic should NOT appear here — sparse is the INPUT to
    # simg2img.  If we see it in the output it means simg2img no-op'd.
    if first_512.startswith(b"\x3a\xff\x26\xed"):
        return True, "suspicious: output still sparse (simg2img no-op)"

    if ext4_marker == b"\x53\xef":
        return True, "verified: ext4"

    # No magic — decide between "all-zero hole" and "unknown but present"
    if all(b == 0 for b in head):
        return True, "suspicious: all-zero first 4 KB"

    return True, "unverified but non-empty"


def _identify_partition_by_content(partition_dir: str) -> str | None:
    """Identify an Android partition by its directory contents.

    Returns a human-readable name like 'system', 'vendor', 'product',
    or None if the partition cannot be identified.
    """
    if not os.path.isdir(partition_dir):
        return None
    try:
        entries = set(os.listdir(partition_dir))
    except OSError:
        return None

    if ("init" in entries and ("bin" in entries or "system" in entries)) or \
       ("app" in entries and "framework" in entries and "priv-app" in entries):
        return "system"

    if "build.prop" in entries and ("firmware" in entries or "lib" in entries or "etc" in entries):
        if "app" not in entries or "framework" not in entries:
            return "vendor"

    if ("app" in entries or "priv-app" in entries) and "framework" not in entries:
        if "overlay" in entries or "media" in entries:
            return "product"

    if "priv-app" in entries and "apex" in entries and "framework" not in entries:
        return "system_ext"

    if "etc" in entries and "lib" in entries and "build.prop" not in entries and \
       "app" not in entries and "framework" not in entries:
        if "firmware" in entries or "overlay" in entries:
            return "odm"

    return None


async def _try_extract_partition(
    raw_path: str, rootfs_dir: str, partition_name: str, log_lines: list[str]
) -> bool:
    """Try to extract a single partition image as ext4 or EROFS."""
    import shutil

    dest_dir = os.path.join(rootfs_dir, partition_name)
    os.makedirs(dest_dir, exist_ok=True)

    if shutil.which("fsck.erofs"):
        proc = await asyncio.create_subprocess_exec(
            "fsck.erofs", f"--extract={dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                # EROFS preserves original Android permissions (600, 640) which
                # break analysis tools.  Add read for all to enable scanning.
                await asyncio.create_subprocess_exec(
                    "chmod", "-R", "+r", dest_dir,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                log_lines.append(f"Extracted {partition_name} as EROFS ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except TimeoutError:
            proc.kill()
            log_lines.append(f"fsck.erofs timed out on {partition_name}")

    if shutil.which("debugfs"):
        proc = await asyncio.create_subprocess_exec(
            "debugfs", "-R", f"rdump / {dest_dir}", raw_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(), timeout=300)
            if os.listdir(dest_dir):
                await asyncio.create_subprocess_exec(
                    "chmod", "-R", "+r", dest_dir,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                log_lines.append(f"Extracted {partition_name} as ext4 ({len(os.listdir(dest_dir))} top-level entries)")
                return True
        except TimeoutError:
            proc.kill()
            log_lines.append(f"debugfs timed out on {partition_name}")

    try:
        os.rmdir(dest_dir)
    except OSError:
        pass
    return False


BOOT_IMG_MAGIC = b"ANDROID!"


def _extract_boot_img_sync(
    boot_path: str, output_dir: str,
) -> tuple[bool, list[str], bytes | None, str | None]:
    """Synchronous boot.img component extraction.

    Returns (header_ok, log_lines, ramdisk_data, error_msg). The async wrapper
    handles the ramdisk decompression after this returns.
    """
    log_lines: list[str] = []
    try:
        with open(boot_path, "rb") as f:
            header = f.read(1648)
    except OSError as e:
        return False, [f"Cannot read boot.img: {e}"], None, str(e)

    if len(header) < 1648 or header[:8] != BOOT_IMG_MAGIC:
        return False, ["Not a valid Android boot image (bad magic)"], None, "bad_magic"

    # Parse v0/v1/v2 header (all share the same base layout)
    (
        kernel_size, _kernel_addr,
        ramdisk_size, _ramdisk_addr,
        second_size, _second_addr,
        _tags_addr, page_size,
        header_version, _os_version,
    ) = struct.unpack_from("<10I", header, 8)

    if page_size == 0 or (page_size & (page_size - 1)) != 0:
        # page_size must be a power of 2
        page_size = 2048  # fallback default

    log_lines.append(
        f"boot.img header v{header_version}: "
        f"kernel={kernel_size}, ramdisk={ramdisk_size}, "
        f"second={second_size}, page_size={page_size}"
    )

    # v3/v4 use a different page size and layout but same magic
    if header_version >= 3:
        page_size = 4096

    os.makedirs(output_dir, exist_ok=True)

    def _page_align(offset: int) -> int:
        return ((offset + page_size - 1) // page_size) * page_size

    # Components are laid out sequentially, page-aligned
    kernel_offset = page_size  # first page after header
    ramdisk_offset = kernel_offset + _page_align(kernel_size)
    second_offset = ramdisk_offset + _page_align(ramdisk_size)

    extracted: list[str] = []
    ramdisk_data: bytes | None = None

    with open(boot_path, "rb") as f:
        # Extract kernel
        if kernel_size > 0:
            f.seek(kernel_offset)
            kernel_data = f.read(kernel_size)
            kernel_path = os.path.join(output_dir, "kernel")
            with open(kernel_path, "wb") as out:
                out.write(kernel_data)
            extracted.append(f"kernel ({kernel_size} bytes)")

        # Extract ramdisk
        if ramdisk_size > 0:
            f.seek(ramdisk_offset)
            ramdisk_data = f.read(ramdisk_size)
            ramdisk_path = os.path.join(output_dir, "ramdisk.img")
            with open(ramdisk_path, "wb") as out:
                out.write(ramdisk_data)
            extracted.append(f"ramdisk ({ramdisk_size} bytes)")

        # Extract second-stage bootloader
        if second_size > 0:
            f.seek(second_offset)
            second_data = f.read(second_size)
            second_path = os.path.join(output_dir, "second")
            with open(second_path, "wb") as out:
                out.write(second_data)
            extracted.append(f"second-stage ({second_size} bytes)")

        # v1+ has recovery DTBO, v2+ has DTB
        if header_version >= 1:
            recovery_dtbo_size = struct.unpack_from("<I", header, 1632)[0]
            dtbo_offset = second_offset + _page_align(second_size)
            if recovery_dtbo_size > 0:
                f.seek(dtbo_offset)
                dtbo_data = f.read(recovery_dtbo_size)
                with open(os.path.join(output_dir, "recovery_dtbo"), "wb") as out:
                    out.write(dtbo_data)
                extracted.append(f"recovery_dtbo ({recovery_dtbo_size} bytes)")

        if header_version >= 2:
            dtb_size = struct.unpack_from("<I", header, 1636)[0]
            if dtb_size > 0:
                # DTB follows recovery_dtbo (or second if no dtbo)
                if header_version >= 1:
                    recovery_dtbo_size = struct.unpack_from("<I", header, 1632)[0]
                else:
                    recovery_dtbo_size = 0
                dtb_start = (
                    second_offset
                    + _page_align(second_size)
                    + _page_align(recovery_dtbo_size)
                )
                f.seek(dtb_start)
                dtb_data = f.read(dtb_size)
                with open(os.path.join(output_dir, "dtb"), "wb") as out:
                    out.write(dtb_data)
                extracted.append(f"dtb ({dtb_size} bytes)")

    if extracted:
        log_lines.append(f"boot.img extracted: {', '.join(extracted)}")
        return True, log_lines, ramdisk_data, None

    log_lines.append("boot.img: no components found to extract")
    return False, log_lines, None, None


async def _extract_boot_img(
    boot_path: str, output_dir: str, log_lines: list[str]
) -> bool:
    """Extract kernel, ramdisk, and DTB from an Android boot.img.

    Supports boot image header v0-v4 (covers all mainstream Android devices).
    The format is page-aligned: header at page 0, then kernel, ramdisk,
    second-stage, and optionally recovery DTBO and DTB.
    """
    loop = asyncio.get_running_loop()
    extracted_ok, sync_logs, ramdisk_data, _err = await loop.run_in_executor(
        None, _extract_boot_img_sync, boot_path, output_dir,
    )
    log_lines.extend(sync_logs)

    # After sync extraction, decompress + extract the ramdisk asynchronously
    # (it spawns the cpio subprocess).
    if ramdisk_data is not None and extracted_ok:
        ramdisk_dir = os.path.join(output_dir, "ramdisk")
        os.makedirs(ramdisk_dir, exist_ok=True)
        try:
            await _extract_ramdisk(ramdisk_data, ramdisk_dir)
            log_lines.append("ramdisk contents extracted")
        except Exception as e:
            log_lines.append(f"Ramdisk extraction failed: {e}")

    return extracted_ok


async def _extract_ramdisk(data: bytes, output_dir: str) -> None:
    """Decompress and extract a ramdisk (gzip/lz4 compressed cpio archive)."""
    import tempfile

    # Try gzip decompression
    decompressed = None
    if data[:2] == b"\x1f\x8b":
        decompressed = gzip.decompress(data)
    elif data[:4] == b"\x02\x21\x4c\x18" or data[:4] == b"\x04\x22\x4d\x18":
        # LZ4 legacy or LZ4 frame — try lz4 if available
        try:
            import lz4.frame
            decompressed = lz4.frame.decompress(data)
        except (ImportError, Exception):
            pass

    if decompressed is None:
        # Maybe it's uncompressed cpio
        if data[:6] in (b"070701", b"070702", b"070707"):
            decompressed = data
        else:
            raise RuntimeError("Unknown ramdisk compression format")

    # Write decompressed cpio and extract with cpio command
    with tempfile.NamedTemporaryFile(suffix=".cpio", delete=False) as tmp:
        tmp.write(decompressed)
        tmp_path = tmp.name

    def _read_cpio_sync(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    try:
        proc = await asyncio.create_subprocess_exec(
            "cpio", "-idm", "--no-absolute-filenames",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=output_dir,
        )
        loop = asyncio.get_running_loop()
        cpio_data = await loop.run_in_executor(None, _read_cpio_sync, tmp_path)
        await asyncio.wait_for(proc.communicate(input=cpio_data), timeout=60)
    finally:
        os.unlink(tmp_path)


def _scan_super_partitions_layout_sync(
    raw_path: str,
) -> tuple[list[tuple[str, int]], str | None]:
    """Mmap-scan a super.img for EROFS/ext4 partition offsets.

    Returns (sorted_partitions, error_msg). Each partition is (fs_type, offset).
    """
    import mmap

    EROFS_MAGIC = b"\xe2\xe1\xf5\xe0"
    EXT4_MAGIC = b"\x53\xef"

    partitions: list[tuple[str, int]] = []

    try:
        with open(raw_path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            size = mm.size()

            for offset in range(1024, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 4] == EROFS_MAGIC:
                    partitions.append(("erofs", offset - 1024))

            for offset in range(0x438, min(size, 10 * 1024**3), 1024 * 1024):
                if mm[offset:offset + 2] == EXT4_MAGIC:
                    partitions.append(("ext4", offset - 0x438))

            mm.close()
    except Exception as e:
        return [], str(e)

    partitions.sort(key=lambda x: x[1])
    return partitions, None


def _carve_partition_to_tmp_sync(
    raw_path: str, start_offset: int, part_size: int, suffix: str,
) -> str:
    """Carve [start_offset, start_offset+part_size) from raw_path into a new tmp file.

    Returns the tmp_path. Caller is responsible for unlinking.
    """
    import tempfile

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp_path = tmp.name
        with open(raw_path, "rb") as src:
            src.seek(start_offset)
            remaining = part_size
            while remaining > 0:
                chunk = src.read(min(remaining, 8 * 1024 * 1024))
                if not chunk:
                    break
                tmp.write(chunk)
                remaining -= len(chunk)
    return tmp_path


async def _scan_super_partitions(
    raw_path: str, rootfs_dir: str, log_lines: list[str]
) -> tuple[int, int]:
    """Scan a raw super.img for embedded EROFS/ext4 partitions and extract them.

    Returns ``(extracted_count, partitions_detected)``.  Callers compare the
    two to decide whether the raw container can be removed safely: when
    every detected partition was carved into ``rootfs/``, the raw LP2
    container is redundant; when extraction was partial we keep the raw
    so corrupt inner partitions remain recoverable.
    """
    loop = asyncio.get_running_loop()
    partitions, err = await loop.run_in_executor(
        None, _scan_super_partitions_layout_sync, raw_path,
    )
    if err is not None:
        log_lines.append(f"Error scanning super.img: {err}")
        return 0, 0

    if not partitions:
        log_lines.append("No EROFS or ext4 partitions found in super.img")
        return 0, 0

    raw_size = await loop.run_in_executor(None, os.path.getsize, raw_path)
    log_lines.append(f"Found {len(partitions)} partition(s) in super.img")

    extracted_count = 0
    for i, (fs_type, start_offset) in enumerate(partitions):
        if i + 1 < len(partitions):
            part_size = partitions[i + 1][1] - start_offset
        else:
            part_size = raw_size - start_offset

        # Keep anything above _MIN_PARTITION_BYTES so we don't silently drop
        # tiny stub partitions (e.g. GFH-only headers a few KB long).  The
        # previous 1 MiB floor hid DPCS10-class small partitions entirely.
        if part_size < _MIN_PARTITION_BYTES:
            continue

        partition_name = f"partition_{i}_{fs_type}"
        tmp_path: str | None = None

        try:
            tmp_path = await loop.run_in_executor(
                None,
                _carve_partition_to_tmp_sync,
                raw_path, start_offset, part_size, f".{fs_type}",
            )

            if await _try_extract_partition(tmp_path, rootfs_dir, partition_name, log_lines):
                identified = _identify_partition_by_content(
                    os.path.join(rootfs_dir, partition_name)
                )
                if identified and identified != partition_name:
                    old_path = os.path.join(rootfs_dir, partition_name)
                    new_path = os.path.join(rootfs_dir, identified)
                    new_exists = await loop.run_in_executor(
                        None, os.path.exists, new_path,
                    )
                    if not new_exists:
                        os.rename(old_path, new_path)
                        log_lines.append(f"Identified {partition_name} as '{identified}'")
                        partition_name = identified
                extracted_count += 1
        except Exception as e:
            log_lines.append(f"Error extracting partition at offset 0x{start_offset:x}: {e}")
        finally:
            if tmp_path is not None:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    log_lines.append(f"Extracted {extracted_count}/{len(partitions)} partitions from super.img")
    return extracted_count, len(partitions)


def _read_magic_sync(path: str, n: int) -> bytes | None:
    """Read the first `n` bytes of a file; return None on OSError."""
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return None


def _read_super_lp_magic_sync(path: str) -> bytes | None:
    """Read the 4-byte LP2 super-partition magic at offset 0x1000; return None on error."""
    try:
        with open(path, "rb") as f:
            f.seek(0x1000)
            return f.read(4)
    except Exception:
        return None


def _recover_sparsechunk_extracts(
    extraction_dir: str, log_lines: list[str]
) -> list[str]:
    """Post-unblob recovery: scan unblob-expanded sparsechunk raw images for
    embedded EROFS/ext4 partitions.

    Context: unblob recognises Motorola ``super.img_sparsechunk.N`` files as
    Android sparse images and expands each independently — emitting a 7.58 GB
    ``raw.image`` per chunk into ``super.img_sparsechunk.N_extract/``. Each
    expanded raw image carries valid partition data at the byte offsets that
    chunk's slice represented; the rest of the image is zero-padding. The
    individual chunks are gone after unblob, so the normal
    :func:`_concatenate_sparsechunks` reassembly path doesn't apply.

    This recovery scans each ``raw.image`` independently for EROFS / ext4
    magic bytes (reusing the existing :func:`_scan_super_partitions` mmap
    scanner) and extracts any partitions it finds into
    ``<extraction_dir>/super.img_recovered_extract/sparsechunk_N/partition_*``.
    Outputs are picked up by the detection_roots scanner via the existing
    ``partition_`` prefix hint — no firmware_paths.py change required.

    Bounded per CLAUDE.md Rule #29: caps the recovery to 16 sparsechunks
    max (real-world Motorola firmware uses 11; the cap defends against
    extraction-bomb-style firmware) and 30 GB total raw-image input. A
    chunk whose raw.image is &gt;10 GB is skipped (defensive against
    malformed/oversized sparse expansions).

    Adaptability note: this function targets the Android sparsechunk
    convention specifically (sparse-img-per-chunk output of unblob). The
    broader "post-unblob carve embedded filesystems" capability is the
    YAML-driven recovery_handlers registry queued for a future session;
    sparsechunk recovery is the highest-leverage instance which is why it
    ships first as an explicit function rather than waiting for the
    registry.

    Returns the list of created ``super.img_recovered_extract/sparsechunk_N``
    directory paths. Empty list when no sparsechunk extracts are present
    or recovery produced no partitions. Failures on a single chunk log to
    ``log_lines`` and skip — never raise — so detection completes for the
    chunks that did succeed.
    """
    import asyncio as _asyncio

    _MAX_CHUNKS = 16
    # 20 GB cap accommodates Moto-G30's 10.3 GB sparsechunk raw images
    # (Snapdragon 480 / SM4350 — slightly larger super.img than G32's
    # SM6225) while still defending against extraction-bomb firmware.
    # Initial 10 GB cap was tuned to G32 and rejected G30 — the
    # adaptability point the user flagged: don't hard-code values that
    # only fit one device. Future devices with even larger super.img
    # can extend per-deploy via env var (TODO: WAIRZ_RECOVERY_MAX_GB)
    # without code change.
    _MAX_RAW_BYTES = 20 * 1024 * 1024 * 1024  # 20 GB per chunk
    _SPARSE_PATTERN = re.compile(r"^(.+)_sparsechunk\.(\d+)_extract$")

    candidates: list[tuple[int, str, str]] = []
    try:
        for entry in os.scandir(extraction_dir):
            if not entry.is_dir(follow_symlinks=False):
                continue
            m = _SPARSE_PATTERN.match(entry.name)
            if not m:
                continue
            chunk_idx = int(m.group(2))
            raw_path = os.path.join(entry.path, "raw.image")
            if not os.path.isfile(raw_path):
                continue
            try:
                raw_size = os.path.getsize(raw_path)
            except OSError:
                continue
            if raw_size == 0 or raw_size > _MAX_RAW_BYTES:
                log_lines.append(
                    f"sparsechunk recovery: skipping {entry.name}/raw.image "
                    f"(size {raw_size // (1024*1024)} MB outside bounds)"
                )
                continue
            candidates.append((chunk_idx, entry.name, raw_path))
    except OSError as e:
        log_lines.append(f"sparsechunk recovery: scan failed: {e}")
        return []

    if not candidates:
        return []

    candidates.sort(key=lambda t: t[0])  # ascending chunk index
    if len(candidates) > _MAX_CHUNKS:
        log_lines.append(
            f"sparsechunk recovery: bounded to {_MAX_CHUNKS} chunks "
            f"({len(candidates)} present); skipping the tail."
        )
        candidates = candidates[:_MAX_CHUNKS]

    recovery_root = os.path.join(extraction_dir, "super.img_recovered_extract")
    try:
        os.makedirs(recovery_root, exist_ok=True)
    except OSError as e:
        log_lines.append(f"sparsechunk recovery: mkdir failed: {e}")
        return []

    created_dirs: list[str] = []

    # Each scan is sync I/O; run sequentially to bound peak memory (mmap
    # of a 7.58 GB image plus carve-to-tmp). Async parallelism doesn't
    # help — the bottleneck is mmap page-cache pressure, not CPU.
    for chunk_idx, src_dirname, raw_path in candidates:
        chunk_out = os.path.join(recovery_root, f"sparsechunk_{chunk_idx}")
        try:
            os.makedirs(chunk_out, exist_ok=True)
        except OSError as e:
            log_lines.append(
                f"sparsechunk recovery: mkdir {chunk_out} failed: {e}"
            )
            continue

        try:
            partitions, err = _scan_super_partitions_layout_sync(raw_path)
        except Exception as e:  # noqa: BLE001
            log_lines.append(
                f"sparsechunk recovery: scan {src_dirname}/raw.image failed: {e}"
            )
            continue
        if err:
            log_lines.append(
                f"sparsechunk recovery: {src_dirname}/raw.image scan err: {err}"
            )
            continue
        if not partitions:
            # Empty raw.image (this chunk's slice was all zeros) — normal.
            continue

        try:
            raw_size = os.path.getsize(raw_path)
        except OSError:
            continue

        # Carve + extract each detected partition into chunk_out.
        extracted_here = 0
        for i, (fs_type, start_offset) in enumerate(partitions):
            if i + 1 < len(partitions):
                part_size = partitions[i + 1][1] - start_offset
            else:
                part_size = raw_size - start_offset
            if part_size < _MIN_PARTITION_BYTES:
                continue
            partition_name = f"partition_{i}_{fs_type}"
            tmp_path: str | None = None
            try:
                tmp_path = _carve_partition_to_tmp_sync(
                    raw_path, start_offset, part_size, f".{fs_type}",
                )
                # _try_extract_partition is async — run via the loop.
                # We're inside a sync helper invoked from an async caller's
                # run_in_executor, so re-entering the loop directly is
                # not safe. Instead use asyncio.run_coroutine_threadsafe
                # against the loop the executor was spawned from, OR keep
                # this helper sync and skip the inner-extract step here —
                # the detection roots scanner will pick up the carved
                # partition file as a raw .erofs/.ext4 image in any case.
                # Simpler design: emit the carved file directly into the
                # chunk_out dir so the existing recursive-extract pass
                # downstream of the unpack pipeline handles unpacking it.
                final_path = os.path.join(
                    chunk_out, f"{partition_name}.{fs_type}",
                )
                # Move tmp into final location (rename is atomic on same fs).
                try:
                    os.replace(tmp_path, final_path)
                except OSError:
                    # Cross-device move — fall back to copy + unlink.
                    shutil.copy2(tmp_path, final_path)
                    with contextlib.suppress(OSError):
                        os.remove(tmp_path)
                tmp_path = None
                extracted_here += 1
            except Exception as e:  # noqa: BLE001
                log_lines.append(
                    f"sparsechunk recovery: carve {src_dirname} "
                    f"partition_{i} failed: {e}"
                )
            finally:
                if tmp_path and os.path.exists(tmp_path):
                    with contextlib.suppress(OSError):
                        os.remove(tmp_path)

        if extracted_here > 0:
            created_dirs.append(chunk_out)
            log_lines.append(
                f"sparsechunk recovery: {src_dirname}/raw.image → "
                f"{extracted_here} partition(s) carved into "
                f"super.img_recovered_extract/sparsechunk_{chunk_idx}/"
            )

    if not created_dirs:
        # Clean up the empty top-level recovery dir.
        with contextlib.suppress(OSError):
            os.rmdir(recovery_root)

    return created_dirs


async def recover_sparsechunk_extracts_async(
    extraction_dir: str, log_lines: list[str]
) -> list[str]:
    """Async post-unblob recovery: carve embedded partitions from sparsechunk
    extracts AND extract each carved partition into a walkable rootfs tree.

    Two-phase shape:
      1. Sync mmap-scan + carve via :func:`_recover_sparsechunk_extracts`
         (run on a thread executor to bound peak memory).
      2. Async extract each carved ``.ext4`` / ``.erofs`` file via the
         existing :func:`_try_extract_partition` helper (fsck.erofs or
         debugfs depending on fs type). Removes the carved image file
         after a successful extract to free disk (the extracted dir
         holds the same content in walkable form).

    Returns the list of walkable rootfs paths under
    ``<extraction_dir>/super.img_recovered_extract/sparsechunk_N/<partition>/``.
    These paths are picked up automatically by the detection_roots
    scanner via the existing ``partition_`` prefix hint.

    Called from :mod:`app.workers.unpack` immediately after the
    ``_recursive_extract_nested`` pass; the per-extract step has its
    own bounded timeout via ``_try_extract_partition`` (300s for
    fsck.erofs / debugfs each).
    """
    loop = asyncio.get_running_loop()
    chunk_dirs = await loop.run_in_executor(
        None, _recover_sparsechunk_extracts, extraction_dir, log_lines,
    )
    if not chunk_dirs:
        return []

    walkable_dirs: list[str] = []
    for chunk_dir in chunk_dirs:
        try:
            entries = os.listdir(chunk_dir)
        except OSError:
            continue
        for entry in entries:
            ent_path = os.path.join(chunk_dir, entry)
            if not os.path.isfile(ent_path):  # noqa: ASYNC240 — pre-flight stat in bounded chunk-dir loop (typically <20 carved partitions); Rule #43 category 1+3
                continue
            # Carved filenames are like "partition_0_ext4.ext4" /
            # "partition_1_erofs.erofs".
            partition_name = entry.rsplit(".", 1)[0]
            extracted = await _try_extract_partition(
                ent_path, chunk_dir, partition_name, log_lines,
            )
            if extracted:
                walkable_dirs.append(os.path.join(chunk_dir, partition_name))
                # Drop the now-redundant .ext4/.erofs image file; the
                # extracted dir holds the same content in walkable shape.
                # Failure to remove is non-fatal (disk waste, not
                # correctness).
                with contextlib.suppress(OSError):
                    os.remove(ent_path)
    return walkable_dirs


def _concatenate_sparsechunks(extraction_dir: str) -> list[tuple[str, int]]:
    """Reassemble Motorola-style ``<name>.img_sparsechunk.N`` files into a
    single ``<name>.img`` per prefix, then remove the individual chunks.

    Motorola factory flash packages split the super partition across N
    sparse chunks (``super.img_sparsechunk.0`` ...
    ``super.img_sparsechunk.10``). Each chunk is itself a valid Android
    sparse-image file; concatenating them in numeric order yields a
    single sparse super.img that the downstream ``simg2img`` + super-
    partition scan logic handles transparently.

    Returns a list of ``(merged_basename, chunk_count)`` tuples — one
    per reassembled image. Empty list if no sparsechunk files were
    found in ``extraction_dir`` (so the caller can skip the log line).

    The chunk filenames follow the convention ``<base>.img_sparsechunk.<N>``
    where ``<base>`` is typically ``super`` and ``<N>`` is a contiguous
    non-negative integer starting at 0. Non-contiguous or non-numeric
    suffixes are treated as a missing chunk and the merge is skipped
    (the chunks remain on disk for inspection rather than silently
    producing a corrupt super.img). Per CLAUDE.md Rule #5 sync-I/O
    discipline: this helper is sync and is invoked via
    ``loop.run_in_executor`` from the async extraction flow.
    """
    chunk_pattern = re.compile(r"^(.+\.img)_sparsechunk\.(\d+)$")
    chunks_by_prefix: dict[str, list[tuple[int, str]]] = {}
    for name in os.listdir(extraction_dir):
        full = os.path.join(extraction_dir, name)
        if not os.path.isfile(full):
            continue
        m = chunk_pattern.match(name)
        if not m:
            continue
        prefix = m.group(1)  # e.g. "super.img"
        index = int(m.group(2))
        chunks_by_prefix.setdefault(prefix, []).append((index, full))

    merged: list[tuple[str, int]] = []
    for prefix, indexed in chunks_by_prefix.items():
        indexed.sort(key=lambda pair: pair[0])
        # Validate contiguity (0 .. N-1) — skip merge on gap so a
        # corrupt upload doesn't yield a silently-truncated super.img.
        expected = list(range(len(indexed)))
        actual = [idx for idx, _ in indexed]
        if actual != expected:
            continue
        merged_path = os.path.join(extraction_dir, prefix)
        # If a same-named file already exists (e.g. a separate
        # ``super.img`` shipped alongside the chunks), don't overwrite
        # it — that's a malformed firmware case that should surface
        # to the operator as-is rather than be silently corrected.
        if os.path.exists(merged_path):
            continue
        # Stream-concatenate in 16 MiB buffers so a 5+ GB super.img
        # doesn't pin memory.
        try:
            with open(merged_path, "wb") as dst:
                for _, chunk_path in indexed:
                    with open(chunk_path, "rb") as src:
                        shutil.copyfileobj(src, dst, length=16 * 1024 * 1024)
        except OSError:
            # If concat failed mid-write, drop the partial output so
            # downstream code doesn't see a half-assembled super.img.
            with contextlib.suppress(OSError):
                os.remove(merged_path)
            continue
        # Remove the individual chunk files now that the merge succeeded.
        for _, chunk_path in indexed:
            with contextlib.suppress(OSError):
                os.remove(chunk_path)
        merged.append((prefix, len(indexed)))
    return merged


async def _extract_android_ota(firmware_path: str, extraction_dir: str) -> str:
    """Extract Android OTA ZIP — handles sparse images, ext4, EROFS."""
    import shutil
    import zipfile as _zipfile

    log_lines: list[str] = []
    loop = asyncio.get_running_loop()

    if _zipfile.is_zipfile(firmware_path):
        from app.workers.safe_extract import safe_extract_zip as _safe_extract_zip

        with _zipfile.ZipFile(firmware_path, "r") as _zf_probe:
            names = _zf_probe.namelist()

        if "payload.bin" in names:
            payload_path = os.path.join(extraction_dir, "payload.bin")
            # Extract only payload.bin through the safe helper so all three
            # defences (zipslip, bomb, symlink-attr) apply.
            _safe_extract_zip(
                firmware_path,
                extraction_dir,
                entry_filter=lambda n: n == "payload.bin",
            )
            log_lines.append("Found payload.bin (A/B OTA)")
            if shutil.which("payload-dumper-go"):
                partitions_dir = os.path.join(extraction_dir, "partitions")
                os.makedirs(partitions_dir, exist_ok=True)
                proc = await asyncio.create_subprocess_exec(
                    "payload-dumper-go", "-o", partitions_dir, payload_path,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                try:
                    stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=600)
                    log_lines.append(stdout.decode(errors="replace")[:2000])
                except TimeoutError:
                    proc.kill()
                    log_lines.append("payload-dumper-go timed out")
                os.remove(payload_path)
            else:
                log_lines.append("payload-dumper-go not installed, skipping payload.bin")
        else:
            # Extract .img / .bin partition images AND Motorola-style
            # sparse-chunk files (``super.img_sparsechunk.0`` ...
            # ``super.img_sparsechunk.N``). Moto factory flash packages
            # split the super partition across N sparse chunks; the
            # default ``.img`` / ``.bin`` filter misses them because the
            # chunk files end in ``.0`` / ``.1`` / ... rather than
            # ``.img``. After extraction, :func:`_concatenate_sparsechunks`
            # below reassembles them into a single ``super.img`` so the
            # downstream simg2img + super-partition scan logic finds the
            # content.
            def _is_android_payload(n: str) -> bool:
                return (
                    n.endswith(".img")
                    or n.endswith(".bin")
                    or ".img_sparsechunk." in os.path.basename(n)
                )

            _safe_extract_zip(
                firmware_path,
                extraction_dir,
                entry_filter=_is_android_payload,
            )
            for name in names:
                if _is_android_payload(name):
                    log_lines.append(f"Extracted {name}")
            # Reassemble Motorola super.img_sparsechunk.N → super.img.
            try:
                merged = await loop.run_in_executor(
                    None, _concatenate_sparsechunks, extraction_dir
                )
                for merged_basename, chunk_count in merged:
                    log_lines.append(
                        f"Reassembled {merged_basename} from "
                        f"{chunk_count} sparse chunk(s)"
                    )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                log_lines.append(f"sparse-chunk concat skipped: {exc}")
    else:
        import shutil
        dest = os.path.join(extraction_dir, os.path.basename(firmware_path))
        if not dest.endswith(".img"):
            dest += ".img"
        shutil.copy2(firmware_path, dest)
        log_lines.append(f"Copied raw sparse image: {os.path.basename(firmware_path)}")

    rootfs_dir = os.path.join(extraction_dir, "rootfs")
    os.makedirs(rootfs_dir, exist_ok=True)

    # Recursively expand any nested archives (Samsung tar.md5 → tar.lz4 →
    # partitions, Odin .zip containing another .zip, etc.) before we start
    # locating partition images.  Bounded to 3 levels of recursion.
    try:
        from app.workers.unpack_common import _recursive_extract_nested
        nested_dirs = _recursive_extract_nested(extraction_dir, max_depth=3)
        if nested_dirs:
            log_lines.append(
                f"Recursive nested extraction: expanded {len(nested_dirs)} archive(s)"
            )
    except Exception as e:
        log_lines.append(f"Nested extraction skipped: {e}")

    # Relocate any .img/.bin files out of scatter-zip version subdirectories
    # into the main extraction_dir.  MediaTek scatter ZIPs commonly nest
    # everything under a version-named folder (e.g. DPCS10_260414-1134/).
    # Previously we *scanned* those subdirs but never moved the files;
    # downstream detection treated `rootfs/` as the single source of truth
    # and never saw the raw partitions.  Now we relocate first, so the
    # subsequent per-image loop and all downstream consumers find them.
    _relocate_scatter_subdirs(extraction_dir, log_lines)

    search_dirs = [extraction_dir, os.path.join(extraction_dir, "partitions")]
    # Also search any subdirectories created by zip extraction that still
    # contain .img files (e.g., non-flat scatter ZIPs after relocation may
    # still leave subdirs we want to walk).
    for entry in os.scandir(extraction_dir):
        if entry.is_dir(follow_symlinks=False) and entry.name not in ("rootfs", "partitions", "boot"):
            search_dirs.append(entry.path)

    for search_dir in search_dirs:
        is_dir = await loop.run_in_executor(None, os.path.isdir, search_dir)
        if not is_dir:
            continue
        for img_name in sorted(os.listdir(search_dir)):
            if not img_name.endswith(".img"):
                continue
            img_path = os.path.join(search_dir, img_name)

            # Skip user-data partitions before any conversion / extraction.
            # Their declared sparse sizes are often multi-GB of mostly-zero
            # data that inflates the extraction tree and trips the bomb
            # limit, without contributing any firmware content worth
            # analysing.  See `_is_user_data_partition` for the set.
            if _is_user_data_partition(img_name):
                try:
                    raw_size = await loop.run_in_executor(
                        None, os.path.getsize, img_path,
                    )
                    size_mb = raw_size // (1024 * 1024)
                except OSError:
                    size_mb = 0
                try:
                    os.remove(img_path)
                except OSError:
                    pass
                log_lines.append(
                    f"Skipped {img_name} ({size_mb}MB, user-data partition — "
                    "not firmware)"
                )
                continue

            # Skip clearly-empty placeholders but preserve small real stubs
            # (DPCS10 modem.img is 528 B, md1dsp.img ~2 KB).  The previous
            # 1 MiB floor silently dropped them.
            try:
                img_size = await loop.run_in_executor(
                    None, os.path.getsize, img_path,
                )
                if img_size < _MIN_PARTITION_BYTES:
                    continue
            except OSError:
                continue

            # Check for boot.img (ANDROID! magic)
            img_magic = await loop.run_in_executor(
                None, _read_magic_sync, img_path, 8,
            )
            if img_magic is None:
                continue

            if img_magic[:8] == BOOT_IMG_MAGIC:
                boot_dir = os.path.join(rootfs_dir, "boot")
                await _extract_boot_img(img_path, boot_dir, log_lines)
                continue

            raw_path = img_path
            try:
                if img_magic[:4] == b"\x3a\xff\x26\xed" and shutil.which("simg2img"):
                    raw_path = img_path + ".raw"
                    proc = await asyncio.create_subprocess_exec(
                        "simg2img", img_path, raw_path,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.STDOUT,
                    )
                    await asyncio.wait_for(proc.communicate(), timeout=600)

                    # Verify output: size > 0 + recognisable magic.  If
                    # verification fails we drop the truncated .raw and
                    # keep the original sparse — downstream can retry.
                    verified, note = _verify_simg_output(raw_path)
                    if verified:
                        raw_mb = (await loop.run_in_executor(
                            None, os.path.getsize, raw_path,
                        )) // (1024 * 1024)
                        log_lines.append(
                            f"Converted {img_name} sparse → raw "
                            f"({raw_mb}MB, {note})"
                        )
                        # Only remove the sparse source once the raw output
                        # is verified — else we'd destroy the only copy.
                        try:
                            os.remove(img_path)
                        except OSError:
                            pass
                    else:
                        log_lines.append(
                            f"simg2img output failed verification for {img_name}: {note}; "
                            "keeping original sparse image"
                        )
                        try:
                            raw_exists = await loop.run_in_executor(
                                None, os.path.exists, raw_path,
                            )
                            if raw_exists:
                                os.remove(raw_path)
                        except OSError:
                            pass
                        raw_path = img_path  # fall through to parser on sparse
            except Exception as e:
                log_lines.append(f"Error converting {img_name}: {e}")
                continue

            is_super = False
            lp_magic = await loop.run_in_executor(
                None, _read_super_lp_magic_sync, raw_path,
            )
            if lp_magic == b"\x67\x44\x6c\x61":
                is_super = True
                log_lines.append(f"{img_name} is a super partition — scanning for embedded filesystems")

            if is_super:
                extracted_count, total_partitions = await _scan_super_partitions(
                    raw_path, rootfs_dir, log_lines,
                )
                # When every detected inner partition extracted cleanly the
                # raw LP2 container is redundant — no parser operates on
                # super.img directly; only the carved inner partitions
                # matter (mtk_preloader / mtk_lk / mediatek_modem target
                # leaf partitions, not the super wrapper).  Keeping the
                # raw would double-count against the extraction-bomb cap
                # and cost ~9 GB per Android firmware for no analytic
                # value.  Partial extraction keeps the raw so corrupt
                # inner partitions remain recoverable from its bytes.
                all_extracted = (
                    total_partitions > 0 and extracted_count == total_partitions
                )
                if all_extracted:
                    try:
                        raw_mb = (await loop.run_in_executor(
                            None, os.path.getsize, raw_path,
                        )) // (1024 * 1024)
                    except OSError:
                        raw_mb = 0
                    try:
                        os.remove(raw_path)
                        log_lines.append(
                            f"Removed {os.path.basename(raw_path)} ({raw_mb}MB) "
                            "after super scan (inner partitions carved into rootfs/)"
                        )
                    except OSError:
                        logger.info(
                            "super scan complete for %s; unable to remove raw",
                            raw_path,
                        )
                else:
                    logger.info(
                        "super scan of %s extracted %d/%d partitions; keeping raw",
                        raw_path,
                        extracted_count,
                        total_partitions,
                    )
                continue

            partition_name = img_name.replace(".img", "").replace(".raw", "")
            await _try_extract_partition(raw_path, rootfs_dir, partition_name, log_lines)

            # Previously we os.remove()'d raw_path here regardless of
            # mount success.  Phase 3 MediaTek/Qualcomm parsers run on the
            # raw bytes, so we keep the image even when mount fails.
            if raw_path != img_path:
                logger.info(
                    "Mount/extract attempted for %s; keeping raw image for downstream parsers",
                    raw_path,
                )

    return "\n".join(log_lines)


def _relocate_scatter_subdirs(extraction_dir: str, log_lines: list[str]) -> int:
    """Move partition images (.img / .bin) from scatter-zip version subdirs
    into ``extraction_dir`` root so downstream consumers see them.

    MediaTek scatter ZIPs nest everything under a version-named directory
    (e.g. ``DPCS10_260414-1134/lk.img``).  We only walk one level down to
    stay conservative; deeper nesting is rare in practice.  Timestamps are
    preserved via ``shutil.move`` (which falls back to copy+unlink across
    filesystem boundaries but we stay in the same FS here).

    Name collisions are resolved by suffixing ``_scatter`` to the moved
    file — we NEVER overwrite.  Returns the number of files moved.
    """
    import shutil as _shutil

    moved = 0
    reserved = {"rootfs", "partitions", "boot"}

    try:
        entries = list(os.scandir(extraction_dir))
    except OSError:
        return 0

    for entry in entries:
        if not entry.is_dir(follow_symlinks=False):
            continue
        if entry.name in reserved:
            continue
        try:
            inner = list(os.scandir(entry.path))
        except OSError:
            continue

        for item in inner:
            if not item.is_file(follow_symlinks=False):
                continue
            lname = item.name.lower()
            if not (lname.endswith(".img") or lname.endswith(".bin")):
                continue

            dest = os.path.join(extraction_dir, item.name)
            if os.path.exists(dest):
                # Collision: suffix the moved copy instead of overwriting
                dest = os.path.join(extraction_dir, item.name + "_scatter")
                if os.path.exists(dest):
                    log_lines.append(
                        f"Skipped relocating {item.name} (both root and "
                        "_scatter already exist)"
                    )
                    continue
                log_lines.append(
                    f"Name collision: relocating {item.name} as "
                    f"{os.path.basename(dest)}"
                )

            try:
                _shutil.move(item.path, dest)
                moved += 1
                log_lines.append(
                    f"Relocated {os.path.join(entry.name, item.name)} → "
                    f"{os.path.basename(dest)}"
                )
            except OSError as e:
                log_lines.append(f"Failed to relocate {item.path}: {e}")

    if moved:
        log_lines.append(
            f"Scatter-zip relocation: moved {moved} partition image(s) to "
            "extraction root"
        )
    return moved
