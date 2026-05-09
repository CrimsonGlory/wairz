"""Android-specific firmware extraction — OTA, sparse images, super.img, boot.img."""

import asyncio
import gzip
import logging
import os
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


async def _extract_boot_img(
    boot_path: str, output_dir: str, log_lines: list[str]
) -> bool:
    """Extract kernel, ramdisk, and DTB from an Android boot.img.

    Supports boot image header v0-v4 (covers all mainstream Android devices).
    The format is page-aligned: header at page 0, then kernel, ramdisk,
    second-stage, and optionally recovery DTBO and DTB.
    """
    try:
        with open(boot_path, "rb") as f:
            header = f.read(1648)
    except OSError as e:
        log_lines.append(f"Cannot read boot.img: {e}")
        return False

    if len(header) < 1648 or header[:8] != BOOT_IMG_MAGIC:
        log_lines.append("Not a valid Android boot image (bad magic)")
        return False

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

    extracted = []

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

            # Try to decompress and extract ramdisk (usually gzip'd cpio)
            ramdisk_dir = os.path.join(output_dir, "ramdisk")
            os.makedirs(ramdisk_dir, exist_ok=True)
            try:
                await _extract_ramdisk(ramdisk_data, ramdisk_dir)
                extracted.append("ramdisk contents extracted")
            except Exception as e:
                log_lines.append(f"Ramdisk extraction failed: {e}")

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
        return True

    log_lines.append("boot.img: no components found to extract")
    return False


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

    try:
        proc = await asyncio.create_subprocess_exec(
            "cpio", "-idm", "--no-absolute-filenames",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=output_dir,
        )
        with open(tmp_path, "rb") as f:
            cpio_data = f.read()
        await asyncio.wait_for(proc.communicate(input=cpio_data), timeout=60)
    finally:
        os.unlink(tmp_path)


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
    import mmap
    import tempfile

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
        log_lines.append(f"Error scanning super.img: {e}")
        return 0, 0

    if not partitions:
        log_lines.append("No EROFS or ext4 partitions found in super.img")
        return 0, 0

    partitions.sort(key=lambda x: x[1])
    log_lines.append(f"Found {len(partitions)} partition(s) in super.img")

    extracted_count = 0
    for i, (fs_type, start_offset) in enumerate(partitions):
        if i + 1 < len(partitions):
            part_size = partitions[i + 1][1] - start_offset
        else:
            part_size = os.path.getsize(raw_path) - start_offset

        # Keep anything above _MIN_PARTITION_BYTES so we don't silently drop
        # tiny stub partitions (e.g. GFH-only headers a few KB long).  The
        # previous 1 MiB floor hid DPCS10-class small partitions entirely.
        if part_size < _MIN_PARTITION_BYTES:
            continue

        partition_name = f"partition_{i}_{fs_type}"

        try:
            with tempfile.NamedTemporaryFile(suffix=f".{fs_type}", delete=False) as tmp:
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

            if await _try_extract_partition(tmp_path, rootfs_dir, partition_name, log_lines):
                identified = _identify_partition_by_content(
                    os.path.join(rootfs_dir, partition_name)
                )
                if identified and identified != partition_name:
                    old_path = os.path.join(rootfs_dir, partition_name)
                    new_path = os.path.join(rootfs_dir, identified)
                    if not os.path.exists(new_path):
                        os.rename(old_path, new_path)
                        log_lines.append(f"Identified {partition_name} as '{identified}'")
                        partition_name = identified
                extracted_count += 1
        except Exception as e:
            log_lines.append(f"Error extracting partition at offset 0x{start_offset:x}: {e}")
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    log_lines.append(f"Extracted {extracted_count}/{len(partitions)} partitions from super.img")
    return extracted_count, len(partitions)


async def _extract_android_ota(firmware_path: str, extraction_dir: str) -> str:
    """Extract Android OTA ZIP — handles sparse images, ext4, EROFS."""
    import shutil
    import zipfile as _zipfile

    log_lines: list[str] = []

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
            # Extract only .img and .bin partition images.
            _safe_extract_zip(
                firmware_path,
                extraction_dir,
                entry_filter=lambda n: n.endswith(".img") or n.endswith(".bin"),
            )
            for name in names:
                if name.endswith(".img") or name.endswith(".bin"):
                    log_lines.append(f"Extracted {name}")
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
        if not os.path.isdir(search_dir):
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
                    size_mb = os.path.getsize(img_path) // (1024 * 1024)
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
                if os.path.getsize(img_path) < _MIN_PARTITION_BYTES:
                    continue
            except OSError:
                continue

            # Check for boot.img (ANDROID! magic)
            try:
                with open(img_path, "rb") as f:
                    img_magic = f.read(8)
            except OSError:
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
                        log_lines.append(
                            f"Converted {img_name} sparse → raw "
                            f"({os.path.getsize(raw_path) // (1024*1024)}MB, {note})"
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
                            if os.path.exists(raw_path):
                                os.remove(raw_path)
                        except OSError:
                            pass
                        raw_path = img_path  # fall through to parser on sparse
            except Exception as e:
                log_lines.append(f"Error converting {img_name}: {e}")
                continue

            is_super = False
            try:
                with open(raw_path, "rb") as f:
                    f.seek(0x1000)
                    lp_magic = f.read(4)
                    if lp_magic == b"\x67\x44\x6c\x61":
                        is_super = True
                        log_lines.append(f"{img_name} is a super partition — scanning for embedded filesystems")
            except Exception:
                pass

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
                        raw_mb = os.path.getsize(raw_path) // (1024 * 1024)
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
