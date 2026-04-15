"""Recursive filesystem-image extractor — runs after binwalk.

Binwalk with -Me handles the common case. This dispatcher catches:
  * vendor-modified SquashFS that binwalk's signature scanner misses
    (Zyxel, D-Link — falls back to sasquatch)
  * UBI/UBIFS/JFFS2 images that binwalk produced but didn't further unpack
  * Nested filesystems revealed only after each extraction pass

All failures are logged, never raised. Binwalk remains the authoritative
first-pass extractor; this module is a best-effort enrichment.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
import stat
from typing import Awaitable, Callable, Literal

from .unpack import _KERNEL_NAME_PATTERNS

FsType = Literal["squashfs", "ubi", "ubifs", "jffs2", "cramfs", "ext", "cpio"]


# Magic bytes at offset 0. Ext is the exception — see _detect_fs_type.
_MAGICS: dict[FsType, tuple[bytes, ...]] = {
    # hsqs LE, sqsh BE, plus older/less-common endian variants
    "squashfs": (b"hsqs", b"sqsh", b"qshs", b"shsq"),
    "ubi":      (b"UBI#",),
    "ubifs":    (b"\x31\x18\x10\x06",),
    "jffs2":    (b"\x85\x19", b"\x19\x85"),
    "cramfs":   (b"\x45\x3d\xcd\x28", b"\x28\xcd\x3d\x45"),
    "cpio":     (b"070701", b"070702", b"070707"),
}

# ext2/3/4 superblock starts at byte 0x400; s_magic (2 bytes) sits at
# offset 0x38 within the superblock → absolute offset 0x438.
_EXT_MAGIC_OFFSET = 0x438
_EXT_MAGIC = b"\x53\xef"

_MIN_FS_SIZE = 4 * 1024
_MAX_FS_SIZE = 2 * 1024 * 1024 * 1024

_SHA_CHUNK = 1024 * 1024  # 1 MB


def _detect_fs_type(path: str) -> FsType | None:
    try:
        size = os.path.getsize(path)
    except OSError:
        return None
    if size < _MIN_FS_SIZE or size > _MAX_FS_SIZE:
        return None

    try:
        with open(path, "rb") as f:
            head = f.read(8)
            for fs_type, magics in _MAGICS.items():
                for magic in magics:
                    if head.startswith(magic):
                        return fs_type

            if size >= _EXT_MAGIC_OFFSET + len(_EXT_MAGIC):
                f.seek(_EXT_MAGIC_OFFSET)
                if f.read(len(_EXT_MAGIC)) == _EXT_MAGIC:
                    return "ext"
    except OSError:
        return None

    return None


def _sha256_file(path: str) -> str | None:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(_SHA_CHUNK)
                if not chunk:
                    break
                h.update(chunk)
    except OSError:
        return None
    return h.hexdigest()


def _is_excluded(path: str, extraction_root_real: str) -> bool:
    """Skip kernels, large ELF executables, and symlinks escaping the sandbox."""
    name_lower = os.path.basename(path).lower()
    if any(p in name_lower for p in _KERNEL_NAME_PATTERNS):
        return True

    try:
        real = os.path.realpath(path)
    except OSError:
        return True
    if not (real == extraction_root_real or real.startswith(extraction_root_real + os.sep)):
        return True

    try:
        with open(path, "rb") as f:
            if f.read(4) == b"\x7fELF":
                if os.path.getsize(path) > 500_000:
                    return True
    except OSError:
        return True

    return False


async def _run(
    args: list[str],
    timeout: int,
    cwd: str | None = None,
    stdin_path: str | None = None,
) -> tuple[int | None, str]:
    """Spawn a subprocess without a shell; return (returncode, combined output).

    returncode is None on timeout or spawn failure.
    """
    stdin_file = None
    try:
        if stdin_path is not None:
            stdin_file = open(stdin_path, "rb")
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdin=stdin_file if stdin_file else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            cwd=cwd,
        )
    except FileNotFoundError:
        if stdin_file:
            stdin_file.close()
        return None, f"[tool not found: {args[0]}]"
    except Exception as exc:
        if stdin_file:
            stdin_file.close()
        return None, f"[spawn failed: {exc}]"

    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.wait()
        except Exception:
            pass
        return None, f"[timeout after {timeout}s]"
    finally:
        if stdin_file:
            stdin_file.close()

    text = stdout.decode(errors="replace").replace("\x00", "")
    return proc.returncode, text


async def _extract_squashfs(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    # unsquashfs refuses to extract into an existing directory unless -f.
    if os.path.exists(out_dir):
        return False, "output dir already exists"

    rc, _log = await _run(["unsquashfs", "-d", out_dir, src], timeout=timeout)
    if rc == 0 and os.path.isdir(out_dir) and os.listdir(out_dir):
        return True, "unsquashfs ok"

    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir, ignore_errors=True)

    if not shutil.which("sasquatch"):
        return False, f"unsquashfs rc={rc}; sasquatch unavailable"

    rc2, _log2 = await _run(["sasquatch", "-d", out_dir, src], timeout=timeout)
    if rc2 == 0 and os.path.isdir(out_dir) and os.listdir(out_dir):
        return True, "sasquatch ok (vendor-modified squashfs)"
    return False, f"unsquashfs rc={rc}, sasquatch rc={rc2}"


async def _extract_jffs2(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    os.makedirs(out_dir, exist_ok=True)
    rc, _log = await _run(["jefferson", "-d", out_dir, src], timeout=timeout)
    if rc == 0 and os.listdir(out_dir):
        return True, "jefferson ok"
    return False, f"jefferson rc={rc}"


async def _extract_ubi(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    os.makedirs(out_dir, exist_ok=True)
    rc, _log = await _run(
        ["ubireader_extract_images", "-o", out_dir, src], timeout=timeout
    )
    if rc == 0 and os.listdir(out_dir):
        return True, "ubireader_extract_images ok"
    return False, f"ubireader_extract_images rc={rc}"


async def _extract_ubifs(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    os.makedirs(out_dir, exist_ok=True)
    rc, _log = await _run(
        ["ubireader_extract_files", "-o", out_dir, src], timeout=timeout
    )
    if rc == 0 and os.listdir(out_dir):
        return True, "ubireader_extract_files ok"
    return False, f"ubireader_extract_files rc={rc}"


async def _extract_cramfs(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    # The Dockerfile provides a cramfsck shim (lines 32-33) that accepts -x <dir>.
    if os.path.exists(out_dir):
        return False, "output dir already exists"
    rc, _log = await _run(["cramfsck", "-x", out_dir, src], timeout=timeout)
    if rc == 0 and os.path.isdir(out_dir) and os.listdir(out_dir):
        return True, "cramfsck ok"
    return False, f"cramfsck rc={rc}"


async def _extract_ext(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    os.makedirs(out_dir, exist_ok=True)
    rc, _log = await _run(
        ["7z", "x", "-y", f"-o{out_dir}", src], timeout=timeout
    )
    if rc == 0 and os.listdir(out_dir):
        return True, "7z ext ok"
    return False, f"7z ext rc={rc}"


async def _extract_cpio(src: str, out_dir: str, timeout: int) -> tuple[bool, str]:
    os.makedirs(out_dir, exist_ok=True)
    rc, _log = await _run(
        ["cpio", "-idmv", "--no-absolute-filenames"],
        timeout=timeout,
        cwd=out_dir,
        stdin_path=src,
    )
    if rc == 0 and os.listdir(out_dir):
        return True, "cpio ok"
    return False, f"cpio rc={rc}"


_Extractor = Callable[[str, str, int], Awaitable[tuple[bool, str]]]
_EXTRACTORS: dict[FsType, _Extractor] = {
    "squashfs": _extract_squashfs,
    "ubi":      _extract_ubi,
    "ubifs":    _extract_ubifs,
    "jffs2":    _extract_jffs2,
    "cramfs":   _extract_cramfs,
    "ext":      _extract_ext,
    "cpio":     _extract_cpio,
}


def _extraction_output_dir(src: str) -> str:
    base = f"{src}.extracted"
    if not os.path.exists(base):
        return base
    i = 1
    while os.path.exists(f"{base}.{i}"):
        i += 1
    return f"{base}.{i}"


def _scan_candidates(
    extraction_dir: str,
    extraction_root_real: str,
    seen_sha: set[str],
) -> list[tuple[str, FsType, str]]:
    """Return (path, fs_type, sha256) for unseen filesystem images."""
    hits: list[tuple[str, FsType, str]] = []
    for root, _dirs, files in os.walk(extraction_dir):
        for name in files:
            path = os.path.join(root, name)
            try:
                st = os.lstat(path)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            if _is_excluded(path, extraction_root_real):
                continue
            fs_type = _detect_fs_type(path)
            if fs_type is None:
                continue
            sha = _sha256_file(path)
            if sha is None or sha in seen_sha:
                continue
            hits.append((path, fs_type, sha))
    return hits


def _count_yaffs_candidates(extraction_dir: str, extraction_root_real: str) -> int:
    count = 0
    for root, _dirs, files in os.walk(extraction_dir):
        for name in files:
            if name.lower().endswith((".yaffs", ".yaffs2")):
                path = os.path.join(root, name)
                if not _is_excluded(path, extraction_root_real):
                    count += 1
    return count


def _dir_bytes(path: str) -> int:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                pass
    return total


async def recursive_extract(
    extraction_dir: str,
    *,
    max_depth: int = 3,
    per_extract_timeout: int = 300,
    max_total_bytes_multiplier: float = 20.0,
    original_size: int | None = None,
) -> str:
    """Extract filesystem images under ``extraction_dir`` until fixed-point.

    Detects SquashFS/UBI/UBIFS/JFFS2/CramFS/ext2-4/cpio by magic bytes at
    offset 0 (ext at 0x438). Dispatches to unsquashfs (with sasquatch
    fallback), ubireader_extract_images/_files, jefferson, cramfsck, ``7z x``,
    and ``cpio -idmv``. Each extraction writes to ``<file>.extracted/`` as a
    sibling directory.

    SHA256 deduplication prevents re-extracting identical blobs emitted
    under multiple paths. Loops until no new images are found or max_depth
    is reached. Per-extraction wall-clock timeout and a cumulative-size cap
    (``original_size * multiplier``) guard against extraction bombs.

    Log-and-continue on every failure; never raises. Returns a human-readable
    multi-line log suitable for appending to ``firmware.unpack_log``.
    """
    lines: list[str] = [f"[fs_extractors] scanning {extraction_dir}"]
    extraction_root_real = os.path.realpath(extraction_dir)
    seen_sha: set[str] = set()
    total_written = 0
    size_cap: int | None = (
        int(original_size * max_total_bytes_multiplier)
        if original_size and max_total_bytes_multiplier > 0
        else None
    )
    capped = False

    for iteration in range(1, max_depth + 1):
        if capped:
            break
        candidates = _scan_candidates(extraction_dir, extraction_root_real, seen_sha)
        if not candidates:
            lines.append(f"[fs_extractors] iter {iteration}: no new images; stopping")
            break

        lines.append(f"[fs_extractors] iter {iteration}: {len(candidates)} candidate(s)")
        new_this_iter = 0

        for src, fs_type, sha in candidates:
            if sha in seen_sha:
                continue
            seen_sha.add(sha)

            if size_cap is not None and total_written >= size_cap:
                lines.append(
                    f"[fs_extractors] size cap hit ({total_written} >= {size_cap}); "
                    f"skipping remaining candidates"
                )
                capped = True
                break

            out_dir = _extraction_output_dir(src)
            extractor = _EXTRACTORS.get(fs_type)
            rel = os.path.relpath(src, extraction_dir)

            if extractor is None:
                lines.append(f"[fs_extractors] {fs_type} {rel}: no extractor registered")
                continue

            try:
                ok, msg = await extractor(src, out_dir, per_extract_timeout)
            except Exception as exc:
                lines.append(f"[fs_extractors] {fs_type} {rel}: exception {exc!r}")
                continue

            lines.append(f"[fs_extractors] {fs_type} {rel}: {msg}")
            if ok:
                new_this_iter += 1
                total_written += _dir_bytes(out_dir)

        if new_this_iter == 0:
            lines.append(f"[fs_extractors] iter {iteration}: nothing extracted; stopping")
            break
    else:
        lines.append(f"[fs_extractors] reached max_depth={max_depth}; stopping")

    yaffs_count = _count_yaffs_candidates(extraction_dir, extraction_root_real)
    if yaffs_count:
        lines.append(
            f"[fs_extractors] {yaffs_count} YAFFS image(s) detected; "
            f"manual extraction with yaffshiv (needs page+OOB size hints) required"
        )

    lines.append("[fs_extractors] done")
    return "\n".join(lines) + "\n"
