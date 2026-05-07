"""ISO 9660 / Joliet / Rock Ridge unpack worker via 7z.

7z handles ISO 9660 + extensions (Joliet, Rock Ridge, El Torito boot
records) cleanly without needing the kernel mount-iso path. Output is
a directory tree the standard post-extraction analysis (architecture
detection, filesystem root, etc.) can consume.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.ISO_9660] = unpack_iso9660

Recursive payloads (WIM inside the ISO) are NOT expanded here —
WINDOWS_INSTALLER_ISO routes through a dedicated handler that
re-dispatches the inner WIM via the WIM handler.

Why 7z (not unblob): unblob's heuristic-driven extractor is
generic; 7z is a single-purpose ISO/archive tool with explicit
ISO 9660 support and predictable exit codes. 7z is already in the
backend container image (no Dockerfile change), so this handler
ships without a Rule #8 backend+worker rebuild.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

from app.workers.unpack_common import (
    UnpackResult,
    check_extraction_limits,
    find_filesystem_root,
    widen_read_perms,
)
from app.workers.unpack_linux import (
    detect_architecture,
    detect_kernel,
    detect_os_info,
)

logger = logging.getLogger(__name__)


# 7z extraction timeout. ISO 9660 extraction is a pure-IO operation
# (no decompression past basic algorithms). 1 hour ceiling covers the
# largest realistic medical/industrial recovery ISOs (~16 GB) on slow
# disk I/O. Mirrors the unblob 1200s ceiling shape from unpack_common
# but raised because ISOs can be larger than typical firmware blobs.
_SEVENZ_TIMEOUT_SECONDS = 3600

# Recognised 7z exit codes:
#   0 — success
#   1 — non-fatal warnings (extraction completed)
#   >=2 — fatal error
# Documented at https://documentation.help/7-Zip/exit_codes.htm
_SEVENZ_OK_RETURN_CODES = (0, 1)


async def unpack_iso9660(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature with unpack_firmware
) -> UnpackResult:
    """Extract an ISO 9660 image via 7z and analyse the resulting tree.

    Steps:
        1. Prep extraction_dir (clean any prior failed run).
        2. Disk-space check (need ~2× the ISO size for safe headroom).
        3. Run ``7z x -y -o<extraction_dir> <iso>`` with a 1h timeout.
        4. Post-extraction: filesystem-root detection, architecture
           detection, OS-info detection — same shape as the monolith.
        5. Bomb-check via :func:`check_extraction_limits`.
        6. Widen read perms so the file-explorer API can read every file.

    Failure modes:
        - 7z not installed → ``result.error = "7z binary missing — …"``,
          ``unpack_log`` carries the install hint.
        - 7z exit ≥ 2 → ``result.error`` carries the truncated stderr.
        - Timeout → ``result.error = "7z extraction timed out after 3600s"``.
        - No Unix-style filesystem root after extraction → still returns
          ``success=True`` with ``extracted_path = extraction_dir`` so the
          file explorer can browse the raw tree (Windows installer ISOs
          and many vendor recovery ISOs lack a Unix rootfs).
    """
    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")

    if os.path.exists(extraction_dir):
        shutil.rmtree(extraction_dir, ignore_errors=True)
    os.makedirs(extraction_dir, exist_ok=True)

    # Disk-space check — Rule #5 wraps blocking shutil/os calls in executor.
    loop = asyncio.get_running_loop()
    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        if free < fw_size * 2:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 2 // (1024 * 1024)} MB for ISO 9660 extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        # Best-effort; let 7z fail cleanly downstream if disk is short.
        pass

    await _report("Extracting ISO 9660 via 7z", 10)

    cmd = [
        "7z", "x", "-y",                # extract, assume yes on prompts
        f"-o{extraction_dir}",          # 7z accepts -o<dir> with NO space
        firmware_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "7z binary missing — install p7zip-full"
        result.unpack_log = (
            f"{result.error}\n"
            "ISO 9660 extraction requires the `7z` CLI. The backend "
            "container ships with p7zip-full preinstalled; if you see "
            "this error, the container image is stale — rebuild with "
            "`docker compose up -d --build backend worker`.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_SEVENZ_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = f"7z extraction timed out after {_SEVENZ_TIMEOUT_SECONDS}s"
        result.unpack_log = result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head = (
        f"7z exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _SEVENZ_OK_RETURN_CODES:
        result.error = f"7z extraction failed (exit={rc}): {stderr[-500:]}"
        result.unpack_log = log_head + result.error
        return result

    # Post-extraction discipline: same as the monolith for parity.
    await _report("Analysing extracted filesystem", 70)

    # Widen read perms so the file-explorer can serve every file.
    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for ISO 9660 extraction: %s", exc)

    # Filesystem-root detection — find_filesystem_root looks for
    # Unix/Linux markers (etc/, usr/, bin/, system/build.prop, …).
    # Windows installer ISOs and many vendor recovery ISOs won't have
    # those, so the function returns None — that is NOT an error.
    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)

    if fs_root:
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
        arch, endian = await loop.run_in_executor(None, detect_architecture, fs_root)
        result.architecture = arch
        result.endianness = endian
        result.os_info = await loop.run_in_executor(None, detect_os_info, fs_root)
        result.kernel_path = await loop.run_in_executor(
            None, lambda: detect_kernel(extraction_dir, fs_root),
        )
    else:
        # No Unix-style rootfs (typical for Windows installer ISOs and
        # vendor recovery ISOs). The extraction is still useful — the
        # file explorer surfaces every file. Treat as success.
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "ISO extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for installer payloads, manifests, "
            "and boot loaders.\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + "ISO 9660 extraction complete via 7z.\n"
    await _report("Extraction complete", 100)
    return result
