"""Windows Imaging Format (WIM) unpack worker via wimlib-imagex.

WIM is the Microsoft installer / recovery format used in Windows
installers (``sources/install.wim``, ``sources/boot.wim``), WinPE
images, and many medical/industrial recovery USBs. ``wimlib-imagex``
(apt: ``wimtools``) decompresses LZX/XPRESS streams and applies the
contained filesystem image to a target directory.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WIM_ARCHIVE] = unpack_wim

Multi-image WIMs (``install.wim`` typically ships Pro/Home/Education
indices 1..N) extract image index ``1`` deterministically; the full
image list captured from ``wimlib-imagex info`` lands in
:attr:`UnpackResult.unpack_log` so the operator knows what other
images are present. A future enhancement may expose an image-index
control to the upload UI; for Phase 2 handler 2, "always image 1"
matches the firmware-analysis use case (consumers care about the
installable rootfs, which is image 1 in every multi-image WIM we've
seen on real upload traffic).

Recursive payloads (squashfs / VHD inside the WIM) are NOT expanded
here. ``WINDOWS_INSTALLER_ISO`` (Phase 2 handler 3) routes through a
dedicated handler that re-dispatches inner WIM payloads via this
handler.

Why wimlib (not 7z): 7z's WIM support is read-only and lossy on
extended attributes / ACLs. wimlib-imagex is the canonical reference
implementation, handles LZX/XPRESS/LZMS, and preserves Unix data via
``--unix-data`` (used here so symlinks land as symlinks rather than
ASCII reparse-point dumps).
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


# wimlib-imagex extraction timeout. WIM extraction is decompression-heavy
# (LZX or LZMS at moderate compression ratios). 1 hour ceiling covers a
# 16 GB recovery USB on slow disk I/O. Mirrors the ISO 9660 ceiling so
# the WINDOWS_INSTALLER_ISO recursive handler (Phase 2 handler 3) can
# share the constant when it composes ISO + WIM extraction.
_WIMLIB_TIMEOUT_SECONDS = 3600

# wimlib-imagex info has its own (much smaller) ceiling — it only walks
# the WIM header + image-list structures; 30 s is generous.
_WIMLIB_INFO_TIMEOUT_SECONDS = 30

# wimlib-imagex returns 0 on success and any non-zero on failure. There
# is no "warnings" tier (unlike 7z's exit=1). Documented at
# https://wimlib.net/man1/wimlib-imagex.html.
_WIMLIB_OK_RETURN_CODES = (0,)

# Default image index to extract from a multi-image WIM. WIM indices are
# 1-based; index 1 is always present and is the "Edition 1" / primary
# install on every multi-image WIM we've measured on production traffic.
_DEFAULT_IMAGE_INDEX = "1"


async def unpack_wim(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature with unpack_firmware
) -> UnpackResult:
    """Extract WIM image #1 via wimlib-imagex and analyse the resulting tree.

    Steps:
        1. Prep extraction_dir (clean any prior failed run).
        2. Disk-space check — WIMs decompress 2-3x; require ~3x headroom.
        3. ``wimlib-imagex info <wim>`` — validate readability, capture
           the image list for unpack_log.
        4. ``wimlib-imagex apply <wim> 1 <extraction_dir> --unix-data``
           with a 1h timeout.
        5. Post-extraction: filesystem-root detection, architecture
           detection, OS-info detection — same shape as the monolith.
        6. Bomb-check via :func:`check_extraction_limits`.
        7. Widen read perms so the file-explorer API can read every file.

    Failure modes:
        - wimlib-imagex not installed → ``result.error = "wimlib-imagex
          binary missing — …"``, ``unpack_log`` carries the install hint.
        - ``info`` fails (rc != 0 OR exception) → ``result.error =
          "WIM archive unreadable"`` + truncated stderr.
        - ``apply`` non-zero exit → ``result.error`` carries the exit
          code + truncated stderr.
        - Timeout on ``apply`` → ``result.error = "wimlib-imagex apply
          timed out after 3600s"``.
        - No Unix-style filesystem root after extraction → still returns
          ``success=True`` with ``extracted_path = extraction_dir`` so
          the file explorer can browse the raw tree (Windows installer
          WIMs deliberately don't have a Unix rootfs).
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
        # WIM decompression typically inflates 2-3x. Require 3x for safe
        # headroom — better to fail fast than fill the volume mid-extract.
        if free < fw_size * 3:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 3 // (1024 * 1024)} MB for WIM extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        # Best-effort; let wimlib-imagex fail cleanly downstream if disk is short.
        pass

    # ---- Step 1: wimlib-imagex info — validate + capture image list ----
    await _report("Inspecting WIM archive", 5)

    info_cmd = ["wimlib-imagex", "info", firmware_path]
    try:
        info_proc = await asyncio.create_subprocess_exec(
            *info_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "wimlib-imagex binary missing — install wimtools"
        result.unpack_log = (
            f"{result.error}\n"
            "WIM extraction requires the `wimlib-imagex` CLI. The backend "
            "container ships with the `wimtools` package preinstalled; if "
            "you see this error, the container image is stale — rebuild "
            "with `docker compose up -d --build backend worker`.\n"
        )
        return result

    try:
        info_stdout_b, info_stderr_b = await asyncio.wait_for(
            info_proc.communicate(), timeout=_WIMLIB_INFO_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        info_proc.kill()
        try:
            await info_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"wimlib-imagex info timed out after {_WIMLIB_INFO_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    info_stdout = (info_stdout_b or b"").decode(errors="replace")
    info_stderr = (info_stderr_b or b"").decode(errors="replace")
    info_rc = info_proc.returncode

    if info_rc != 0:
        result.error = f"WIM archive unreadable (info exit={info_rc})"
        result.unpack_log = (
            f"wimlib-imagex info exit={info_rc}\n"
            f"stderr (last 2KB):\n{info_stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"wimlib-imagex info exit=0\n"
        f"image list (first 2KB):\n{info_stdout[:2000]}\n"
    )

    # ---- Step 2: wimlib-imagex apply — extract image #1 ----
    await _report(f"Extracting WIM image {_DEFAULT_IMAGE_INDEX} via wimlib-imagex", 10)

    apply_cmd = [
        "wimlib-imagex", "apply",
        firmware_path,
        _DEFAULT_IMAGE_INDEX,
        extraction_dir,
        "--unix-data",   # preserve symlinks + permissions where the WIM has them
        "--no-acls",     # skip Windows ACLs — meaningless on a Linux extract host
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *apply_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        # Defensive — info succeeded above so wimlib-imagex was on PATH;
        # if apply suddenly can't find it, surface the same install hint.
        result.error = "wimlib-imagex binary missing — install wimtools"
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "wimlib-imagex apply could not be invoked despite info "
            "succeeding. Rebuild backend + worker.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_WIMLIB_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"wimlib-imagex apply timed out after {_WIMLIB_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = log_head + result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"wimlib-imagex apply exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _WIMLIB_OK_RETURN_CODES:
        result.error = (
            f"wimlib-imagex apply failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 3: post-extraction analysis (mirror unpack_iso9660) ----
    await _report("Analysing extracted filesystem", 70)

    # Widen read perms so the file-explorer can serve every file. WIMs
    # often carry Windows-style permission bits that confuse the API.
    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for WIM extraction: %s", exc)

    # Filesystem-root detection. Windows WIMs typically lack the Linux
    # markers (etc/, usr/, …), so find_filesystem_root will return None;
    # that is NOT an error — it just means the operator browses the raw
    # Windows-style tree (Windows/, Program Files/, etc.).
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
        # No Unix-style rootfs (typical for Windows installer WIMs and
        # vendor recovery WIMs). The extraction is still useful — the
        # file explorer surfaces every file. Treat as success.
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "WIM extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for Windows-style payloads "
            "(Windows/, Program Files/, sources/, …).\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = (
        log_head
        + f"WIM extraction complete via wimlib-imagex (image {_DEFAULT_IMAGE_INDEX}).\n"
    )
    await _report("Extraction complete", 100)
    return result
