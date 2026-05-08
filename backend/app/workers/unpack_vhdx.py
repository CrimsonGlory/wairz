"""VHDX virtual disk unpack worker via qemu-img.

VHDX is the Hyper-V / WSL2 virtual disk format. ``qemu-img`` (apt:
``qemu-utils``, added in Phase α.6 Dockerfile) converts VHDX to a raw
disk image; the raw image is typically an NTFS volume, ready for
libfsntfs walk by the ``mount_vhdx`` MCP tool (Phase α.4).

Phase α handler 7 — extracts the VHDX into ``extraction_dir/disk.raw``
+ surfaces qemu-img info metadata in the unpack_log.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_VHDX] = unpack_vhdx

NTFS reparse-point sandbox-bypass risk (Persona-E #29 + future Rule
#1 escalation): the ``mount_vhdx`` MCP tool MUST realpath-walk every
reparse-point target against the extraction sandbox before serving
any file. The unpack worker doesn't read NTFS — it just produces the
raw image — so the discipline lands at the MCP layer.

Why qemu-img (not libvhdi-utils): qemu-img is the most-maintained
Linux-side VHDX tool and handles both fixed + dynamic + differencing
chains. libvhdi covers VHD/VHDX format-level access for in-process
parsing (used by MCP tools), but for raw-image extraction qemu-img
is the workflow tool.

Differencing / parent VHDX chains (Persona-E #32) — handled by
``mount_vhdx`` MCP tool which walks ``ParentLocator``. The unpack
worker handles a single VHDX; chained packages need the MCP tool's
parent-walk path.
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
)

logger = logging.getLogger(__name__)


# qemu-img convert timeout. VHDX conversion is I/O-bound; a 4 GB VHDX
# typically converts in 20-40 s, so 10 minutes is generous for the
# large-VHDX tail (Win11 install captures, WSL2 rootfs at 30+ GB).
# Aligned with Ghidra-tier (360_000 ms) per Rule #29.
_QEMU_IMG_CONVERT_TIMEOUT_SECONDS = 600

# qemu-img info — cheap probe (reads only the BAT header). 30s ample.
_QEMU_IMG_INFO_TIMEOUT_SECONDS = 30

# qemu-img exit codes: 0 = success; non-zero = failure (any).
_QEMU_IMG_OK_RETURN_CODES = (0,)

# VHDX magic bytes — "vhdxfile" at offset 0 (verified per Microsoft
# MS-VHDX spec; alternate magic for LEGACY VHD is "conectix" at the
# last 512-byte block, which this worker does NOT handle — VHD support
# is a separate enum value if added later).
_VHDX_MAGIC = b"vhdxfile"
_VHDX_MAGIC_PROBE_BYTES = 8


async def unpack_vhdx(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001
) -> UnpackResult:
    """Convert a VHDX to a raw disk image via qemu-img.

    Steps:
        1. Prep extraction_dir.
        2. Validate VHDX magic ("vhdxfile" at offset 0).
        3. ``qemu-img info <vhdx>`` — metadata (virtual size, cluster
           size, parent locator, format-specific options).
        4. Disk-space check — raw conversion expands sparse → full.
        5. ``qemu-img convert -f vhdx -O raw <vhdx> <dir>/disk.raw``.
        6. Surface info + raw image path in unpack_log.

    Failure modes:
        - qemu-img missing → install hint pointing at Phase α.6
          (qemu-utils apt package).
        - magic mismatch → "Not a VHDX" error.
        - qemu-img info exit != 0 → "VHDX unreadable".
        - convert exit != 0 → exit code + stderr.
        - timeout → Ghidra-tier ceiling exceeded.
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

    # ---- Step 1: validate VHDX magic ----
    await _report("Validating VHDX magic", 5)

    loop = asyncio.get_running_loop()

    def _read_head() -> bytes:
        with open(firmware_path, "rb") as fh:
            return fh.read(_VHDX_MAGIC_PROBE_BYTES)

    try:
        head = await loop.run_in_executor(None, _read_head)
    except OSError as exc:
        result.error = f"VHDX read failed: {exc}"
        result.unpack_log = result.error
        return result

    if head[: len(_VHDX_MAGIC)] != _VHDX_MAGIC:
        result.error = (
            f"Not a VHDX file — expected magic {_VHDX_MAGIC!r} at offset 0, "
            f"got {head[:8]!r}"
        )
        result.unpack_log = result.error
        return result

    # ---- Step 2: qemu-img info ----
    await _report("Inspecting VHDX metadata", 10)

    info_cmd = ["qemu-img", "info", "--output=json", firmware_path]
    try:
        info_proc = await asyncio.create_subprocess_exec(
            *info_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "qemu-img binary missing — install qemu-utils"
        result.unpack_log = (
            f"{result.error}\n"
            "VHDX extraction requires the `qemu-img` CLI from the "
            "`qemu-utils` apt package. Phase α.6 ships this — "
            "rebuild backend + worker with the Phase α.6 Dockerfile delta.\n"
        )
        return result

    try:
        info_stdout_b, info_stderr_b = await asyncio.wait_for(
            info_proc.communicate(),
            timeout=_QEMU_IMG_INFO_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        info_proc.kill()
        try:
            await info_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"qemu-img info timed out after {_QEMU_IMG_INFO_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    info_stdout = (info_stdout_b or b"").decode(errors="replace")
    info_stderr = (info_stderr_b or b"").decode(errors="replace")
    info_rc = info_proc.returncode

    if info_rc != 0:
        result.error = f"VHDX unreadable (qemu-img info exit={info_rc})"
        result.unpack_log = (
            f"qemu-img info exit={info_rc}\n"
            f"stderr (last 2KB):\n{info_stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"qemu-img info exit=0\n"
        f"info JSON (first 4KB):\n{info_stdout[:4000]}\n"
    )

    # ---- Step 3: disk-space check ----
    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        # VHDX → raw can expand sparse blocks; require the virtual size
        # plus 20% headroom. We don't parse virtual_size from JSON here
        # (keeping the worker simple); use 5x the file size as a safe
        # heuristic (covers 95% of real VHDX → raw conversions).
        if free < fw_size * 5:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 5 // (1024 * 1024)} MB for VHDX → raw conversion"
            )
            result.unpack_log = log_head + result.error
            return result
    except OSError:
        pass

    # ---- Step 4: qemu-img convert ----
    await _report("Converting VHDX to raw", 20)

    raw_path = os.path.join(extraction_dir, "disk.raw")
    convert_cmd = [
        "qemu-img", "convert",
        "-f", "vhdx",
        "-O", "raw",
        firmware_path,
        raw_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *convert_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "qemu-img binary missing — install qemu-utils"
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "qemu-img info succeeded but convert invocation could not "
            "find the binary; rebuild backend + worker.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(),
            timeout=_QEMU_IMG_CONVERT_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"qemu-img convert timed out after {_QEMU_IMG_CONVERT_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = log_head + result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"qemu-img convert exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _QEMU_IMG_OK_RETURN_CODES:
        result.error = (
            f"qemu-img convert failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 5: post-conversion analysis ----
    await _report("Analysing converted raw image", 80)

    raw_size = 0
    try:
        raw_size = await loop.run_in_executor(None, os.path.getsize, raw_path)
    except OSError:
        pass

    log_head += (
        f"\nRaw disk image written to {os.path.relpath(raw_path, output_base_dir)} "
        f"({raw_size:,} bytes).\n"
        "Use the windows_storage MCP tools (Phase α.4): `list_vhdx_partitions`, "
        "`mount_vhdx_readonly`, `scan_ntfs_alternate_data_streams`. NTFS "
        "reparse-point resolution is sandboxed in mount_vhdx_readonly per "
        "the Phase α.6 Rule #1 escalation (Persona-E #29) — every reparse "
        "target is realpath-walked against the extraction sandbox before "
        "serving any file.\n"
    )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.extracted_path = extraction_dir
    result.extraction_dir = extraction_dir
    result.unpack_log = log_head + "\nVHDX extraction complete via qemu-img convert.\n"
    await _report("Extraction complete", 100)
    return result
