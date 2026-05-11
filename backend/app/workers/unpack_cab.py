"""CAB (Microsoft Cabinet) unpack worker via cabextract.

CAB is the cornerstone substrate of Windows servicing — MSU updates,
CBS cabinets, driver packages, and signed-installer payloads all wrap
their inner files in CAB. This Phase α handler 1 worker extracts a
top-level CAB end-to-end via ``cabextract`` (apt: ``cabextract``), the
canonical Linux-side reader.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_CAB] = unpack_cab

Why cabextract (not 7-zip): cabextract is the reference CAB reader,
handles MSZIP / Quantum / LZX compression and preserves filename
encoding correctly across the 1996+ CAB family. 7-zip is a fallback
for the rare CAB+LZMA2 variant that cabextract refuses (a 7-zip-only
extension; Persona-E anti-pattern #7). For Phase α we ship the cabextract
path and treat CAB+LZMA2 as a future enhancement (the silent-failure
risk is documented in unpack_log so operators can spot it).

Composing handlers (MSU = CAB-of-CABs, driver-package = CAB+INF+SYS+CAT)
delegate to this worker for the outer extraction step before doing
their format-specific introspection.
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
    reset_extraction_dir_sync,
    widen_read_perms,
)

logger = logging.getLogger(__name__)


# cabextract extraction timeout. Most CABs are sub-100MB and extract in
# under 30 s; 5 minutes is a generous cap for vendor driver CABs in the
# 200-500 MB range. Aligned with the radare2 frontend tier (150_000 ms ×
# safety margin) per Rule #29 — operators see synchronous completion.
_CABEXTRACT_TIMEOUT_SECONDS = 300

# cabextract --list (no extraction; just dump the central index). Cheap
# probe; 30 s is generous even for huge CABs.
_CABEXTRACT_INFO_TIMEOUT_SECONDS = 30

# cabextract returns 0 on success. Unlike 7-zip, there is no "warnings
# allowed" tier — any non-zero exit is a real failure. See cabextract(1).
_CABEXTRACT_OK_RETURN_CODES = (0,)


async def unpack_cab(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature with unpack_firmware
) -> UnpackResult:
    """Extract a CAB archive via cabextract and surface the resulting tree.

    Steps:
        1. Prep extraction_dir (clean any prior failed run).
        2. Disk-space check — CABs decompress 2-4x on LZX-compressed
           payloads; require 4x headroom.
        3. ``cabextract --list <cab>`` — validate readability + capture
           the file list for unpack_log.
        4. ``cabextract -d <extraction_dir> -F '*' <cab>`` — extract all.
        5. Post-extraction: filesystem-root detection (rare for CABs;
           typically Windows-flat or vendor-tree), bomb-check, widen perms.

    Failure modes (mirror unpack_wim.py shape):
        - cabextract not installed → ``result.error = "cabextract binary
          missing — install cabextract"`` with rebuild hint in unpack_log.
        - ``--list`` fails (rc != 0) → ``result.error = "CAB archive
          unreadable"`` + truncated stderr.
        - Extract non-zero exit → ``result.error`` carries exit code +
          truncated stderr.
        - Timeout on extract → ``result.error = "cabextract timed out
          after 300s"``.
        - No Unix-style filesystem root → still ``success=True`` with
          ``extracted_path = extraction_dir`` (CABs typically don't carry
          one; flat-payload trees are the norm).
    """
    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass

    result = UnpackResult()
    extraction_dir = os.path.join(output_base_dir, "extracted")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O

    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, reset_extraction_dir_sync, extraction_dir)
    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        # CAB inflation factor up to 4x on heavy LZX. Fail-fast rather
        # than fill the volume mid-extract.
        if free < fw_size * 4:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 4 // (1024 * 1024)} MB for CAB extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        # Best-effort; let cabextract fail cleanly downstream.
        pass

    # ---- Step 1: cabextract --list — validate + capture file list ----
    await _report("Inspecting CAB archive", 5)

    list_cmd = ["cabextract", "--list", firmware_path]
    try:
        list_proc = await asyncio.create_subprocess_exec(
            *list_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "cabextract binary missing — install cabextract"
        result.unpack_log = (
            f"{result.error}\n"
            "CAB extraction requires the `cabextract` CLI. The backend "
            "container ships with the `cabextract` package preinstalled; "
            "if you see this error, the container image is stale — rebuild "
            "with `docker compose up -d --build backend worker`.\n"
        )
        return result

    try:
        list_stdout_b, list_stderr_b = await asyncio.wait_for(
            list_proc.communicate(),
            timeout=_CABEXTRACT_INFO_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        list_proc.kill()
        try:
            await list_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"cabextract --list timed out after {_CABEXTRACT_INFO_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    list_stdout = (list_stdout_b or b"").decode(errors="replace")
    list_stderr = (list_stderr_b or b"").decode(errors="replace")
    list_rc = list_proc.returncode

    if list_rc != 0:
        result.error = f"CAB archive unreadable (--list exit={list_rc})"
        result.unpack_log = (
            f"cabextract --list exit={list_rc}\n"
            f"stderr (last 2KB):\n{list_stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"cabextract --list exit=0\n"
        f"file list (first 2KB):\n{list_stdout[:2000]}\n"
    )

    # ---- Step 2: cabextract -d <dir> -F '*' <cab> ----
    await _report("Extracting CAB via cabextract", 10)

    extract_cmd = [
        "cabextract",
        "-d", extraction_dir,
        "-F", "*",
        firmware_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *extract_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        # Defensive — list succeeded so cabextract was on PATH; if extract
        # suddenly can't find it, surface the same install hint.
        result.error = "cabextract binary missing — install cabextract"
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "cabextract --list succeeded but extract invocation could "
            "not find the binary; rebuild backend + worker.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_CABEXTRACT_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"cabextract timed out after {_CABEXTRACT_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = log_head + result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"cabextract exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _CABEXTRACT_OK_RETURN_CODES:
        result.error = (
            f"cabextract failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 3: post-extraction analysis ----
    await _report("Analysing extracted CAB tree", 70)

    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for CAB extraction: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)

    if fs_root:
        # Rare — a CAB carrying a Linux rootfs (e.g. a vendor-shipped
        # firmware-update CAB containing an OpenWrt overlay). Treat
        # exactly like other rootfs-discovering workers.
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
    else:
        # Typical CAB: flat *.dll/*.sys/*.inf or nested manifest XMLs.
        # Operator browses the extraction dir for Windows-style payloads.
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "CAB extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for Windows-style payloads "
            "(typically flat *.dll/*.sys/*.inf or nested manifest XMLs).\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + "CAB extraction complete via cabextract.\n"
    await _report("Extraction complete", 100)
    return result
