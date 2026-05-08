"""MSIX / AppX / MSIXBundle unpack worker via 7-zip.

MSIX is a ZIP container with three signal files at the root:
``AppxManifest.xml`` (package metadata, Capabilities, entry points),
``AppxBlockMap.xml`` (per-block SHA-256 integrity hashes), and an
``AppxSignature.p7x`` (Authenticode signature over the block map).
AppX is the Win8-era predecessor with the same shape; MSIXBundle is
a meta-package containing inner MSIX/AppX packages plus a top-level
``AppxBundleManifest.xml``.

Phase α handler 3 — extracts the ZIP envelope. Manifest parsing,
block-map validation, and signature verification are MCP tool jobs in
Phase α.4 (windows_archive) and Phase β (windows_pe_signature) — the
worker only surfaces the raw tree.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_MSIX] = unpack_msix

Why 7-zip (not Python zipfile): 7z handles ZIP64 + Unicode filenames +
AES-256-encrypted entries (not present in standard MSIX, but defensive),
and it's already in the worker Dockerfile via ``p7zip-full``. Mirrors
the precedent shape from ``unpack_iso9660.py``.

Block-map verification (Persona E #8): NOT done in the worker — that's
``verify_msix_blockmap`` in the windows_archive MCP category, which
re-hashes every block at request time so the operator can compare the
reported integrity status to the manifest's claims.
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

logger = logging.getLogger(__name__)


# 7z extraction timeout. MSIX packages are typically tens-to-hundreds of
# MB; 5 min covers the largest desktop-app MSIXBundle we expect.
_SEVEN_ZIP_TIMEOUT_SECONDS = 300

# 7z list — cheap probe; 30 s ample.
_SEVEN_ZIP_LIST_TIMEOUT_SECONDS = 30

# 7z returns 0 on success. Exit 1 = "warnings, content extracted" (e.g.
# checksum mismatch on individual entries). For MSIX we accept rc<=1
# but flag warnings in the unpack_log so operators can spot integrity
# concerns. Exit 2+ = real failure. See 7-zip exit-code matrix.
_SEVEN_ZIP_OK_RETURN_CODES = (0,)
_SEVEN_ZIP_WARN_RETURN_CODES = (1,)


# Signal files that must appear in any valid MSIX/AppX package. Used to
# validate the ZIP central directory matches the MSIX shape (cheap
# integrity gate before paying the extraction cost).
_MSIX_SIGNAL_FILES = (
    "AppxManifest.xml",        # Per-package manifest (MSIX, AppX)
    "AppxBundleManifest.xml",  # Bundle-level manifest (MSIXBundle, AppXBundle)
)


async def unpack_msix(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature
) -> UnpackResult:
    """Extract an MSIX / AppX / MSIXBundle via 7z.

    Steps:
        1. Prep extraction_dir.
        2. Disk-space check — MSIX inflation typically ~1.5x; require 2x headroom.
        3. ``7z l <msix>`` — validate readable + check for MSIX signal files
           (AppxManifest.xml or AppxBundleManifest.xml).
        4. ``7z x -o<extraction_dir> -y <msix>`` — extract.
        5. Post-extraction: filesystem-root detection, bomb-check, widen perms.

    Failure modes:
        - 7z not installed → install hint.
        - list rc != 0 → "MSIX archive unreadable".
        - no signal file in list → "Not an MSIX/AppX package".
        - extract rc>=2 → exit code + stderr.
        - timeout → "7z timed out after 300s".
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

    loop = asyncio.get_running_loop()
    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        # MSIX inflation ~1.5x typical; 2x headroom.
        if free < fw_size * 2:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 2 // (1024 * 1024)} MB for MSIX extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass

    # ---- Step 1: 7z l — list + validate MSIX shape ----
    await _report("Inspecting MSIX archive", 5)

    list_cmd = ["7z", "l", "-ba", firmware_path]
    try:
        list_proc = await asyncio.create_subprocess_exec(
            *list_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "7z binary missing — install p7zip-full"
        result.unpack_log = (
            f"{result.error}\n"
            "MSIX extraction requires the `7z` CLI from `p7zip-full` "
            "(already in the backend Dockerfile). Rebuild backend+worker.\n"
        )
        return result

    try:
        list_stdout_b, list_stderr_b = await asyncio.wait_for(
            list_proc.communicate(),
            timeout=_SEVEN_ZIP_LIST_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        list_proc.kill()
        try:
            await list_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"7z l timed out after {_SEVEN_ZIP_LIST_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    list_stdout = (list_stdout_b or b"").decode(errors="replace")
    list_stderr = (list_stderr_b or b"").decode(errors="replace")
    list_rc = list_proc.returncode

    if list_rc not in (*_SEVEN_ZIP_OK_RETURN_CODES, *_SEVEN_ZIP_WARN_RETURN_CODES):
        result.error = f"MSIX archive unreadable (7z l exit={list_rc})"
        result.unpack_log = (
            f"7z l exit={list_rc}\n"
            f"stderr (last 2KB):\n{list_stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"7z l exit={list_rc}\n"
        f"file list (first 2KB):\n{list_stdout[:2000]}\n"
    )

    # MSIX-shape sanity check: at least one signal file must be present.
    has_signal = any(signal in list_stdout for signal in _MSIX_SIGNAL_FILES)
    if not has_signal:
        result.error = (
            "Not an MSIX/AppX package — no AppxManifest.xml or "
            "AppxBundleManifest.xml in archive index"
        )
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "If this is an MSIX-shaped archive missing manifests, the "
            "vendor packaging is malformed. Re-detect via format_detection "
            "or upload as a generic ZIP.\n"
        )
        return result

    # ---- Step 2: 7z x -o<dir> -y <msix> ----
    await _report("Extracting MSIX via 7z", 10)

    extract_cmd = [
        "7z", "x",
        f"-o{extraction_dir}",
        "-y",   # assume yes on overwrite prompts (we cleaned the dir)
        firmware_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *extract_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "7z binary missing — install p7zip-full"
        result.unpack_log = log_head + (
            f"{result.error}\n7z l succeeded but x invocation could not "
            "find the binary; rebuild backend + worker.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_SEVEN_ZIP_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"7z x timed out after {_SEVEN_ZIP_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = log_head + result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"7z x exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc in _SEVEN_ZIP_OK_RETURN_CODES:
        log_head += "7z extraction completed cleanly.\n"
    elif rc in _SEVEN_ZIP_WARN_RETURN_CODES:
        log_head += (
            "7z extraction completed with warnings (rc=1) — review stderr "
            "for per-entry integrity concerns. Use the windows_archive "
            "verify_msix_blockmap MCP tool for authoritative integrity check.\n"
        )
    else:
        result.error = (
            f"7z extraction failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 3: post-extraction analysis ----
    await _report("Analysing extracted MSIX tree", 70)

    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for MSIX extraction: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)

    if fs_root:
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
    else:
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "MSIX extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for AppxManifest.xml, "
            "AppxBlockMap.xml, AppxSignature.p7x, and the payload tree. "
            "Use windows_archive MCP tools to read the manifest, list "
            "capabilities, and verify the block-map integrity.\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + "MSIX extraction complete via 7z.\n"
    await _report("Extraction complete", 100)
    return result
