"""MSI (Microsoft Installer) unpack worker via msiextract.

MSI is an OLE2 compound document (CFB) with structured tables (Property,
File, CustomAction, Registry, ServiceInstall, Binary, etc.) and an
embedded compressed file payload. ``msiextract`` (apt: ``msitools``)
walks the File table and writes each installable file to disk in the
directory layout declared by the MSI's Directory table.

Phase α handler 2 — extracts the user-visible installable payload.
The MCP tool category ``windows_archive`` (Phase α.4) reads tables and
the Binary stream (custom actions) directly from the ORIGINAL .msi via
``msiinfo`` / ``msidump`` on demand — no need for the worker to dump
tables eagerly into the extraction tree.

**Custom-action discipline** (Persona E anti-pattern #3, Phase β CLAUDE.md
Rule #36 candidate): the worker NEVER executes custom actions. ``msiextract``
is a pure file extractor; it does not invoke the embedded Windows Installer
engine. The downstream ``dump_msi_custom_actions`` MCP tool is dump-only —
it extracts the bytes of the Binary table for analysis but never runs them.
A custom-action PE inside an MSI is just another file the operator can
analyse with the existing ``binary`` tool category.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_MSI] = unpack_msi

Why msitools (not 7-zip): 7-zip can crack open the OLE2 compound document
and dump every stream as raw bytes, but it does NOT walk the File table,
which means the operator gets ``_StringPool`` / ``_StringData`` / ``Tables``
streams instead of the actual installable file tree. msiextract uses libmsi
to interpret the tables and produces the user-visible filesystem layout.
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


# msiextract timeout. MSIs are usually under 100 MB and extract in seconds;
# 5 min is a generous cap for vendor-IoT MSIs that can reach 500+ MB
# (medical device manager installers, vehicle infotainment).
# Aligned with radare2-tier (150_000 ms × safety margin) per Rule #29.
_MSIEXTRACT_TIMEOUT_SECONDS = 300

# msiinfo suminfo — cheap probe for "is this a readable MSI". Returns the
# Summary Information stream (~30 fields, very small).
_MSIINFO_TIMEOUT_SECONDS = 30

# msiextract returns 0 on success. msitools/msiextract source confirms
# no warnings tier.
_MSIEXTRACT_OK_RETURN_CODES = (0,)


async def unpack_msi(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature
) -> UnpackResult:
    """Extract an MSI's installable file payload via msiextract.

    Steps:
        1. Prep extraction_dir.
        2. Disk-space check — MSIs typically inflate 2x; require 3x headroom.
        3. ``msiinfo suminfo <msi>`` — validate readability + capture summary.
        4. ``msiextract --directory=<extraction_dir> <msi>`` — extract files.
        5. Post-extraction: filesystem-root detection (rare; usually a
           Windows-style ProgramFiles64Folder/<vendor>/<product>/ tree),
           bomb-check, widen perms.

    Failure modes:
        - msiinfo / msiextract not installed → install hint.
        - suminfo fails (corrupt MSI) → "MSI archive unreadable".
        - msiextract non-zero exit → exit code + stderr.
        - timeout → "msiextract timed out after 300s".
        - empty extraction (zero files) → still success (some MSIs are
          pure-action / pure-registry installers with no File table rows).
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

    # Disk-space check.
    loop = asyncio.get_running_loop()
    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
        free = await loop.run_in_executor(
            None, lambda: shutil.disk_usage(extraction_dir).free,
        )
        if free < fw_size * 3:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 3 // (1024 * 1024)} MB for MSI extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass

    # ---- Step 1: msiinfo suminfo — validate + capture summary ----
    await _report("Inspecting MSI archive", 5)

    suminfo_cmd = ["msiinfo", "suminfo", firmware_path]
    try:
        suminfo_proc = await asyncio.create_subprocess_exec(
            *suminfo_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "msiinfo binary missing — install msitools"
        result.unpack_log = (
            f"{result.error}\n"
            "MSI extraction requires the `msiinfo` and `msiextract` CLIs "
            "from the `msitools` apt package. Phase α.6 ships this — "
            "rebuild backend + worker with the Phase α.6 Dockerfile delta.\n"
        )
        return result

    try:
        suminfo_stdout_b, suminfo_stderr_b = await asyncio.wait_for(
            suminfo_proc.communicate(),
            timeout=_MSIINFO_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        suminfo_proc.kill()
        try:
            await suminfo_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"msiinfo suminfo timed out after {_MSIINFO_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    suminfo_stdout = (suminfo_stdout_b or b"").decode(errors="replace")
    suminfo_stderr = (suminfo_stderr_b or b"").decode(errors="replace")
    suminfo_rc = suminfo_proc.returncode

    if suminfo_rc != 0:
        result.error = f"MSI archive unreadable (suminfo exit={suminfo_rc})"
        result.unpack_log = (
            f"msiinfo suminfo exit={suminfo_rc}\n"
            f"stderr (last 2KB):\n{suminfo_stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"msiinfo suminfo exit=0\n"
        f"summary stream (first 2KB):\n{suminfo_stdout[:2000]}\n"
    )

    # ---- Step 2: msiextract --directory=<dir> <msi> ----
    await _report("Extracting MSI via msiextract", 10)

    extract_cmd = [
        "msiextract",
        "--directory", extraction_dir,
        firmware_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *extract_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        # msiinfo succeeded but msiextract is missing — partial msitools
        # install (rare; suggests a manually-edited Dockerfile).
        result.error = "msiextract binary missing — install msitools"
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "msiinfo found but msiextract not on PATH; reinstall msitools.\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_MSIEXTRACT_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"msiextract timed out after {_MSIEXTRACT_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = log_head + result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"msiextract exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _MSIEXTRACT_OK_RETURN_CODES:
        result.error = (
            f"msiextract failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 3: post-extraction analysis ----
    await _report("Analysing extracted MSI tree", 70)

    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for MSI extraction: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)

    if fs_root:
        # Rare — an MSI carrying a Linux rootfs (vendor-cross-platform package).
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
    else:
        # Typical MSI: ProgramFilesFolder/<vendor>/<product>/ tree, or empty
        # for action-only / registry-only installers.
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "MSI extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for Windows-style payloads "
            "(typically ProgramFiles*/<vendor>/<product>/ trees). "
            "Use the windows_archive MCP tools to inspect tables, "
            "custom actions, registry changes, and service installs "
            "directly from the original .msi file.\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + "MSI extraction complete via msiextract.\n"
    await _report("Extraction complete", 100)
    return result
