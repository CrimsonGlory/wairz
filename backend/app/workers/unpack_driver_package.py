"""Driver Package unpack worker — CAB + INF + SYS + CAT bundle.

A Windows driver package is a CAB containing a coordinated set:

- ``*.inf`` — driver info (PnP IDs, class GUID, services, file table)
- ``*.sys`` — kernel-mode driver binary (PE subsystem 1 — Native)
- ``*.cat`` — security catalog (PKCS#7 SignedData with file hashes)
- optional: ``*.dll`` (UMDF host / co-installers), ``*.exe``,
  ``*.ini``, vendor-specific resources

Phase α handler 6 — extracts the CAB via cabextract (already in worker
Dockerfile) and classifies the driver-package subtype based on file
presence. Subtypes (Persona-D #4 contradiction resolution):

- ``cab_inf_sys_cat`` — traditional 4-file driver package (most common)
- ``driver_store_dir`` — extracted DriverStore FileRepository layout
  (e.g. ``amd64_<inf>_<arch>_<hash>``, no outer CAB)
- ``dch`` — Declarative-Componentized-Hardware driver (Win10+;
  restricted dirs, ext-INF refs)
- ``msi_installer_driver`` — an MSI installing a driver (rare path
  routed via unpack_msi instead)

Specialisation (INF parsing, .cat hash validation, kernel-API
capability inference, attestation-vs-cross-signed signer tier) is
the ``windows_driver`` MCP category in Phase γ. The worker only
extracts and identifies the subtype.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_DRIVER_PACKAGE] = unpack_driver_package
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


_CABEXTRACT_TIMEOUT_SECONDS = 300
_CABEXTRACT_OK_RETURN_CODES = (0,)


async def unpack_driver_package(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001
) -> UnpackResult:
    """Extract a driver-package CAB and classify the subtype.

    Steps:
        1. Prep extraction_dir.
        2. Disk-space check — driver CABs inflate ~3x.
        3. ``cabextract`` into extraction_dir.
        4. Walk for ``*.inf`` / ``*.sys`` / ``*.cat`` / ``*.dll`` files.
        5. Classify subtype (cab_inf_sys_cat / dch / driver_store_dir).
        6. Surface counts + subtype + filenames in unpack_log.
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
        if free < fw_size * 3:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 3 // (1024 * 1024)} MB for driver-package extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass

    # ---- Step 1: cabextract ----
    await _report("Extracting driver-package CAB", 5)

    cmd = ["cabextract", "-d", extraction_dir, "-F", "*", firmware_path]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "cabextract binary missing — install cabextract"
        result.unpack_log = (
            f"{result.error}\n"
            "Driver-package extraction requires cabextract (already in "
            "the backend Dockerfile). Rebuild backend + worker.\n"
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
        result.unpack_log = result.error
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head = (
        f"cabextract exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _CABEXTRACT_OK_RETURN_CODES:
        result.error = (
            f"Driver-package CAB extraction failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = log_head + result.error
        return result

    # ---- Step 2: classify subtype + count component files ----
    await _report("Classifying driver-package subtype", 50)

    def _walk_extensions(root: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {
            "inf": [],
            "sys": [],
            "cat": [],
            "dll": [],
            "exe": [],
        }
        for r, _dirs, files in os.walk(root):
            for name in files:
                ext = os.path.splitext(name)[1].lower().lstrip(".")
                if ext in out:
                    out[ext].append(os.path.relpath(os.path.join(r, name), root))
        return out

    components = await loop.run_in_executor(
        None, _walk_extensions, extraction_dir,
    )

    n_inf = len(components["inf"])
    n_sys = len(components["sys"])
    n_cat = len(components["cat"])
    n_dll = len(components["dll"])

    # Subtype classification (Persona-D #4):
    # - cab_inf_sys_cat: at least 1 each of inf+sys+cat (canonical)
    # - dch: presence of "ext_*.inf" or "Vendor*.inf" with no .sys at top
    #        level (extensions reference primary driver elsewhere)
    # - driver_store_dir: presence of FileRepository-style nested dirs
    #        (amd64_<basename>.inf_<arch>_<hash>)
    # - cab_inf_only: INF-only package (rare; vendor drivers shipping
    #        only the INI-style metadata, expected to be paired with a
    #        separate SYS upload)
    if n_inf > 0 and n_sys > 0 and n_cat > 0:
        # Check DCH heuristic — DCH INFs reference EXT INFs via ExtensionId.
        is_dch = any(
            "ext_" in os.path.basename(p).lower()
            or "extension" in os.path.basename(p).lower()
            for p in components["inf"]
        )
        subtype = "dch" if is_dch else "cab_inf_sys_cat"
    elif n_inf > 0 and n_sys == 0:
        subtype = "cab_inf_only"
    elif n_inf == 0 and n_sys > 0:
        # SYS-only package (unusual; manual driver install scenario).
        subtype = "cab_sys_only"
    else:
        # Heuristic fallback: check for DriverStore-style nested dirs.
        try:
            top_entries = await loop.run_in_executor(
                None, lambda: sorted(os.listdir(extraction_dir)),
            )
            ds_pattern = any(
                "_" in e and (".inf_" in e or "_amd64_" in e or "_x86_" in e)
                for e in top_entries
            )
            subtype = "driver_store_dir" if ds_pattern else "unknown"
        except OSError:
            subtype = "unknown"

    log_head += (
        f"\nDriver-package subtype: {subtype}\n"
        f"  *.inf files ({n_inf}): "
        f"{components['inf'][:5]}{'...' if n_inf > 5 else ''}\n"
        f"  *.sys files ({n_sys}): "
        f"{components['sys'][:5]}{'...' if n_sys > 5 else ''}\n"
        f"  *.cat files ({n_cat}): "
        f"{components['cat'][:5]}{'...' if n_cat > 5 else ''}\n"
        f"  *.dll files ({n_dll}): "
        f"{components['dll'][:5]}{'...' if n_dll > 5 else ''}\n"
    )

    if subtype == "cab_inf_sys_cat":
        log_head += (
            "\nCanonical 4-file driver package detected. "
            "Use windows_driver MCP tools (Phase γ) to parse the INF, "
            "validate the .cat catalog hash chain against Microsoft "
            "Authenticode roots, and infer kernel-API capabilities "
            "from the .sys imports.\n"
        )
    elif subtype == "dch":
        log_head += (
            "\nDeclarative-Componentized-Hardware (DCH) driver detected. "
            "DCH drivers use EXT INF references to compose multiple "
            "INF files; primary INF + extension INFs are coordinated "
            "via ExtensionId in the Version section.\n"
        )

    # ---- Step 3: post-extraction analysis ----
    await _report("Analysing extracted driver-package tree", 75)

    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for driver-package: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)
    if fs_root:
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
    else:
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + (
        f"\nDriver-package extraction complete via cabextract "
        f"(subtype={subtype}).\n"
    )
    await _report("Extraction complete", 100)
    return result
