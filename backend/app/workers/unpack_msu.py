"""MSU (Microsoft Update Standalone Package) unpack worker.

MSU is a CAB-of-CABs: an outer ``*.msu`` (CAB-shaped) contains XML
metadata + 1-3 inner CABs (typically ``Windows10.0-KB.cab`` for the
binary payload + ``WSUSSCAN.cab`` for offline-scan metadata) + zero or
more ``*.psf`` Patch Storage Files (Express install deltas).

Phase α handler 4 — extracts outer CAB, recursively extracts inner
CABs one level deep, detects PSF presence and surfaces it in the log.
Inner-CAB recursion is the key behaviour: without it, the operator
sees opaque ``Windows10.0-KB.cab`` files, not the actual servicing
payload.

PSF deltas are detected but NOT extracted by the Phase α worker — that
requires PSFExtractor which is gated behind ``ARG INCLUDE_PSF=1`` in
Phase α.6 due to upstream license-unclear status. When the gate is
active and the unpack_psf worker is wired, this worker can chain
``unpack_psf`` (Phase α.5).

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_MSU] = unpack_msu

Composing on top of the cabextract foundation rather than calling
``unpack_cab`` directly because the recursion semantics differ — the
inner CABs share the outer extraction dir layout, and we don't want
each inner extraction to re-run filesystem-root detection /
widen-perms / bomb-check separately.
"""
from __future__ import annotations

import asyncio
import glob
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


# Outer MSU/CAB extraction timeout. MSUs typically 10-500 MB; 5 min covers.
_MSU_OUTER_TIMEOUT_SECONDS = 300

# Inner CAB extraction timeout. Inner CABs can be the bulk of the MSU
# (e.g. cumulative updates with 200 MB inner CABs); 10 min generous.
_MSU_INNER_TIMEOUT_SECONDS = 600

# cabextract --list timeout (cheap probe).
_MSU_LIST_TIMEOUT_SECONDS = 30


async def _run_cabextract(
    src_cab: str, dest_dir: str, timeout_seconds: int,
) -> tuple[int, str, str]:
    """Run ``cabextract -d <dest_dir> -F '*' <src_cab>``.

    Returns ``(returncode, stdout, stderr)``. Special return-codes for
    failure modes the caller needs to distinguish:

        - ``(-1, "", "FileNotFoundError")`` — cabextract not on PATH.
        - ``(-2, "", "TimeoutError")`` — wait_for raised.

    Used internally by the outer + inner extraction passes; isolates
    the subprocess details so the orchestration logic stays clean.
    """
    cmd = ["cabextract", "-d", dest_dir, "-F", "*", src_cab]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return (-1, "", "FileNotFoundError")
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=timeout_seconds,
        )
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        return (-2, "", "TimeoutError")
    return (
        proc.returncode or 0,
        (stdout_b or b"").decode(errors="replace"),
        (stderr_b or b"").decode(errors="replace"),
    )


async def unpack_msu(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001
) -> UnpackResult:
    """Extract an MSU package end-to-end with one-level inner-CAB recursion.

    Steps:
        1. Prep extraction_dir.
        2. Disk-space check — MSU inflation 3x (outer + inner CABs both
           inflate ~2x, plus the file-payload size).
        3. Outer ``cabextract`` into ``extraction_dir``.
        4. Walk extraction_dir for ``*.cab`` files (inner CABs).
        5. For each inner CAB: ``cabextract`` into ``<inner>_extracted/``.
        6. Detect ``*.psf`` (Express delta) and surface in log.
        7. Detect KB metadata files (``*.xml`` — typically a single
           ``*update.mum`` or ``*.xml`` describing the rollup).
        8. find_filesystem_root + bomb-check + widen perms.

    Failure modes mirror unpack_cab; outer-cab failure aborts the whole
    extraction. Inner-cab failure logs a warning but doesn't fail the
    overall MSU (some inner CABs may be optional / WSUS-scan metadata).
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
        # MSU inflation up to 5x (outer 2x + inner 2x layered).
        if free < fw_size * 5:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 5 // (1024 * 1024)} MB for MSU extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        pass

    # ---- Step 1: outer cabextract ----
    await _report("Extracting outer MSU CAB", 5)

    rc, stdout, stderr = await _run_cabextract(
        firmware_path, extraction_dir, _MSU_OUTER_TIMEOUT_SECONDS,
    )

    if rc == -1:
        result.error = "cabextract binary missing — install cabextract"
        result.unpack_log = (
            f"{result.error}\n"
            "MSU extraction requires the `cabextract` CLI from the apt "
            "package `cabextract` (already in the backend Dockerfile). "
            "Rebuild backend + worker.\n"
        )
        return result

    if rc == -2:
        result.error = (
            f"outer cabextract timed out after {_MSU_OUTER_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = result.error
        return result

    if rc != 0:
        result.error = (
            f"MSU outer CAB extraction failed (exit={rc}): {stderr[-500:]}"
        )
        result.unpack_log = (
            f"outer cabextract exit={rc}\n"
            f"stderr (last 2KB):\n{stderr[-2000:]}\n"
            f"{result.error}\n"
        )
        return result

    log_head = (
        f"outer cabextract exit=0\n"
        f"outer stdout (last 2KB):\n{stdout[-2000:]}\n"
    )

    # ---- Step 2: find inner *.cab files ----
    await _report("Discovering inner MSU CABs", 30)

    def _walk_for_cabs(root: str) -> list[str]:
        return sorted(
            glob.glob(os.path.join(root, "**", "*.cab"), recursive=True)
            + glob.glob(os.path.join(root, "**", "*.CAB"), recursive=True),
        )

    inner_cabs = await loop.run_in_executor(None, _walk_for_cabs, extraction_dir)
    log_head += f"\nDiscovered {len(inner_cabs)} inner CAB file(s):\n"
    for ic in inner_cabs:
        log_head += f"  {os.path.relpath(ic, extraction_dir)}\n"

    # ---- Step 3: recurse one level ----
    inner_ok = 0
    inner_failed: list[tuple[str, int, str]] = []
    for idx, inner_cab in enumerate(inner_cabs):
        progress_pct = 30 + int(40 * (idx + 1) / max(len(inner_cabs), 1))
        await _report(
            f"Extracting inner CAB {idx + 1}/{len(inner_cabs)}", progress_pct,
        )
        inner_dir = inner_cab + "_extracted"
        try:
            os.makedirs(inner_dir, exist_ok=True)
        except OSError as exc:
            log_head += (
                f"  ! could not create inner dir {inner_dir}: {exc}\n"
            )
            inner_failed.append((inner_cab, -3, str(exc)))
            continue

        inner_rc, inner_stdout, inner_stderr = await _run_cabextract(
            inner_cab, inner_dir, _MSU_INNER_TIMEOUT_SECONDS,
        )
        if inner_rc == 0:
            inner_ok += 1
            log_head += (
                f"  ✓ {os.path.relpath(inner_cab, extraction_dir)} → "
                f"{os.path.relpath(inner_dir, extraction_dir)}/\n"
            )
        else:
            inner_failed.append((inner_cab, inner_rc, inner_stderr[-200:]))
            log_head += (
                f"  ! {os.path.relpath(inner_cab, extraction_dir)} "
                f"extraction failed (rc={inner_rc}): {inner_stderr[-200:]}\n"
            )

    log_head += (
        f"\nInner CAB extraction: {inner_ok}/{len(inner_cabs)} succeeded.\n"
    )
    if inner_failed:
        log_head += (
            f"({len(inner_failed)} inner CAB(s) failed — typically WSUSSCAN.cab "
            "metadata-only payloads; the primary update CAB usually succeeds.)\n"
        )

    # ---- Step 4: detect PSF (Express delta) ----
    await _report("Scanning for PSF deltas", 75)

    def _walk_for_psf(root: str) -> list[str]:
        return sorted(
            glob.glob(os.path.join(root, "**", "*.psf"), recursive=True)
            + glob.glob(os.path.join(root, "**", "*.PSF"), recursive=True),
        )

    psf_files = await loop.run_in_executor(None, _walk_for_psf, extraction_dir)
    if psf_files:
        log_head += (
            f"\nPSF (Patch Storage File / Express install delta) detected — "
            f"{len(psf_files)} file(s):\n"
        )
        for pf in psf_files:
            log_head += f"  {os.path.relpath(pf, extraction_dir)}\n"
        log_head += (
            "PSF deltas reconstruct full files via forward/reverse "
            "differentials. Phase α ships PSF support gated behind "
            "Dockerfile ARG INCLUDE_PSF=1; without it the operator "
            "sees the .psf bytes but not the reconstructed payload. "
            "Without PSF reconstruction, MSU coverage is ~20% (full-install "
            "replacements only); with it, ~95%.\n"
        )

    # ---- Step 5: detect KB / update metadata XMLs ----
    def _walk_for_xmls(root: str) -> list[str]:
        # Typical MSU metadata: *.mum / *update.xml / *.cat (catalog)
        candidates = []
        for pattern in ("*.xml", "*.mum", "*.cat"):
            candidates.extend(
                glob.glob(os.path.join(root, "**", pattern), recursive=True),
            )
        return sorted(set(candidates))

    metadata_files = await loop.run_in_executor(None, _walk_for_xmls, extraction_dir)
    if metadata_files:
        log_head += f"\nUpdate metadata files ({len(metadata_files)}):\n"
        for mf in metadata_files[:20]:  # cap log noise
            log_head += f"  {os.path.relpath(mf, extraction_dir)}\n"
        if len(metadata_files) > 20:
            log_head += f"  ... and {len(metadata_files) - 20} more.\n"

    # ---- Step 6: post-extraction analysis ----
    await _report("Analysing extracted MSU tree", 85)

    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"\nWidened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for MSU extraction: %s", exc)

    fs_root = await loop.run_in_executor(None, find_filesystem_root, extraction_dir)
    if fs_root:
        result.extracted_path = fs_root
        result.extraction_dir = extraction_dir
    else:
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "\nMSU extraction produced no Unix-style filesystem root. "
            "Browse the extraction tree for inner CABs (already recursed), "
            "PSF deltas, *.mum / *update.xml manifests, and *.cat catalogs. "
            "Use windows_update MCP tools (Phase β) to parse KB metadata "
            "and CBS/CSI/MUM manifests; use windows_pe_signature to validate "
            "catalogs against Microsoft Authenticode roots.\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    result.unpack_log = log_head + "\nMSU extraction complete (outer + inner CABs).\n"
    await _report("Extraction complete", 100)
    return result
