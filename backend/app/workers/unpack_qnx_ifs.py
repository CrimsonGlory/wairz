"""QNX IFS (Image File System) unpack worker via ifsdump.

QNX IFS is the firmware-image format used by automotive head units (BMW
HU NBT EVO, Audi MMI, Ford Sync 3 variants), some medical-imaging
consoles, and various industrial controllers. The format is documented
publicly via QNX's ``mount_ifs`` / ``mkifs`` / ``dumpifs`` user-facing
docs, but no byte-level spec is published — every open-source extractor
is the product of reverse-engineering work or a derivative of leaked
QNX SDP source.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.QNX_IFS] = unpack_qnx_ifs

License-aware tool selection: this worker wraps ``jtang613/qnx_dumpers``'s
``ifsdump`` (MIT, per-source-file headers; pinned at SHA
``c621029e3495f3881407d6487735d44155c75f98`` in ``backend/Dockerfile``).
Every other extractor with broader format coverage carries the
proprietary ``$QNXLicenseC$`` header verbatim and CANNOT be bundled in
a public Docker image. See
``.planning/knowledge/qnx-ifs-extraction-research-2026-05-07.md`` for
the full Decision Matrix and license-risk analysis.

Capability claim is **PARTIAL** rather than FULL because:

1. The pinned upstream tool has a small ecosystem (8 stars, single
   author, no public test corpus, no tagged releases) — format-coverage
   breadth is unverified against real-world IFS variants (HBCIFS-wrapped
   vehicle firmware, vendor-specific extensions, less-common QNX
   versions).
2. We ship a 2-phase ``--list`` then ``--extract`` invocation where the
   list step is a cheap probe; if the tool can't even read the IFS
   header, the worker degrades to a no_handler-like soft-fail rather
   than half-extracting and confusing the operator.
3. HBCIFS-wrapped vehicle firmware (BMW + Harman/Becker) is NOT handled
   by ifsdump alone. The fallback workaround in the failure path points
   the user at host-side QNX SDP ``dumpifs`` (Free Non-Commercial
   license, cannot be redistributed but legal to run on the host) for
   variants ifsdump doesn't cover.

Soft-fail discipline: on any non-zero exit (list or extract), the
worker returns ``success=False`` with ``error`` naming the failing
phase + exit code, ``unpack_log`` carrying the truncated stderr AND
the workaround pointer. Mirrors ``unpack_no_handler`` semantics so
the upstream router transitions ``project.status='error'`` and the
existing 202+polling state machine handles it without modification.

CLI flags verified at the pinned SHA against the upstream README:

    ifsdump --list <ifs>             # list contents (also default w/ no flags)
    ifsdump -d <dir> --extract <ifs> # extract all files into dir

Per Rule #6 (verify CLI flags before hardcoding) confirmed against
https://github.com/jtang613/qnx_dumpers/blob/master/README.md and the
in-container ``ifsdump -h`` output captured during the rebuild step.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

from app.services.format_detection import (
    CAPABILITY_NOTES,
    DetectedFormat,
)
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


# ifsdump --list timeout. Listing is a cheap header walk + directory
# enumeration; 30 s is generous and matches the WIM info ceiling.
_IFSDUMP_LIST_TIMEOUT_SECONDS = 30

# ifsdump --extract timeout. Decompression covers LZO + UCL + zlib
# blocks. 1 hour ceiling matches the WIM apply / ISO 7z ceilings.
_IFSDUMP_EXTRACT_TIMEOUT_SECONDS = 3600

# ifsdump exits 0 on success, non-zero on any failure (no separate
# "warnings" tier per upstream source inspection).
_IFSDUMP_OK_RETURN_CODES = (0,)

# Workaround pointer surfaced in the unpack_log when the handler
# soft-fails. Mirrors the spirit of CAPABILITY_NOTES[QNX_IFS] but
# re-stated here so the per-failure log is self-contained for
# operators who don't read the format-detection note.
_WORKAROUND_POINTER = (
    "For QNX IFS images that the bundled ifsdump cannot extract "
    "(notably HBCIFS-wrapped automotive firmware), use host-side "
    "QNX SDP `dumpifs` (Free Non-Commercial license: cannot be "
    "redistributed in container images but legal to install + run "
    "on the host) and re-upload the resulting filesystem as a tar "
    "archive."
)


async def unpack_qnx_ifs(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature with unpack_firmware
) -> UnpackResult:
    """Extract a QNX IFS image via ifsdump and analyse the resulting tree.

    Steps:
        1. Prep extraction_dir (clean any prior failed run).
        2. Disk-space check — IFS decompresses 2-3x; require ~3x headroom.
        3. ``ifsdump --list <ifs>`` (30s timeout) — validate readability,
           capture file inventory for ``unpack_log``.
        4. ``ifsdump -d <extraction_dir> --extract <ifs>`` (3600s timeout).
        5. Post-extraction: filesystem-root detection, architecture
           detection, OS-info detection — same shape as the monolith.
        6. Bomb-check via :func:`check_extraction_limits`.
        7. Widen read perms so the file-explorer API can read every file.

    Soft-fail modes (all return ``success=False`` with the workaround
    pointer in ``unpack_log``):
        - ``ifsdump`` not installed → ``error="ifsdump binary not
          available in container"``.
        - ``--list`` non-zero or timeout → ``error="QNX IFS extraction
          failed (list phase exit=N)"`` + truncated stderr.
        - ``--extract`` non-zero or timeout → ``error="QNX IFS
          extraction failed (extract phase exit=N)"`` + truncated stderr.

    Per Rule #29 every subprocess call carries an explicit timeout.
    Per Rule #5 every blocking filesystem operation runs in
    ``run_in_executor``.
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
        # IFS decompression typically inflates 2-3x. Require 3x for safe
        # headroom — better to fail fast than fill the volume mid-extract.
        if free < fw_size * 3:
            result.error = (
                f"Insufficient disk space: {free // (1024 * 1024)} MB free, "
                f"need ~{fw_size * 3 // (1024 * 1024)} MB for QNX IFS extraction"
            )
            result.unpack_log = result.error
            return result
    except OSError:
        # Best-effort; let ifsdump fail cleanly downstream if disk is short.
        pass

    # ---- Step 1: ifsdump --list — validate + capture file inventory ----
    await _report("Inspecting QNX IFS archive", 5)

    list_cmd = ["ifsdump", "--list", firmware_path]
    try:
        list_proc = await asyncio.create_subprocess_exec(
            *list_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        result.error = "ifsdump binary not available in container"
        result.unpack_log = (
            f"{result.error}\n"
            "QNX IFS extraction requires the `ifsdump` CLI from "
            "jtang613/qnx_dumpers. The backend container ships with it "
            "preinstalled at /usr/local/bin/ifsdump; if you see this "
            "error, the container image is stale — rebuild with "
            "`docker compose up -d --build backend worker`.\n"
            f"\n{_WORKAROUND_POINTER}\n"
        )
        return result

    try:
        list_stdout_b, list_stderr_b = await asyncio.wait_for(
            list_proc.communicate(), timeout=_IFSDUMP_LIST_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        list_proc.kill()
        try:
            await list_proc.communicate()
        except Exception:
            pass
        result.error = (
            f"ifsdump --list timed out after {_IFSDUMP_LIST_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = (
            f"{result.error}\n\n{_WORKAROUND_POINTER}\n"
        )
        return result

    list_stdout = (list_stdout_b or b"").decode(errors="replace")
    list_stderr = (list_stderr_b or b"").decode(errors="replace")
    list_rc = list_proc.returncode

    if list_rc not in _IFSDUMP_OK_RETURN_CODES:
        result.error = (
            f"QNX IFS extraction failed (list phase exit={list_rc})"
        )
        result.unpack_log = (
            f"ifsdump --list exit={list_rc}\n"
            f"stderr (last 2KB):\n{list_stderr[-2000:]}\n"
            f"{result.error}\n"
            f"\n{_WORKAROUND_POINTER}\n"
        )
        return result

    log_head = (
        f"ifsdump --list exit=0\n"
        f"file inventory (first 2KB):\n{list_stdout[:2000]}\n"
    )

    # ---- Step 2: ifsdump --extract ----
    await _report("Extracting QNX IFS via ifsdump", 10)

    extract_cmd = [
        "ifsdump",
        "-d", extraction_dir,
        "--extract",
        firmware_path,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *extract_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        # Defensive — list succeeded above so ifsdump was on PATH; if
        # extract suddenly can't find it, surface the same install hint.
        result.error = "ifsdump binary not available in container"
        result.unpack_log = log_head + (
            f"{result.error}\n"
            "ifsdump --extract could not be invoked despite --list "
            "succeeding. Rebuild backend + worker.\n"
            f"\n{_WORKAROUND_POINTER}\n"
        )
        return result

    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(), timeout=_IFSDUMP_EXTRACT_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        proc.kill()
        try:
            await proc.communicate()
        except Exception:
            pass
        result.error = (
            f"ifsdump --extract timed out after "
            f"{_IFSDUMP_EXTRACT_TIMEOUT_SECONDS}s"
        )
        result.unpack_log = (
            log_head + result.error + f"\n\n{_WORKAROUND_POINTER}\n"
        )
        return result

    stdout = (stdout_b or b"").decode(errors="replace")
    stderr = (stderr_b or b"").decode(errors="replace")
    rc = proc.returncode

    log_head += (
        f"ifsdump --extract exit={rc}\n"
        f"stdout (last 2KB):\n{stdout[-2000:]}\n"
        f"stderr (last 2KB):\n{stderr[-2000:]}\n"
    )

    if rc not in _IFSDUMP_OK_RETURN_CODES:
        result.error = (
            f"QNX IFS extraction failed (extract phase exit={rc}): "
            f"{stderr[-500:]}"
        )
        result.unpack_log = (
            log_head + result.error + f"\n\n{_WORKAROUND_POINTER}\n"
        )
        return result

    # ---- Step 3: post-extraction analysis (mirror unpack_wim) ----
    await _report("Analysing extracted filesystem", 70)

    # Widen read perms so the file-explorer can serve every file. IFS
    # often carries QNX-style permission bits (some files mode 0o000).
    try:
        widened = await loop.run_in_executor(None, widen_read_perms, extraction_dir)
        if widened:
            log_head += f"Widened read permissions on {widened} entries.\n"
    except Exception as exc:
        logger.debug("widen_read_perms failed for QNX IFS extraction: %s", exc)

    # Filesystem-root detection. QNX IFS images for embedded systems
    # typically carry a partial Unix-style layout (etc/, bin/, usr/) so
    # find_filesystem_root often locks on; vendor IFS variants may not.
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
        # No Unix-style rootfs (typical for vendor automotive IFS that
        # arranges files under proprietary path conventions). The
        # extraction is still useful — the file explorer surfaces every
        # file. Treat as success.
        result.extracted_path = extraction_dir
        result.extraction_dir = extraction_dir
        log_head += (
            "QNX IFS extraction produced no Unix-style filesystem root. "
            "Browse the extraction dir for vendor-specific layouts "
            "(automotive head-unit firmware often arranges files under "
            "proprietary partition names).\n"
        )

    bomb_error = await loop.run_in_executor(
        None, lambda: check_extraction_limits(extraction_dir, fw_size),
    )
    if bomb_error:
        log_head += f"\nWARNING: {bomb_error} — extraction kept.\n"

    result.success = True
    # Capability claim is PARTIAL — surface that to operators reading
    # the log so they understand why some IFS variants may not extract
    # cleanly even when ifsdump itself returned 0.
    qnx_note = CAPABILITY_NOTES.get(DetectedFormat.QNX_IFS, "")
    result.unpack_log = (
        log_head
        + "QNX IFS extraction complete via ifsdump (jtang613/qnx_dumpers).\n"
        + (f"\nCapability note: {qnx_note}\n" if qnx_note else "")
    )
    await _report("Extraction complete", 100)
    return result
