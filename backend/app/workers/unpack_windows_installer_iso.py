"""Windows installer ISO recursive unpack worker.

Composes the ISO 9660 (:func:`unpack_iso9660`) and WIM
(:func:`unpack_wim`) handlers to produce a fully-expanded view of a
Windows installer / WinPE / recovery-USB ISO. The detection layer
flags an ISO as :data:`DetectedFormat.WINDOWS_INSTALLER_ISO` when
``bootmgr`` + ``sources/boot.wim`` (and friends) are present in the
ISO head zone — see ``format_detection.detect_format`` lines 215-232.

Output layout::

    <output_base_dir>/extracted/                              ← ISO 9660 contents
    <output_base_dir>/extracted/sources/install.wim_extracted/ ← if present
    <output_base_dir>/extracted/sources/boot.wim_extracted/    ← if present

The most useful root for downstream analysis is the ``install.wim``'s
``Windows/`` tree (the actual OS image); falls back to the ``boot.wim``
tree (WinPE only — no full OS), then the ISO 9660 root if neither WIM
is found. ``result.extracted_path`` is set to that root; sibling
extraction trees are still discoverable via
:func:`firmware_paths.get_detection_roots` per Rule #16, and the
unpack_log records the inner extraction count.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_INSTALLER_ISO] = unpack_windows_installer_iso

Failure modes:
- ISO 9660 outer extraction fails → propagate the failure unchanged.
- ISO extraction succeeds but no WIM payloads found → still success;
  unpack_log notes "No inner WIM/ESD payloads detected" — a
  legitimate state for non-installer Windows ISOs (e.g. driver-only
  recovery media).
- Per-WIM extraction fails → degrade to PARTIAL: the ISO content is
  intact (success=True), the per-WIM failure is recorded in unpack_log
  so the operator can pull the WIM manually with 7z if needed.

Why composition (not a single 7z call): 7z can crack ISOs and read
WIM streams individually, but its WIM support is read-only and lossy
on Unix metadata (symlinks, perms). Routing the inner WIM through the
canonical wimlib handler preserves ``--unix-data`` semantics and
matches the contract Phase 2 handler 2 already validates.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

from app.workers.unpack_common import UnpackResult
from app.workers.unpack_iso9660 import unpack_iso9660
from app.workers.unpack_wim import unpack_wim

logger = logging.getLogger(__name__)


# Inner WIM filenames the recursive handler looks for. The Windows
# installer always ships ``sources/boot.wim``; ``install.wim`` is the
# actual OS image (not present on WinPE-only or driver-recovery ISOs).
# ``install.esd`` is the encrypted/highly-compressed variant
# (Electronic Software Download) — wimlib-imagex handles ESD via the
# same ``apply`` semantics, so we treat the two extensions uniformly.
_INNER_WIM_CANONICAL_PATHS: tuple[str, ...] = (
    "sources/install.wim",
    "sources/install.esd",
    "sources/boot.wim",
    "sources/boot.esd",
)

# Extensions used by the recursive os.walk fallback when canonical
# paths miss (vendor recovery USBs sometimes drop WIMs in /recovery/,
# /winpe/, /WIM/, etc.).
_INNER_WIM_EXTENSIONS: tuple[str, ...] = (".wim", ".esd")


async def unpack_windows_installer_iso(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,
) -> UnpackResult:
    """Recursively extract a Windows installer ISO and any inner WIM payloads.

    Steps:
        1. Run :func:`unpack_iso9660` on the outer ISO. If it fails,
           propagate the failure unchanged.
        2. Walk the extracted tree for inner WIM/ESD files at canonical
           paths first (sources/install.wim, sources/boot.wim, …),
           then a recursive scan for non-canonical layouts.
        3. For each inner WIM, invoke :func:`unpack_wim` in-place;
           log per-payload success/failure into the composite
           ``unpack_log``.
        4. Pick the most useful ``extracted_path``: install.wim's
           Windows/ root if present, else install.{wim,esd}, else
           boot.wim's root, else the ISO root.
        5. Record sibling extraction dirs in unpack_log so operators
           and downstream :func:`get_detection_roots` see the full set.
    """
    async def _report(stage: str, progress: int) -> None:
        if progress_callback:
            try:
                await progress_callback(stage, progress)
            except Exception:
                pass

    # ── Step 1: outer ISO 9660 extraction (delegate to handler 1) ──
    await _report("Extracting outer ISO 9660", 5)
    iso_result = await unpack_iso9660(
        firmware_path,
        output_base_dir,
        progress_callback=None,  # composite handler owns top-level progress
        firmware_id=firmware_id,
    )

    if not iso_result.success:
        # Outer ISO failure — bail with the iso_result as-is so the
        # caller sees the real 7z error rather than a wrapped variant.
        return iso_result

    extraction_dir = iso_result.extraction_dir or os.path.join(output_base_dir, "extracted")
    log_lines: list[str] = [
        iso_result.unpack_log or "",
        "",
        "=== Inner WIM payload pass ===",
    ]
    inner_extracted_paths: list[str] = []

    # ── Step 2: scan for inner WIM/ESD files ──
    loop = asyncio.get_running_loop()
    candidates = await loop.run_in_executor(
        None, _find_inner_wim_candidates, extraction_dir,
    )

    if not candidates:
        log_lines.append("No inner WIM/ESD payloads detected.")
        log_lines.append(
            "Browse the ISO contents directly for installer assets, "
            "boot loaders, and manifests.",
        )
        iso_result.unpack_log = "\n".join(log_lines)
        await _report("Recursive Windows installer extraction complete", 100)
        return iso_result

    log_lines.append(f"Detected {len(candidates)} inner WIM/ESD payload(s):")
    for c in candidates:
        log_lines.append(f"  - {os.path.relpath(c, extraction_dir)}")  # noqa: ASYNC240 — pure-string path math; no filesystem I/O

    # ── Step 3: extract each inner WIM in-place ──
    # Reserve 80% of the progress range for WIM expansion (10..90%).
    progress_per_wim = 80.0 / max(len(candidates), 1)
    for idx, wim_path in enumerate(candidates):
        rel = os.path.relpath(wim_path, extraction_dir)  # noqa: ASYNC240 — pure-string path math; no filesystem I/O
        await _report(
            f"Expanding inner WIM: {rel}",
            int(10 + progress_per_wim * idx),
        )

        # Layout: <wim_path>_extracted/ (sibling beside the .wim).
        # E.g. .../sources/install.wim → .../sources/install.wim_extracted/
        #
        # unpack_wim expects an output_base_dir and creates extracted/
        # inside it. We pass a temporary base, then move/rename to the
        # canonical layout for predictable downstream paths.
        wim_output_dir = wim_path + "_extracted"
        wim_base_dir = wim_path + "_unpack_base"
        await loop.run_in_executor(None, _ensure_dir, wim_base_dir)

        wim_result = await unpack_wim(
            wim_path,
            wim_base_dir,
            progress_callback=None,
            firmware_id=firmware_id,
        )

        if wim_result.success:
            inner_dir = os.path.join(wim_base_dir, "extracted")
            if await loop.run_in_executor(None, os.path.isdir, inner_dir):
                # Replace any prior <wim>_extracted/ from a partial run.
                if await loop.run_in_executor(None, os.path.exists, wim_output_dir):
                    await loop.run_in_executor(
                        None, lambda: shutil.rmtree(wim_output_dir, ignore_errors=True),
                    )
                await loop.run_in_executor(None, os.rename, inner_dir, wim_output_dir)
                # The wim_base_dir is empty after the rename — clean up.
                try:
                    await loop.run_in_executor(None, os.rmdir, wim_base_dir)
                except OSError:
                    pass

                inner_extracted_paths.append(wim_output_dir)
                file_count = await loop.run_in_executor(
                    None, _count_files, wim_output_dir,
                )
                log_lines.append(
                    f"  [OK] {rel} -> {os.path.basename(wim_output_dir)}/ "
                    f"({file_count} file(s))"
                )
            else:
                log_lines.append(
                    f"  [WARN] {rel} extraction reported success but no "
                    "extracted/ directory was produced — skipping."
                )
                await _safe_rmdir(loop, wim_base_dir)
        else:
            log_lines.append(
                f"  [FAIL] {rel} extraction failed: "
                f"{(wim_result.error or 'unknown error')[:200]}"
            )
            await _safe_rmdir(loop, wim_base_dir)

    # ── Step 4: pick the most useful extracted_path ──
    composite_extracted_path = _pick_preferred_root(
        inner_extracted_paths, fallback=iso_result.extracted_path or extraction_dir,
    )

    # ── Step 5: build composite result ──
    composite = UnpackResult()
    composite.success = True
    composite.extracted_path = composite_extracted_path
    composite.extraction_dir = extraction_dir
    composite.architecture = iso_result.architecture
    composite.endianness = iso_result.endianness
    composite.os_info = iso_result.os_info or "Windows installer ISO"
    composite.kernel_path = iso_result.kernel_path

    if inner_extracted_paths:
        log_lines.append("")
        log_lines.append(
            f"Inner extraction roots: {len(inner_extracted_paths)} sibling "
            "tree(s) under sources/ — discoverable via "
            "get_detection_roots() per Rule #16."
        )
    log_lines.append("")
    log_lines.append("Recursive Windows installer ISO extraction complete.")
    composite.unpack_log = "\n".join(log_lines)

    await _report("Recursive Windows installer extraction complete", 100)
    return composite


# ---------------------------------------------------------------------------
# Sync helpers — wrapped in run_in_executor by callers (Rule #5).
# ---------------------------------------------------------------------------

def _find_inner_wim_candidates(extraction_dir: str) -> list[str]:
    """Walk ``extraction_dir`` for inner WIM/ESD payloads.

    Checks canonical installer paths first
    (``sources/install.wim``, ``sources/install.esd``,
    ``sources/boot.wim``, ``sources/boot.esd``); if none exist, falls
    back to a recursive walk for non-standard layouts (vendor recovery
    USBs sometimes drop WIMs in ``/recovery/``, ``/winpe/``, etc.).

    Returns a list of absolute paths in canonical-then-discovery order.
    """
    candidates: list[str] = []

    # 1. Canonical paths.
    for canonical in _INNER_WIM_CANONICAL_PATHS:
        full = os.path.join(extraction_dir, canonical)
        if os.path.isfile(full):
            candidates.append(full)

    # 2. Recursive scan for non-canonical layouts. Only run when the
    #    canonical pass found nothing — avoids double-listing canonical
    #    payloads in the candidate list.
    if not candidates:
        seen: set[str] = set()
        for root, _dirs, files in os.walk(extraction_dir):
            for fname in files:
                low = fname.lower()
                if low.endswith(_INNER_WIM_EXTENSIONS):
                    full = os.path.join(root, fname)
                    if full not in seen:
                        candidates.append(full)
                        seen.add(full)

    return candidates


def _pick_preferred_root(
    inner_extracted_paths: list[str], *, fallback: str,
) -> str:
    """Pick the most useful extracted_path from the inner trees.

    Preference order:
        1. ``install.wim`` extraction with a ``Windows/`` subdir (the
           actual OS image with a recognisable Windows layout).
        2. Any ``install.wim`` / ``install.esd`` extraction (Windows/
           subdir absent — vendor-customised installer).
        3. Any ``boot.wim`` / ``boot.esd`` extraction (WinPE-only ISO).
        4. ``fallback`` (the ISO root).
    """
    # Tier 1: install.wim with Windows/ subdir.
    for inner in inner_extracted_paths:
        low = inner.lower()
        if ("install.wim" in low or "install.esd" in low) and os.path.isdir(
            os.path.join(inner, "Windows"),
        ):
            return inner

    # Tier 2: any install.{wim,esd}.
    for inner in inner_extracted_paths:
        low = inner.lower()
        if "install.wim" in low or "install.esd" in low:
            return inner

    # Tier 3: any boot.{wim,esd}.
    for inner in inner_extracted_paths:
        low = inner.lower()
        if "boot.wim" in low or "boot.esd" in low:
            return inner

    # Tier 4: fallback (ISO root).
    return fallback


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _count_files(path: str) -> int:
    """Best-effort file count for unpack_log diagnostics. Never raises."""
    count = 0
    try:
        for _root, _dirs, files in os.walk(path):
            count += len(files)
    except OSError:
        pass
    return count


async def _safe_rmdir(loop: asyncio.AbstractEventLoop, path: str) -> None:
    """Best-effort cleanup for an empty wim_base_dir. Never raises."""
    try:
        await loop.run_in_executor(None, os.rmdir, path)
    except OSError:
        # Non-empty (extraction wrote something then failed) or
        # already gone. Leave it; caller's log already records the
        # failure context.
        pass
