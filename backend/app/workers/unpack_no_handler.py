"""Sentinel worker for formats wairz detects but cannot yet extract.

Returns an :class:`UnpackResult` with ``success=False``, ``error`` set to a
clear operator-facing message, and ``unpack_log`` carrying the workaround
text from :data:`format_detection.CAPABILITY_NOTES`. The router's background
runner treats this as a normal extraction failure (``project.status='error'``,
``firmware.unpack_stage=None``) so the existing 202+polling Rule #33 state
machine handles it without modification.

Why a separate worker (not a special-case in :mod:`extraction_pipeline`):

- Strategy callables share a uniform signature
  ``(firmware_path, output_base_dir, progress_callback, firmware_id)``.
  Branching at the dispatcher would force the dispatcher to know about the
  no-handler case, polluting the dispatch logic.
- Future no-handler entries can carry per-format diagnostics (e.g. parse a
  ``.tibx`` header to extract version metadata even when we can't extract
  content) without touching the dispatcher.

Phase 1 routes ACRONIS_BACKUP, QNX_IFS, and WIM_ARCHIVE here. Phase 2
handlers replace the registry entry with a real worker as each ships.
"""

from __future__ import annotations

import logging
import os
import uuid
from pathlib import Path

from app.services.format_detection import (
    CAPABILITY_NOTES,
    DetectedFormat,
    detect_format,
)
from app.workers.unpack_common import UnpackResult

logger = logging.getLogger(__name__)


def _classify_tibx_slice(firmware_path: str) -> str | None:
    """Return a per-file-class diagnostic when the firmware is a .tibx slice.

    Per Acronis KB 64744, multi-slice backups carry a naming convention:
    ``Archive(N).tibx`` is the master (contains metadata + index);
    ``Archive(N)-NNNN.tibx`` are continuation slices that hold payload
    bytes but are NOT extractable standalone (the dedup index lives in
    the master). The 2026-05-13 deep-research surfaced an observable
    distinguisher in the head bytes: master files start
    ``41 01 00 00 02 4c 52 ea "ARCH"...`` while continuations start
    ``41 ff 00 00 ...`` (no ARCH marker). Use both signals — filename
    pattern + magic — to emit operator-actionable guidance.
    """
    name = os.path.basename(firmware_path).lower()
    if not (name.endswith(".tibx") or name.endswith(".tib")):
        return None
    # Continuation files match -NNNN.tibx (4-digit slice index).
    is_continuation_by_name = any(
        name.endswith(f"-{i:04d}.tibx") for i in range(0, 10000)
    )
    is_master_by_magic = False
    try:
        with open(firmware_path, "rb") as fh:
            head = fh.read(16)
        is_master_by_magic = len(head) >= 12 and head[8:12] == b"ARCH"
    except OSError:
        pass

    if is_master_by_magic:
        return (
            "tibx master slice — start here when running the operator "
            "extraction workflow (``tibxread get content --arc <this "
            "file>``). The master carries the dedup index + metadata; "
            "continuation slices alone are not extractable."
        )
    if is_continuation_by_name:
        return (
            "tibx continuation slice — this file holds payload bytes "
            "but is NOT extractable standalone. Locate the corresponding "
            "Archive(N).tibx (master, same directory, no slice suffix) "
            "and run the extraction workflow against the master; the "
            "Acronis extractor pulls payload from all continuation "
            "slices alongside the master automatically."
        )
    return (
        "tibx file detected but slice-class is ambiguous (neither master "
        "ARCH magic nor -NNNN naming pattern). Operator should verify "
        "with ``head -c 16 <file> | xxd`` — master starts with ``41 01`` "
        "+ ``ARCH`` at offset 8."
    )


async def unpack_no_handler(
    firmware_path: str,
    output_base_dir: str,  # noqa: ARG001 — uniform signature with unpack_firmware
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,
) -> UnpackResult:
    """Mark a format as detected-but-not-yet-extractable.

    Re-runs :func:`detect_format` so the failure message names the actual
    detected format. The strategy was selected based on the persisted
    ``firmware.detected_format`` column, but the user-facing message should
    always reflect the file's true content (the column may be stale or
    null for older rows).
    """
    fmt = detect_format(Path(firmware_path))
    note = CAPABILITY_NOTES.get(fmt) or (
        f"No extraction handler is registered for {fmt.value}."
    )

    # Append per-slice diagnostic for tibx — distinguishes master vs
    # continuation so the operator knows which file to feed tibxread.
    extra_lines: list[str] = []
    if fmt == DetectedFormat.ACRONIS_BACKUP:
        slice_note = _classify_tibx_slice(firmware_path)
        if slice_note:
            extra_lines.append(slice_note)

    if progress_callback:
        try:
            await progress_callback(f"No handler for {fmt.value}", 100)
        except Exception:
            pass

    result = UnpackResult()
    result.success = False
    result.error = f"No extraction handler available for {fmt.value}."
    log_parts = [f"Detected format: {fmt.value}", note]
    log_parts.extend(extra_lines)
    result.unpack_log = "\n".join(log_parts) + "\n"
    logger.info(
        "unpack_no_handler: firmware=%s format=%s — failing cleanly with workaround note",
        firmware_id,
        fmt.value,
    )
    return result
