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
import uuid
from pathlib import Path

from app.services.format_detection import (
    CAPABILITY_NOTES,
    detect_format,
)
from app.workers.unpack_common import UnpackResult

logger = logging.getLogger(__name__)


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
    if progress_callback:
        try:
            await progress_callback(f"No handler for {fmt.value}", 100)
        except Exception:
            pass

    result = UnpackResult()
    result.success = False
    result.error = f"No extraction handler available for {fmt.value}."
    result.unpack_log = (
        f"Detected format: {fmt.value}\n"
        f"{note}\n"
    )
    logger.info(
        "unpack_no_handler: firmware=%s format=%s — failing cleanly with workaround note",
        firmware_id,
        fmt.value,
    )
    return result
