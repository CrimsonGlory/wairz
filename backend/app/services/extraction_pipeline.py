"""Dispatch layer that routes firmware unpack to the right worker.

Read by both the arq path
(:func:`app.workers.arq_worker.unpack_firmware_job`) and the in-process
fallback path (:func:`app.routers.firmware._run_unpack_background`).
Consults ``firmware.detected_format`` → :data:`STRATEGIES` → returns the
worker callable; the caller awaits it.

Why a separate service file (not just a function in
:mod:`extraction_strategies`):

- The service layer owns the read of ``firmware.detected_format`` and the
  fallback to :func:`format_detection.detect_format` if the column is
  null (older rows pre-detection didn't get the pre-flight populated).
- The workers package keeps its single responsibility: actually
  unpacking. The dispatcher's job is *deciding which worker*.

Logging: every dispatch logs the resolved (detected_format, strategy)
pair so misroutes are observable post-hoc.
"""

from __future__ import annotations

import logging
import uuid
from pathlib import Path

from app.models.firmware import Firmware
from app.services.format_detection import DetectedFormat, detect_format
from app.workers.extraction_strategies import Strategy, get_strategy
from app.workers.unpack_common import UnpackResult

logger = logging.getLogger(__name__)


async def resolve_strategy(firmware: Firmware) -> tuple[DetectedFormat, Strategy]:
    """Resolve the unpack strategy for a firmware row.

    Trusts ``firmware.detected_format`` when the row was uploaded post-
    pre-flight detection; falls back to a fresh :func:`detect_format`
    call against the storage_path for older rows or when the column is
    None / unparseable.

    Returns a ``(format, strategy)`` tuple so callers can log/report the
    resolved format alongside the strategy name.
    """
    fmt: DetectedFormat
    raw = getattr(firmware, "detected_format", None)
    if raw:
        try:
            fmt = DetectedFormat(raw)
        except ValueError:
            logger.warning(
                "extraction_pipeline: unknown detected_format=%r on firmware %s; "
                "falling back to fresh detection",
                raw,
                firmware.id,
            )
            fmt = detect_format(Path(firmware.storage_path))
    else:
        fmt = detect_format(Path(firmware.storage_path))
    strategy = get_strategy(fmt)
    logger.info(
        "extraction_pipeline: firmware=%s detected_format=%s strategy=%s",
        firmware.id,
        fmt.value,
        strategy.__name__,
    )
    return fmt, strategy


async def run_unpack(
    firmware: Firmware,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,
) -> UnpackResult:
    """Dispatch the unpack to the right per-format worker.

    Mirrors :func:`unpack_firmware`'s signature, so call sites only
    change the function name (and the firmware-row argument). The
    chosen strategy is invoked with the same positional/keyword
    arguments the monolith expected.
    """
    _fmt, strategy = await resolve_strategy(firmware)
    return await strategy(
        firmware.storage_path,
        output_base_dir,
        progress_callback,
        firmware_id=firmware_id,
    )
