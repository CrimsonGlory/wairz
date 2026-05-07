"""Strategy registry mapping :class:`DetectedFormat` → unpack worker callable.

Single source of truth for "which worker handles which format". Read by
:func:`app.services.extraction_pipeline.run_unpack`. When a Phase 2
handler ships, the worker module is added here in one line; no other
file needs editing except :data:`format_detection.EXTRACTION_CAPABILITY`
(the user-facing capability claim).

Contract for a strategy callable::

    async def strategy(
        firmware_path: str,
        output_base_dir: str,
        progress_callback: ProgressCallback | None = None,
        firmware_id: uuid.UUID | None = None,
    ) -> UnpackResult

Same signature as :func:`unpack_firmware` — the existing monolith IS the
default strategy for the formats unblob/binwalk already handle well.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TypeAlias

from app.services.format_detection import DetectedFormat
from app.workers.unpack import unpack_firmware
from app.workers.unpack_common import UnpackResult
from app.workers.unpack_iso9660 import unpack_iso9660
from app.workers.unpack_no_handler import unpack_no_handler
from app.workers.unpack_qnx_ifs import unpack_qnx_ifs
from app.workers.unpack_wim import unpack_wim
from app.workers.unpack_windows_installer_iso import unpack_windows_installer_iso

ProgressCallback: TypeAlias = Callable[[str, int], Awaitable[None]]
Strategy: TypeAlias = Callable[..., Awaitable[UnpackResult]]


# Default strategy for formats that the existing monolith handles via its
# built-in classify_firmware() fast paths + unblob/binwalk fallback.
_DEFAULT: Strategy = unpack_firmware


# Per-format strategy lookup. Phase 2 handlers REPLACE _DEFAULT for their
# format (e.g. DetectedFormat.WIM_ARCHIVE → unpack_wim) and REPLACE
# unpack_no_handler when an extractor lands.
#
# Aligned with services/format_detection.EXTRACTION_CAPABILITY: any
# format flagged FULL or PARTIAL routes to a real worker (currently
# the unpack_firmware monolith); any format flagged NONE routes to
# unpack_no_handler. UNKNOWN routes to the monolith so unblob has a
# chance to crack open files we don't classify (Rule #19 evidence-first
# discipline — let the extractor's heuristics speak before claiming we
# can't handle a thing).
STRATEGIES: dict[DetectedFormat, Strategy] = {
    DetectedFormat.LINUX_FIRMWARE_BLOB: _DEFAULT,
    DetectedFormat.ANDROID_APK: _DEFAULT,
    DetectedFormat.ANDROID_OTA: _DEFAULT,
    DetectedFormat.TAR_ARCHIVE: _DEFAULT,
    DetectedFormat.ZIP_ARCHIVE: _DEFAULT,
    DetectedFormat.PE_EXECUTABLE: _DEFAULT,           # existing pe_binary fast path
    DetectedFormat.ISO_9660: unpack_iso9660,          # Phase 2 handler 1 — 7z extraction (FULL)
    DetectedFormat.WIM_ARCHIVE: unpack_wim,           # Phase 2 handler 2 — wimlib-imagex (FULL)
    DetectedFormat.WINDOWS_INSTALLER_ISO: unpack_windows_installer_iso,  # Phase 2 handler 3 — recursive ISO+WIM (FULL)
    DetectedFormat.QNX_IFS: unpack_qnx_ifs,           # Phase 2 handler 5 — ifsdump (jtang613/qnx_dumpers, PARTIAL)
    DetectedFormat.UNKNOWN: _DEFAULT,                 # let unblob have a try
    DetectedFormat.ACRONIS_BACKUP: unpack_no_handler,
}


def get_strategy(fmt: DetectedFormat) -> Strategy:
    """Return the unpack worker for the given detected format.

    Falls back to the default strategy (the unpack_firmware monolith) for
    any format value not present in :data:`STRATEGIES`. This makes the
    registry forward-compatible: a new DetectedFormat enum value added
    without a registry entry won't crash the dispatcher — it will just
    take the default path until a real handler ships.
    """
    return STRATEGIES.get(fmt, _DEFAULT)
