"""PSF (Patch Storage File) unpack worker — Phase α stub.

PSF is the Microsoft Express install delta format used by Win10+ for
incremental cumulative updates. Each PSF carries forward/reverse
differentials against a BASELINE file (the previous version of the
target binary). Standalone PSF extraction is meaningless without the
baseline — the format requires the original bytes to reconstruct.

Phase α stub responsibilities:
1. Validate PSF magic (``PA30`` / ``PA19`` / ``PA17``).
2. Preserve the upload path so the operator can browse the .psf file.
3. Surface a clear gating-aware operator message explaining the two
   prerequisites for full reconstruction:
     (a) A baseline file (the previous version of the target binary).
     (b) The gated psfextract toolchain — Phase α.6 Dockerfile
         ``ARG INCLUDE_PSF=1`` enables it.

Strategy registration::

    extraction_strategies.STRATEGIES[DetectedFormat.WINDOWS_PSF] = unpack_psf

Phase β / δ enhancement: when a baseline is available (e.g. from a
prior firmware upload or operator-provided previous version), the
``apply_psf_to_baseline`` MCP tool reconstructs the target. The
``identify_psf_baseline`` Phase α.4 MCP tool reads the PSF header to
extract the target binary's RSDS GUID — the operator can use that to
locate the baseline in another firmware upload or via Microsoft's
symbol server (offline cache, Phase β).

Persona-E #1 covers the format in detail. Persona-B's tooling brief
flags PSFExtractor (Secant1006) as the only viable Linux-side reader
with license-unclear status — hence the gated rollout.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import uuid

from app.workers.unpack_common import UnpackResult

logger = logging.getLogger(__name__)


# PSF magic bytes — verified against documented Express-install variants.
# PA30 covers Win10/11 cumulative updates; PA19 / PA17 cover Win7/8 era
# and earliest variants respectively.
_PSF_MAGICS: tuple[bytes, ...] = (
    b"PA30",
    b"PA19",
    b"PA17",
)

# Header probe size — first 16 bytes more than cover the magic.
_PSF_PROBE_BYTES = 16


async def unpack_psf(
    firmware_path: str,
    output_base_dir: str,
    progress_callback=None,
    firmware_id: uuid.UUID | None = None,  # noqa: ARG001 — uniform signature
) -> UnpackResult:
    """Validate a PSF file and emit the gating-aware operator message.

    Returns ``success=True`` when the magic matches one of the known
    PSF variants. Returns ``success=False`` for malformed / non-PSF
    inputs.
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

    # ---- Step 1: validate PSF magic ----
    await _report("Validating PSF magic", 5)

    loop = asyncio.get_running_loop()

    def _read_head() -> bytes:
        with open(firmware_path, "rb") as fh:
            return fh.read(_PSF_PROBE_BYTES)

    try:
        head = await loop.run_in_executor(None, _read_head)
    except OSError as exc:
        result.error = f"PSF read failed: {exc}"
        result.unpack_log = result.error
        return result

    matched_magic: bytes | None = None
    for magic in _PSF_MAGICS:
        if head[: len(magic)] == magic:
            matched_magic = magic
            break

    if matched_magic is None:
        result.error = (
            f"Not a valid PSF file — expected magic in "
            f"{[m.decode() for m in _PSF_MAGICS]!r}, "
            f"got {head[:4]!r}"
        )
        result.unpack_log = result.error
        return result

    # ---- Step 2: surface gating message ----
    await _report("PSF detected (Phase α stub)", 50)

    fw_size = 0
    try:
        fw_size = await loop.run_in_executor(None, os.path.getsize, firmware_path)
    except OSError:
        pass

    log_head = (
        f"PSF (Patch Storage File) detected — magic={matched_magic.decode()}, "
        f"size={fw_size} bytes.\n\n"
        "PSF is the Microsoft Express install delta format. Full "
        "reconstruction requires:\n"
        "  (a) The BASELINE file (the previous version of the target "
        "binary this PSF differentials against). Without it, the delta "
        "carries no meaning.\n"
        "  (b) The gated `psfextract` toolchain — Phase α.6 Dockerfile "
        "`ARG INCLUDE_PSF=1` enables it. PSFExtractor (Secant1006) is "
        "the canonical Linux-side reader; license-unclear status keeps "
        "it isolated to a side-container.\n\n"
        "Without (a) and (b), this worker preserves the .psf file at "
        "the upload path. The `identify_psf_baseline` MCP tool (Phase "
        "α.4) reads the PSF header to extract the target binary's "
        "RSDS GUID, which the operator can use to locate the baseline "
        "in another firmware upload or via Microsoft's symbol server "
        "(offline cache, Phase β).\n\n"
        "PSF deltas embedded inside MSU packages are detected and "
        "surfaced by `unpack_msu` automatically (Phase α handler 4); "
        "this worker handles the rare case of a standalone PSF upload.\n"
    )

    result.success = True
    result.extracted_path = extraction_dir
    result.extraction_dir = extraction_dir
    result.unpack_log = log_head
    await _report("Extraction complete (stub)", 100)
    return result
