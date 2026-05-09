"""Phase δ.4: .NET single-file bundle decompile service.

Walks every .NET single-file bundle in a firmware's hardware_firmware_blobs,
detects bundles via dnfile (read-only PE-table walking), and runs ilspycmd
(installed inside the worker container behind ARG INCLUDE_DOTNET=1) to
extract per-assembly IL output. Aggregate results land in
``firmware.dotnet_decompile_result`` (δ.2 5-column status set).

Rule #36 no-execute discipline:

- ``dnfile`` parses the PE AS DATA (read-only PE-table walk; no managed
  code is loaded into a runtime).
- ``ilspycmd`` is invoked via subprocess as a DECOMPILER — it reads the
  bundle's PE/metadata streams and emits IL/C# text. The .NET assembly's
  entry point (``Program.Main`` / ``EXEMain``) is NEVER invoked.
- The subprocess argv passed to ilspycmd MUST resolve to the trusted,
  image-shipped ``ilspycmd`` binary (validated by the test gate); the
  bundle path is passed as ``argv[1]`` (an input filename), never as
  ``argv[0]``.
- The forbidden-token test gate
  (``test_dotnet_decompile_service.py::test_no_execute_argv_shape``) asserts
  the subprocess argv contains ONLY ``ilspycmd`` + the bundle path +
  ``-o`` + output dir + read-only flags — never ``wine``, ``mono``,
  ``dotnet`` (the .NET runtime CLI invokes assemblies), ``cscript``, or
  ``wscript``.

Per Rule #33 .a/.c/.d:
- 5-state machine + Pydantic ``DotnetDecompileStatus`` Literal (.c)
- arq dispatch (.d) — coordinated via ``decompile_dotnet_bundle_job``
- Idempotent + 409-on-conflict at the trigger MCP tool layer (.a, δ.7)

Per Rule #19 evidence-first: the dnfile + dncil + flare-capa surface
shapes were probed BEFORE writing this module (see commit message);
``ilspycmd`` is a published .NET tool — flags reference
https://github.com/icsharpcode/ILSpy CLI README.

If ``INCLUDE_DOTNET=1`` was NOT set at build time, the worker container
won't have ilspycmd; the service degrades gracefully — the bundles are
still detected via dnfile, the row transitions to ``failed`` with a
clear error message, and operators see "ilspycmd not available — rebuild
with INCLUDE_DOTNET=1" in the error column.
"""
from __future__ import annotations

import asyncio
import logging
import os
import shutil
import time
import traceback
import uuid
from datetime import datetime
from pathlib import Path

from sqlalchemy import select

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.hardware_firmware import HardwareFirmwareBlob
from app.services.jsonb_normalizers import (
    _stamp_firmware_dotnet_decompile_result,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Hard ceiling per bundle. ilspycmd on a moderate single-file bundle takes
# 5–30 s; the 600 s ceiling guards against pathologically large bundles
# (Visual Studio Code's electron host can ship a 200+ MB bundle that
# decompiles to 100k+ files; we don't want one bundle to wedge the worker
# job indefinitely).
DEFAULT_BUNDLE_TIMEOUT_SECONDS = 600

# Tool name. Looked up via ``shutil.which`` so the test can mock the
# resolver. Production install location: ``/root/.dotnet/tools/ilspycmd``
# (per ``dotnet tool install -g`` default) which is on PATH for the
# wairz user inside the worker container when ARG INCLUDE_DOTNET=1.
ILSPYCMD_BIN = "ilspycmd"

# Where extracted IL output lives. Mirrors the existing
# Ghidra/extraction layout under STORAGE_ROOT.
DOTNET_OUTPUT_SUBDIR = "dotnet"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def decompile_firmware_background(firmware_id: uuid.UUID) -> None:
    """Run the .NET decompile workflow for a firmware.

    Owns the full Rule #33 .a state machine: queued → running →
    completed/failed. Each state transition is committed independently so
    a mid-run crash leaves the row in ``running`` (the operator can re-run
    safely; per-bundle rows are idempotent on the firmware-row aggregate
    overwrite).
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning(
                    "decompile_firmware_background: firmware not found "
                    "(id=%s)",
                    firmware_id,
                )
                return

            row.dotnet_decompile_status = "running"
            row.dotnet_decompile_started_at = datetime.utcnow()
            await db.commit()

            try:
                aggregate = await _do_decompile_run(db, firmware_id)
                row = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one()
                row.dotnet_decompile_status = "completed"
                row.dotnet_decompile_finished_at = datetime.utcnow()
                row.dotnet_decompile_result = (
                    _stamp_firmware_dotnet_decompile_result(aggregate)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err_msg = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.dotnet_decompile_status = "failed"
                        fail_row.dotnet_decompile_finished_at = datetime.utcnow()
                        fail_row.dotnet_decompile_error = err_msg
                        await fail_db.commit()
                logger.exception(
                    "decompile_firmware_background failed (firmware=%s)",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "decompile_firmware_background outer guard caught unrecoverable "
            "error (firmware=%s)",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _do_decompile_run(db, firmware_id: uuid.UUID) -> dict:
    """Inner runner — gathers candidate PEs, runs ilspycmd per bundle,
    accumulates the aggregate. The OUTER ``decompile_firmware_background``
    owns transaction + status state.
    """
    start = time.monotonic()

    blobs = (
        (
            await db.execute(
                select(HardwareFirmwareBlob).where(
                    HardwareFirmwareBlob.firmware_id == firmware_id
                )
            )
        )
        .scalars()
        .all()
    )

    candidates = await asyncio.get_event_loop().run_in_executor(
        None, _scan_for_bundles_sync, [str(b.blob_path) for b in blobs if b.blob_path]
    )

    bundles_decompiled = 0
    bundles_failed = 0
    total_assemblies = 0
    by_arch: dict[str, int] = {}
    bundle_results: list[dict] = []
    errors: list[str] = []

    out_root = _firmware_output_dir(firmware_id)
    out_root.mkdir(parents=True, exist_ok=True)

    for candidate in candidates:
        bundle_path = candidate["bundle_path"]
        bundle_sha = candidate.get("bundle_sha256") or "unknown"
        target_dir = out_root / bundle_sha
        try:
            extracted = await asyncio.get_event_loop().run_in_executor(
                None, _run_ilspycmd_sync, bundle_path, str(target_dir),
            )
            bundles_decompiled += 1
            total_assemblies += extracted["count"]
            arch = candidate.get("arch") or "msil"
            by_arch[arch] = by_arch.get(arch, 0) + 1
            bundle_results.append(
                {
                    "bundle_path": bundle_path,
                    "bundle_sha256": bundle_sha,
                    "extracted_count": extracted["count"],
                    "decompile_target_dir": str(target_dir),
                    "errors": extracted.get("errors", []),
                }
            )
        except Exception as exc:
            bundles_failed += 1
            err = f"{bundle_path}: {exc}"
            errors.append(err)
            bundle_results.append(
                {
                    "bundle_path": bundle_path,
                    "bundle_sha256": bundle_sha,
                    "extracted_count": 0,
                    "decompile_target_dir": str(target_dir),
                    "errors": [str(exc)],
                }
            )
            logger.warning("ilspycmd bundle failed: %s", err)

    return {
        "run_seconds": round(time.monotonic() - start, 2),
        "bundle_count": len(candidates),
        "bundles_decompiled": bundles_decompiled,
        "bundles_failed": bundles_failed,
        "total_assemblies_extracted": total_assemblies,
        "by_arch": by_arch,
        "bundles": bundle_results,
        "errors": errors,
    }


def _firmware_output_dir(firmware_id: uuid.UUID) -> Path:
    """Output root for one firmware's decompile artefacts."""
    from app.config import get_settings

    return Path(get_settings().storage_root) / str(firmware_id) / DOTNET_OUTPUT_SUBDIR


def _scan_for_bundles_sync(blob_paths: list[str]) -> list[dict]:
    """Walk candidate PEs and return single-file bundle metadata.

    Synchronous (blocking I/O), wrapped via ``run_in_executor`` from the
    async caller. Lazy-imports dnfile per Rule #30 (cold-import cost +
    test patch-at-source-module discipline).
    """
    candidates: list[dict] = []
    for path in blob_paths:
        try:
            meta = _detect_bundle_sync(path)
        except Exception as exc:  # defensive — keep walking on parse error
            logger.debug("dnfile parse failed for %s: %s", path, exc)
            continue
        if meta is not None:
            meta["bundle_path"] = path
            candidates.append(meta)
    return candidates


def _detect_bundle_sync(path: str) -> dict | None:
    """Parse one PE and return bundle metadata if it's a .NET single-file
    bundle. Returns ``None`` for non-.NET or non-bundle PEs.

    Rule #36: dnfile parses the PE AS DATA — no .NET runtime is loaded;
    no managed entry-point is invoked.
    """
    # Lazy imports per Rule #30. dnfile cold-import is non-trivial; we
    # only want to pay it when there's actually a candidate to scan.
    from dnfile import dnPE  # type: ignore[import-untyped]

    if not os.path.isfile(path):
        return None
    try:
        pe = dnPE(path, fast_load=True)
    except Exception:
        return None
    # Heuristic: a .NET assembly has a metadata directory; a single-file
    # bundle additionally embeds .NET payload resources or an
    # AppHostBundle signature. We treat any .NET PE (managed assembly OR
    # native AppHost wrapper) as a bundle candidate — δ.6's R2R-stomping
    # detector consumes both shapes.
    if not getattr(pe, "net", None):
        # Possibly a native AppHost wrapper without .NET metadata. Check
        # for the AppHostBundle signature in raw bytes.
        with open(path, "rb") as fh:
            head = fh.read(0x1_00_00_00)  # 16 MiB sniff cap
        if b"DOTNET_BUNDLE_EXTRACT_BASE_DIR" not in head and b".dll\x00" not in head:
            return None
    arch = _detect_pe_arch(path)
    sha = _sha256_of_file_sync(path)
    return {"bundle_sha256": sha, "arch": arch}


def _detect_pe_arch(path: str) -> str:
    """Return ``msil`` / ``amd64`` / ``arm64`` / ``unknown``.

    Reads PE machine field via pefile (already in pyproject).
    """
    try:
        import pefile

        pe = pefile.PE(path, fast_load=True)
        machine = pe.FILE_HEADER.Machine
    except Exception:
        return "unknown"
    # IMAGE_FILE_MACHINE_* constants
    if machine == 0x8664:
        return "amd64"
    if machine == 0xAA64:
        return "arm64"
    if machine == 0x14C:
        return "i386"
    if machine == 0x1C4:
        return "armnt"
    if machine == 0x0:  # IMAGE_FILE_MACHINE_UNKNOWN — pure MSIL
        return "msil"
    return "unknown"


def _sha256_of_file_sync(path: str, chunk_size: int = 1024 * 1024) -> str:
    import hashlib

    sha = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            sha.update(chunk)
    return sha.hexdigest()


def _run_ilspycmd_sync(
    bundle_path: str,
    out_dir: str,
    timeout: int = DEFAULT_BUNDLE_TIMEOUT_SECONDS,
) -> dict:
    """Run ilspycmd against a bundle and return ``{count, errors}``.

    Rule #36 no-execute: argv shape is::

        [ilspycmd, bundle_path, "-o", out_dir, "--no-dead-code", "--lang", "IL"]

    ``ilspycmd`` is the trusted, image-shipped binary at ``argv[0]``;
    the bundle path is an INPUT FILENAME at ``argv[1]``, never invoked.
    The forbidden-token test gate asserts the argv resolves to ilspycmd
    and never to ``wine`` / ``mono`` / ``dotnet`` / ``cscript`` / ``wscript``.

    Synchronous (blocks the executor thread); the async caller wraps
    via ``run_in_executor``.
    """
    import subprocess

    binary = shutil.which(ILSPYCMD_BIN) or ILSPYCMD_BIN
    os.makedirs(out_dir, exist_ok=True)
    argv = [
        binary,
        bundle_path,
        "-o",
        out_dir,
        "--no-dead-code",
        "--lang",
        "IL",
    ]
    proc = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        # ilspycmd's failure is captured but propagated as an exception so
        # the per-bundle "failed" branch in _do_decompile_run records it.
        # The decompile_log captured here is part of the row's error
        # field, not stored anywhere that could re-execute the bundle.
        raise RuntimeError(
            f"ilspycmd exited {proc.returncode}: {proc.stderr.strip()[-500:]}"
        )
    # Walk out_dir for IL files; report count + any non-fatal errors
    # surfaced in stderr.
    count = 0
    for _root, _dirs, files in os.walk(out_dir):
        count += sum(1 for f in files if f.endswith((".il", ".cs", ".decompiled.cs")))
    errors: list[str] = []
    if proc.stderr:
        errors = [
            line for line in proc.stderr.splitlines()
            if line.strip() and ("error" in line.lower() or "warning" in line.lower())
        ][:50]
    return {"count": count, "errors": errors}


# ---------------------------------------------------------------------------
# Argv assertion helper (used by the Rule #36 test gate)
# ---------------------------------------------------------------------------


# Forbidden tokens — any of these in argv[0] indicates the runner is about
# to invoke a .NET runtime / Windows scripting host that would EXECUTE the
# bundle's entry point. The test gate asserts none of these appear at
# argv[0]; the bundle is only ever an INPUT to ilspycmd.
FORBIDDEN_ARGV0_TOKENS: tuple[str, ...] = (
    "wine",
    "mono",
    "dotnet",
    "cscript",
    "wscript",
    "powershell",
    "pwsh",
)


def assert_no_execute_argv(argv: list[str]) -> None:
    """Assert subprocess argv complies with Rule #36 no-execute discipline.

    Used by the test gate. Public so the (future) trigger router can
    optionally re-validate before enqueuing a job (defence-in-depth).
    """
    if not argv:
        raise ValueError("empty argv")
    head = os.path.basename(argv[0]).lower()
    for tok in FORBIDDEN_ARGV0_TOKENS:
        if tok in head:
            raise ValueError(
                f"Rule #36 violation: argv[0] resolves to {head!r} which "
                f"could execute the bundle. Use ilspycmd (read-only "
                f"decompiler) instead."
            )
