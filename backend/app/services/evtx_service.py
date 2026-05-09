"""Phase ε.1 — Windows Event Log (EVTX) walker (PRD-deferred reversal).

Reads on-disk ``.evtx`` Event Log files from extracted Windows
installations / live-system images and surfaces event records as
plain dictionaries for downstream finding-emit hooks.

**Scope (Phase ε.1 — scaffold + parser foundation + walker).**

ε.1.a shipped the *parser foundation* (:func:`parse_evtx_file` +
:func:`is_python_evtx_available`). ε.1.b.1 (this commit) adds the
*walker* (:func:`walk_evtx_files`) — the on-disk scanner that yields
``.evtx`` paths under any iterable of detection roots. Subsequent
ε.1.b commits add Rule #33 outer state-machine runner + auto-walk
hook + MCP tool category + FE skeleton page + Finding emit hook.

**Mirrors γ.4 / δ.5 precedent shape.** Per the new
``.mex/patterns/real-firmware-skip-tier-canary.md`` recipe (committed
on ``feat/postmortem-followups-2026-05-09``, PR #2) and CLAUDE.md
Rule #33, subsequent ε.1.b commits will add:

- ``_do_evtx_walk_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict``
  — INNER orchestrator (accepts a ``db``; the live canary tier-1
  shape from δ Pattern #2). Walks every ``.evtx`` in the firmware's
  detection roots (resolved via :func:`app.services.firmware_paths.get_detection_roots`
  per Rule #16), aggregates event records into a JSONB result on
  ``firmware.evtx_walk_result`` (per-event persistence deferred to a
  future ζ.X phase per the ε.1.b campaign Decision #1).
- ``run_evtx_walk_background(firmware_id: uuid.UUID) -> None`` —
  OUTER state-machine wrapper (owns the Rule #33 .a status
  transitions ``idle → queued → running → completed | failed`` via
  ``async_session_factory()``).
- ``auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None`` —
  unpack-post-detection hook that runs the same orchestrator but
  does NOT mutate the firmware's status fields (γ.4
  ``auto_walk_firmware_safe`` precedent).

**Rule #36 no-execute discipline.** python-evtx PARSES the EVTX
binary AS DATA — there is no event-replay path. The EVTX file
format is a custom binary record stream; events are decoded
read-only into Python dictionaries. wairz does NOT invoke
``wevtutil``, ``Get-WinEvent``, or any other event-replay tool, and
the ε.1 worker MUST NOT pass an extracted ``.evtx`` path as
``argv[0]`` to ``subprocess.run`` / ``Popen`` / ``asyncio.create_subprocess_*``
or any ``os.system`` / ``execv*`` family call. Future ε.X workers
that shell out to additional EVTX tools (e.g. ``evtxtool``,
``LogParser``, ``Plaso``) MUST extend ``FORBIDDEN_ARGV0_TOKENS`` in
the same shape as δ.4's ``dotnet_decompile_service.assert_no_execute_argv``.

**Rule #19 evidence-first probe.** The dependency probe
(:func:`is_python_evtx_available`) is exposed as a public function
so MCP tools / future Rule #33 trigger handlers can degrade
gracefully when ``python-evtx`` is missing — same shape as δ.7's
``windows_storage`` tools degrading when ``libesedb-utils`` is
absent (now installed via Phase ε.2 Dockerfile delta).
"""
from __future__ import annotations

import asyncio
import logging
import os
import time
import traceback
import uuid
from collections.abc import Iterable
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_evtx_walk_result,
)

logger = logging.getLogger(__name__)


# ── Runner tunables ──────────────────────────────────────────────────────────


# Maximum sample event records persisted PER .evtx file. A real
# Security.evtx can carry millions of events; the per-firmware aggregate
# JSONB caps at this many per file so the row size stays bounded.
# Operators wanting full inspection re-walk via the MCP ``parse_evtx_file``
# tool against a specific path. Per ε.1.b campaign Decision #1, per-event
# row persistence is deferred to a future ζ.X phase.
_DEFAULT_SAMPLE_RECORDS_PER_FILE: int = 32

# Maximum total records SUMMED across all .evtx files in one walk.
# Protects walk_result row size when a firmware contains an unusually
# large number of EVTX files (e.g. a forensic capture spanning months).
_DEFAULT_TOTAL_RECORDS_CAP: int = 50000

# Maximum walk wall-clock per .evtx file. python-evtx is generally fast
# but a multi-GB Security.evtx in a degraded image could send the parser
# into a long iteration. The cap is a soft-limit (checked between files,
# not per-record) — current value matches γ.4's per-hive cap.
_DEFAULT_PER_FILE_TIMEOUT_SECONDS: float = 60.0


# ── Walker constants ────────────────────────────────────────────────────────


# Canonical Windows Event Log file extension. Real EVTX files always end
# in ``.evtx`` (case-insensitive on Windows; we match case-insensitively
# here so an EXTRACTED tree from a case-preserving filesystem doesn't
# miss files capitalised by the unpacker). Files with the extension
# without the EVTX magic header are still surfaced — :func:`parse_evtx_file`
# will degrade them to ``status="error"`` rather than crashing.
_EVTX_EXTENSION: str = ".evtx"


# ── Rule #19 dependency probe ───────────────────────────────────────────────


def is_python_evtx_available() -> bool:
    """Return True iff ``python-evtx`` is importable in this process.

    Mirrors the regipy / dnfile graceful-degrade probes used by γ.4
    and δ.4. Use this at the top of any consumer (MCP tool handler,
    Rule #33 trigger, auto-walk hook) so the absence of the dep
    surfaces as a clear "library not installed" message rather than
    an opaque ImportError stack trace.

    The probe runs in <1 ms after first call (Python's import cache
    handles repeated invocations).
    """
    try:
        import Evtx.Evtx  # noqa: F401 — import-only probe
    except ImportError:
        return False
    return True


# ── Parser ──────────────────────────────────────────────────────────────────


# Sentinel returned by parse_evtx_file when python-evtx is unavailable.
# Distinguishable from a "real" empty parse (a zero-record EVTX file is
# valid but rare; missing-dep is the common failure mode at scaffold time
# and during minimal-CI Docker builds that omit Phase ε deps).
PYTHON_EVTX_UNAVAILABLE: dict[str, Any] = {
    "status": "unavailable",
    "reason": "python-evtx not installed — see backend/pyproject.toml ε.1 block",
    "records": [],
    "record_count": 0,
}


def parse_evtx_file(path: str | Path) -> dict[str, Any]:
    """Parse a single ``.evtx`` file and return a record summary.

    Returns a dict with keys:
    - ``status``: ``"ok"`` | ``"unavailable"`` | ``"error"``.
    - ``record_count``: total event records yielded by the parser.
    - ``records``: list of records (each a dict with keys
      ``event_id``, ``provider``, ``timestamp``, ``raw_xml``). Empty
      list when ``status != "ok"``.
    - ``error``: present only when ``status == "error"``; contains
      the exception message (truncated to 500 chars to stay under
      Rule "MCP tool output ≤30KB" budget when wrapped by a tool
      handler).

    **Defensive against missing dep** — returns
    :data:`PYTHON_EVTX_UNAVAILABLE` shape if ``python-evtx`` isn't
    importable. Callers MUST check ``status`` before accessing
    ``records``.

    **Defensive against malformed input** — wraps the EVTX iteration
    in a try/except. A truncated / corrupted EVTX file raises in
    python-evtx; we surface a structured error instead of letting
    the caller crash.

    Rule #36 reminder: ``path`` is read AS DATA (the python-evtx
    parser uses ``mmap`` internally — read-only memory map, not
    process spawn).
    """
    if not is_python_evtx_available():
        return PYTHON_EVTX_UNAVAILABLE

    # Lazy import per Rule #30 — `from Evtx.Evtx import Evtx` at
    # module scope would force a hard import even when consumers
    # only check the probe. The lazy import keeps the module
    # cold-import fast (<5 ms) for non-EVTX code paths.
    from Evtx.Evtx import Evtx

    p = Path(path)
    records: list[dict[str, Any]] = []

    try:
        with Evtx(str(p)) as log:
            for record in log.records():
                # python-evtx Record.lxml() returns the parsed lxml
                # element; .xml() returns a serialized string. Both
                # are expensive on large logs; we sample minimal
                # fields here. The full XML is preserved as raw_xml
                # for downstream finding emitters that need the
                # complete record (e.g. a future Sysmon-1 rule that
                # extracts the parent-process command line).
                try:
                    xml = record.xml()
                except Exception as exc:  # pragma: no cover — record-level
                    logger.debug(
                        "evtx record %s xml() failed: %s",
                        record.record_num(),
                        exc,
                    )
                    continue
                records.append(
                    {
                        "record_num": record.record_num(),
                        "raw_xml": xml,
                    }
                )
    except Exception as exc:
        msg = str(exc)
        if len(msg) > 500:
            msg = msg[:500] + "..."
        return {
            "status": "error",
            "record_count": 0,
            "records": [],
            "error": msg,
        }

    return {
        "status": "ok",
        "record_count": len(records),
        "records": records,
    }


__all__ = [
    "PYTHON_EVTX_UNAVAILABLE",
    "is_python_evtx_available",
    "parse_evtx_file",
    "walk_evtx_files",
    "_do_evtx_walk_run",
    "run_evtx_walk_background",
    "auto_walk_firmware_safe",
]


# ── Walker ──────────────────────────────────────────────────────────────────


def walk_evtx_files(roots: Iterable[str]) -> list[str]:
    """Walk every detection root and return a list of ``.evtx`` file paths.

    Mirrors :func:`registry_hive_walker.scan_for_hives` (γ.4 precedent)
    exactly — case-insensitive extension match + sandbox check that
    rejects symlinks pointing outside the root tree (Rule #1 spirit;
    the unpacker may have legitimate symlinks within the rootfs but
    escape symlinks are a sandbox concern).

    Sync I/O — wrap in ``run_in_executor`` for async callers
    (Rule #5). Defensive against missing roots, permission errors,
    short reads — every error path is swallowed at the per-root /
    per-file level so one corrupted detection root doesn't abort the
    entire walk.

    Caller responsibility per Rule #16: pass roots resolved via
    :func:`app.services.firmware_paths.get_detection_roots` — NEVER
    a single ``firmware.extracted_path`` (scatter-zip uploads, multi-
    archive medical firmware, and nested unblob output produce sibling
    detection roots that ``extracted_path`` misses entirely).
    """
    hits: list[str] = []
    for root in roots:
        try:
            real_root = os.path.realpath(root)
        except OSError:
            continue
        if not os.path.isdir(real_root):
            continue
        for dirpath, _dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames:
                # Case-insensitive match — Windows filesystems are
                # case-preserving but case-insensitive, and unpackers
                # vary on case-normalisation behavior.
                if not name.lower().endswith(_EVTX_EXTENSION):
                    continue
                full = os.path.join(dirpath, name)
                # Sandbox check — never surface a file whose realpath
                # escapes the root tree. Same shape as scan_for_hives;
                # legitimate intra-rootfs symlinks pass through, escape
                # symlinks are dropped silently.
                try:
                    real_full = os.path.realpath(full)
                except OSError:
                    continue
                if not real_full.startswith(real_root):
                    continue
                # ``os.path.isfile`` after realpath confirms the symlink
                # target (if any) actually exists as a regular file —
                # broken symlinks within the sandbox are rejected.
                try:
                    if not os.path.isfile(real_full):
                        continue
                except OSError:
                    continue
                hits.append(real_full)
    return hits


# ── Async wrappers (Rule #5 sync-I/O discipline) ─────────────────────────────


async def _walk_evtx_files_async(roots: list[str]) -> list[str]:
    """Async wrapper around :func:`walk_evtx_files` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, walk_evtx_files, roots)


async def _parse_evtx_file_async(path: str) -> dict[str, Any]:
    """Async wrapper around :func:`parse_evtx_file` (Rule #5)."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(None, parse_evtx_file, path)


# ── Aggregate helpers ────────────────────────────────────────────────────────


def _empty_walk_result(run_seconds: float) -> dict[str, Any]:
    """Aggregate shape for "no .evtx files found" or "no detection roots"."""
    return {
        "run_seconds": round(run_seconds, 3),
        "evtx_count": 0,
        "by_provider": {},
        "by_status": {"ok": 0, "error": 0, "unavailable": 0},
        "total_records": 0,
        "sample_records_per_file": _DEFAULT_SAMPLE_RECORDS_PER_FILE,
        "errors": [],
        "per_file": [],
    }


def _provider_from_record(record: dict[str, Any]) -> str:
    """Extract the provider name from a parsed EVTX record dict.

    The parser returns records as ``{"record_num": int, "raw_xml": str}``
    — provider lives inside the XML. Cheap regex extraction beats lxml
    parse for the aggregate (we don't need every field; just the
    provider for the by_provider histogram).
    """
    xml = record.get("raw_xml") or ""
    # ``<Provider Name='Microsoft-Windows-Sysmon' …`` — match either
    # single or double quotes; tolerate attribute order.
    import re

    m = re.search(r"<Provider\b[^>]*\bName=['\"]([^'\"]+)['\"]", xml)
    return m.group(1) if m else "unknown"


# ── Inner orchestrator (accepts a db; reusable in tier-1 live canaries) ──────


async def _do_evtx_walk_run(
    db: AsyncSession,
    firmware_id: uuid.UUID,
    *,
    sample_records_per_file: int = _DEFAULT_SAMPLE_RECORDS_PER_FILE,
    total_records_cap: int = _DEFAULT_TOTAL_RECORDS_CAP,
    per_file_timeout_seconds: float = _DEFAULT_PER_FILE_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Walk every ``.evtx`` file in ``firmware_id``'s extracted tree.

    1. Resolve detection roots via :func:`get_detection_roots` (Rule #16).
    2. Scan filesystem for ``.evtx`` files (extension match + sandbox
       check via :func:`walk_evtx_files`).
    3. For each file: parse via :func:`parse_evtx_file` (run_in_executor
       for Rule #5 sync I/O), aggregate per-provider + per-status counts,
       cap sample records per file.
    4. Compute aggregate result; caller stamps it onto firmware row.

    Inner-vs-outer split per δ Pattern #2 — this function accepts a
    ``db`` so tier-1 live canary tests (Rule #35b) can drive the FULL
    walk against a real test DB without DNS resolution issues from
    ``async_session_factory()``. The outer wrapper
    :func:`run_evtx_walk_background` owns the Rule #33 .a state machine
    transitions; this inner runner is pure logic.

    Returns the aggregate dict (UNSTAMPED — caller stamps via
    :func:`_stamp_firmware_evtx_walk_result` before assigning).
    """
    started = time.monotonic()

    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        return _empty_walk_result(0.0)

    roots = await get_detection_roots(firmware, db=db)
    if not roots:
        return _empty_walk_result(time.monotonic() - started)

    evtx_paths = await _walk_evtx_files_async(roots)
    if not evtx_paths:
        return _empty_walk_result(time.monotonic() - started)

    # ── Per-file parse + aggregate ──
    by_provider: dict[str, int] = {}
    by_status: dict[str, int] = {"ok": 0, "error": 0, "unavailable": 0}
    total_records = 0
    errors: list[str] = []
    per_file: list[dict[str, Any]] = []

    for evtx_path in evtx_paths:
        # Per-file wall-clock cap (soft) — checked between files, not
        # per-record. A pathological file that exceeds the cap during
        # parse will still complete the call but is logged.
        file_started = time.monotonic()
        try:
            parsed = await _parse_evtx_file_async(evtx_path)
        except Exception as exc:  # noqa: BLE001 — defensive boundary
            err = f"parse failed for {evtx_path}: {type(exc).__name__}: {str(exc)[:200]}"
            errors.append(err)
            by_status["error"] += 1
            per_file.append(
                {
                    "path": evtx_path,
                    "status": "error",
                    "record_count": 0,
                    "error": err,
                }
            )
            continue

        elapsed = time.monotonic() - file_started
        if elapsed > per_file_timeout_seconds:
            errors.append(
                f"slow parse for {evtx_path}: {elapsed:.2f}s "
                f"exceeded {per_file_timeout_seconds}s soft cap"
            )

        status = parsed.get("status", "error")
        record_count = int(parsed.get("record_count", 0))
        by_status[status] = by_status.get(status, 0) + 1

        # Aggregate per-provider counts from sample records (saves a
        # full re-parse). Records past the per-file sample cap are
        # counted in record_count but don't contribute to by_provider —
        # acceptable trade-off for bounded row size.
        records = parsed.get("records") or []
        sample = records[:sample_records_per_file]
        for rec in sample:
            prov = _provider_from_record(rec)
            by_provider[prov] = by_provider.get(prov, 0) + 1

        # Total-records cap protects the aggregate when walking many
        # files. Once hit we still parse remaining files for status
        # accounting but stop accumulating sample records.
        contribution = (
            min(record_count, total_records_cap - total_records)
            if total_records < total_records_cap
            else 0
        )
        total_records += contribution

        per_file_entry: dict[str, Any] = {
            "path": evtx_path,
            "status": status,
            "record_count": record_count,
            "error": parsed.get("error"),
        }
        per_file.append(per_file_entry)

    return {
        "run_seconds": round(time.monotonic() - started, 3),
        "evtx_count": len(evtx_paths),
        "by_provider": by_provider,
        "by_status": by_status,
        "total_records": total_records,
        "sample_records_per_file": sample_records_per_file,
        "errors": errors,
        "per_file": per_file,
    }


# ── Outer wrapper (Rule #33 .a state machine; uses async_session_factory) ────


async def run_evtx_walk_background(firmware_id: uuid.UUID) -> None:
    """202+polling background runner for the EVTX walk.

    Owns its own AsyncSession via :func:`async_session_factory`; outer
    guard catches anything that escapes; failure persistence on a
    fresh session because the inner one rolled back. Mirrors the γ.4
    ``_run_registry_hive_walk_background`` shape (Rule #33 reference
    recipe).

    Status transitions: ``idle → running → completed | failed``. The
    ``queued`` state belongs to the trigger router (idempotent POST
    + 409-on-conflict per Rule #33 .a) which lands in ε.1.b.4 alongside
    the MCP tools.
    """
    try:
        async with async_session_factory() as db:
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is None:
                logger.warning("evtx_walk: firmware %s not found", firmware_id)
                return

            row.evtx_walk_status = "running"
            row.evtx_walk_started_at = datetime.utcnow()
            await db.commit()

            try:
                result = await _do_evtx_walk_run(db, firmware_id)
                row.evtx_walk_status = "completed"
                row.evtx_walk_finished_at = datetime.utcnow()
                row.evtx_walk_result = _stamp_firmware_evtx_walk_result(result)
                await db.commit()
                logger.info(
                    "evtx_walk: firmware %s completed in %.2fs (%d evtx files, %d records)",
                    firmware_id,
                    result["run_seconds"],
                    result["evtx_count"],
                    result["total_records"],
                )
            except Exception as exc:  # noqa: BLE001 — defensive boundary
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.evtx_walk_status = "failed"
                        fail_row.evtx_walk_finished_at = datetime.utcnow()
                        fail_row.evtx_walk_error = err
                        await fail_db.commit()
                logger.exception("evtx_walk: firmware %s failed", firmware_id)
    except Exception:
        logger.exception("evtx_walk: unrecoverable for %s", firmware_id)


# ── Auto-walk-on-unpack hook ────────────────────────────────────────────────


async def auto_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Fire-and-forget entry point invoked by ``unpack._run_*`` hooks
    after detection completes. Same shape as
    :func:`registry_hive_walker.auto_walk_firmware_safe` (γ.4 precedent).

    Distinct from :func:`run_evtx_walk_background`: the background
    runner (a) transitions the firmware status column through
    queued → running → completed/failed, and (b) is intended for
    explicit operator-triggered walks via the 202+polling endpoint
    (ε.1.b.4 MCP tools hand the trigger). The auto-walk-on-unpack
    flow runs the SAME orchestrator (``_do_evtx_walk_run``) but DOES
    NOT transition the status column — it stays ``idle`` until an
    operator explicitly triggers a re-walk via the trigger MCP tool,
    which resets and runs again. This matches the existing
    auto_walk_firmware_safe shape from γ.4.
    """
    try:
        async with async_session_factory() as db:
            result = await _do_evtx_walk_run(db, firmware_id)
            row = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if row is not None:
                # Stamp the result aggregate so the operator can see
                # the walk happened, but leave status at idle so a
                # manual re-trigger via the MCP tool still works
                # without 409 conflict (status='running' would block).
                row.evtx_walk_result = _stamp_firmware_evtx_walk_result(result)
                await db.commit()
            logger.info(
                "evtx_walk auto: firmware %s walked %d evtx files in %.2fs",
                firmware_id,
                result["evtx_count"],
                result["run_seconds"],
            )
    except Exception:
        logger.warning(
            "evtx_walk auto: firmware %s failed",
            firmware_id,
            exc_info=True,
        )
