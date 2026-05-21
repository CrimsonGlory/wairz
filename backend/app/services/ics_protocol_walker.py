"""ICS protocol catalog walker (CLAUDE.md Rule #52 instance #3 — Session 2).

Rule #39 inner/outer/safe triplet for the Session 1 ICS protocol catalog
scaffold (commits ``0dabbd6..1d0d0a9``). The walker iterates every binary
candidate in ``get_detection_roots(firmware)`` per Rule #16, invokes the
closed-grammar :func:`resolve_all` against each binary's head bytes
(bounded by ``_HEAD_BYTES`` to keep the per-walk cost predictable), and
aggregates the per-binary :class:`IcsProtocolMatch` lists into a single
JSONB result stamp.

Three functions per Rule #39:

  - :func:`_do_ics_protocol_walk` — INNER pure-logic orchestrator.
    Caller owns the session + transaction. Returns the result aggregate
    UNSTAMPED. Pins the catalog snapshot at entry (W2-β §SC5-NEW-ICS-S2-β
    mitigation) and reads the snapshot at exit; surfaces mid-walk
    snapshot drift as a structured ``consistency_warning`` field that
    downstream CVE matcher / cross-firmware lookup consumers MUST refuse
    to attribute when set. Clears stale ``ics_protocol_walk_result``
    JSONB at function entry per W2-β §SC5-NEW-ICS-S2-δ.

  - :func:`run_ics_protocol_walk_background` — OUTER Rule #33 .a state
    machine. Owns its own ``async_session_factory()``. Cycles
    ``queued → running → completed | failed``. Outer guard catches any
    exception escaping inner; failure persistence on a FRESH session per
    Rule #33 .b. On failure, ``ics_protocol_walk_result`` is cleared to
    NULL per W2-β §SC5-NEW-ICS-S2-δ (partial-JSONB-on-failure violates
    Rule #33 .b idempotency).

  - :func:`auto_ics_protocol_walk_firmware_safe` — SAFE
    unpack-post-detection hook (Rule #39 .safe contract). Owns own
    session. Runs the inner walker. Stamps result onto JSONB so
    operators see the last-known result. Does NOT mutate
    ``ics_protocol_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via the ``trigger_ics_protocol_walk`` MCP
    tool works without a 409 conflict. Swallows exceptions silently
    with structured ``logger.exception`` (Rule #51 partner).

**Rule #36 + Rule #45 parse-only contract.** The walker NEVER invokes any
extracted binary, NEVER instantiates operator-supplied YAML as code.
The closed Literals + ``extra='forbid'`` on every Pydantic model in the
Session 1 ICS schema structurally guarantee no eval/exec path. Test gate
``test_ics_protocol_walker.py::test_walker_no_execute_no_decrypt``
enforces via tokenize-walk over this module's source; Rule #46 paired
META-CANARY (whitespace-tolerant per Rule #45 lesson-from-EFS-DDF gate)
confirms the gate fires on synthetic violations.

**Rule #35c writer contract.** The walker writes ``ics_protocol_walk_result``
via :func:`_stamp_firmware_ics_protocol_walk_result` exclusively. The
stamp helper enforces ``schema_version=1`` + ``provenance="walker"``
sister-key per W2-β §SC5-NEW-ICS-S2-1 — downstream CVE matcher
consumers gate attribution on ``provenance == "walker"``, so a future
operator-supplied descriptor route cannot bypass the curated-source
trust boundary by pre-seeding the JSONB.
"""
from __future__ import annotations

import asyncio
import datetime as dt
import logging
import os
import traceback
import uuid
from collections import Counter

from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.ics_protocol_catalog import (
    IcsResolverContext,
    get_default_catalog,
    resolve_all,
)
from app.services.jsonb_normalizers import (
    _stamp_firmware_ics_protocol_walk_result,
)

logger = logging.getLogger(__name__)


# Head-byte slice per binary. Sized to cover magic_bytes (offset 0..N) +
# string_in_binary (default window ~4 KB) + function_code_set (default
# window 1 KB). 32 KiB is the Modbus/DNP3/S7Comm coverage band per the
# Session 1 resolver's _SIGNAL_COST_CLASS bounds. Larger windows pay
# more I/O without changing detection outcomes (the resolver's evaluators
# are bounded by their own ``window_bytes`` constraints).
_HEAD_BYTES = 32 * 1024

# Per-walk hard binary count cap. Prevents a pathological firmware with
# 10K+ files from blowing the walker's wall-clock budget; remaining count
# is surfaced in the ``errors`` list of the result aggregate.
_MAX_BINARIES_PER_WALK = 2000

# Per-file minimum/maximum size. Empty/<64-byte files are filesystem
# placeholders; >50 MB files are not protocol binaries (kernel images,
# disk images — handled by other walkers).
_MIN_BINARY_SIZE = 64
_MAX_BINARY_SIZE = 50 * 1024 * 1024

# Extension allowlist for binary candidates. Empty extension (typical
# Linux ``/bin /sbin /usr/bin /usr/sbin /usr/libexec`` shape) is allowed.
# This filter is a fast filesystem-level rejection so we don't open
# every config / log / asset file just to fail magic_bytes.
_BINARY_EXT_ALLOWLIST: frozenset[str] = frozenset({
    "",          # no extension — Linux executables
    ".bin",      # raw firmware images
    ".elf",      # ELF executables
    ".so",       # shared objects
    ".ko",       # kernel modules
    ".dll",      # Windows DLLs
    ".exe",      # Windows executables
    ".out",      # legacy a.out
    ".dylib",    # macOS dylibs
})


def _iter_binaries_sync(root_path: str, max_count: int) -> list[tuple[str, int]]:
    """Walk a single detection root for binary candidates (sync).

    Returns ``[(path, size_bytes), ...]`` bounded by ``max_count``.
    Filters by ``_BINARY_EXT_ALLOWLIST`` + ``_MIN_BINARY_SIZE`` +
    ``_MAX_BINARY_SIZE``. Reads via ``os.walk`` — caller is responsible
    for wrapping in ``loop.run_in_executor`` per Rule #5.
    """
    candidates: list[tuple[str, int]] = []
    for dirpath, _, filenames in os.walk(root_path):
        for filename in filenames:
            if len(candidates) >= max_count:
                return candidates
            ext = os.path.splitext(filename)[1].lower()
            if ext and ext not in _BINARY_EXT_ALLOWLIST:
                continue
            full = os.path.join(dirpath, filename)
            try:
                size = os.path.getsize(full)
            except OSError:
                continue
            if size < _MIN_BINARY_SIZE or size > _MAX_BINARY_SIZE:
                continue
            candidates.append((full, size))
    return candidates


def _read_head_sync(path: str, head_bytes: int) -> bytes | None:
    """Read up to ``head_bytes`` from the start of ``path`` (sync).

    Returns ``None`` on read error. Wrapped in ``run_in_executor`` per
    Rule #5 (open + read is bounded-but-blocking).
    """
    try:
        with open(path, "rb") as fh:
            return fh.read(head_bytes)
    except OSError:
        return None


def _empty_result_aggregate(
    walked_at: str,
    snapshot_id_at_entry: str,
    errors: list[str],
) -> dict:
    """Helper — empty per-binary aggregate (firmware-row missing, no
    detection roots, etc.). Same shape as the populated aggregate so
    downstream readers (MCP tools, CVE matcher) see a stable schema.
    """
    return {
        "walked_at": walked_at,
        "snapshot_id_at_entry": snapshot_id_at_entry,
        "snapshot_id_at_exit": snapshot_id_at_entry,
        "consistency_warning": None,
        "binaries_scanned_count": 0,
        "binaries_total_count": 0,
        "per_binary": [],
        "protocol_family_counts": {},
        "manifest_ids_seen": [],
        "manifest_sources_seen": [],
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# INNER pure-logic walker (Rule #39).
# ---------------------------------------------------------------------------


async def _do_ics_protocol_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER pure-logic orchestrator.

    Pins the catalog snapshot at entry (W2-β §SC5-NEW-ICS-S2-β); iterates
    detection roots × binary candidates × ``resolve_all`` calls; reads
    the catalog snapshot at exit; surfaces drift as
    ``consistency_warning``. Returns the result aggregate UNSTAMPED —
    caller stamps via ``_stamp_firmware_ics_protocol_walk_result``.

    Caller owns the session + transaction. The inner runner clears
    ``firmware.ics_protocol_walk_result`` to NULL at entry per W2-β
    §SC5-NEW-ICS-S2-δ (clears stale partial state from previous runs).
    """
    walked_at = dt.datetime.now(dt.timezone.utc).isoformat()

    # W2-β §SC5-NEW-ICS-S2-β: pin snapshot at INNER entry.
    catalog = get_default_catalog()
    entry_snapshot = catalog.get_snapshot()
    snapshot_id_at_entry = entry_snapshot.snapshot_id

    firmware = await db.get(Firmware, firmware_id)
    if firmware is None:
        return _empty_result_aggregate(
            walked_at,
            snapshot_id_at_entry,
            [f"firmware {firmware_id} not found"],
        )

    # W2-β §SC5-NEW-ICS-S2-δ: clear stale JSONB at INNER entry.
    firmware.ics_protocol_walk_result = None

    # Rule #16 — walk every detection root, not just extracted_path.
    detection_roots = await get_detection_roots(firmware, db=db)
    if not detection_roots:
        return _empty_result_aggregate(
            walked_at,
            snapshot_id_at_entry,
            ["no detection_roots for firmware (extraction may have failed)"],
        )

    context = IcsResolverContext()
    per_binary: list[dict] = []
    family_counts: Counter[str] = Counter()
    manifest_ids: list[str] = []
    manifest_sources: list[str] = []
    errors: list[str] = []
    binaries_total = 0

    loop = asyncio.get_running_loop()

    for root_path in detection_roots:
        remaining = _MAX_BINARIES_PER_WALK - binaries_total
        if remaining <= 0:
            errors.append(
                f"reached _MAX_BINARIES_PER_WALK={_MAX_BINARIES_PER_WALK} "
                f"cap; later roots skipped"
            )
            break
        # Rule #5 — bounded sync filesystem walk wrapped in executor.
        binaries = await loop.run_in_executor(
            None, _iter_binaries_sync, root_path, remaining,
        )
        for binary_path, size in binaries:
            binaries_total += 1
            # Rule #5 — bounded sync read wrapped in executor.
            head = await loop.run_in_executor(
                None, _read_head_sync, binary_path, _HEAD_BYTES,
            )
            if head is None:
                errors.append(f"read failed: {binary_path}")
                continue
            try:
                matches = resolve_all(
                    head, binary_path, size, entry_snapshot, context,
                )
            except Exception as exc:  # noqa: BLE001 — resolver defensive boundary
                errors.append(f"resolver failed for {binary_path}: {exc}")
                continue
            if not matches:
                continue
            match_dicts: list[dict] = []
            for m in matches:
                match_dicts.append({
                    "manifest_id": m.manifest_id,
                    "manifest_source": m.manifest_source,
                    "protocol_family": m.protocol_family,
                    "layer": m.layer,
                    "transport": m.transport,
                    "vendor": m.vendor,
                    "vendor_product": m.vendor_product,
                    "protocol_version": m.protocol_version,
                    "confidence": m.confidence,
                    "certainty": m.certainty,
                    "matched_signals": list(m.matched_signals),
                })
                family_counts[m.protocol_family] += 1
                if m.manifest_id not in manifest_ids:
                    manifest_ids.append(m.manifest_id)
                if m.manifest_source not in manifest_sources:
                    manifest_sources.append(m.manifest_source)
            per_binary.append({
                "blob_path": binary_path,
                "blob_size": size,
                "matches": match_dicts,
            })

    # W2-β §SC5-NEW-ICS-S2-β: read snapshot at EXIT; flag drift.
    exit_snapshot = catalog.get_snapshot()
    snapshot_id_at_exit = exit_snapshot.snapshot_id
    consistency_warning: str | None = None
    if snapshot_id_at_entry != snapshot_id_at_exit:
        consistency_warning = (
            f"catalog snapshot changed mid-walk "
            f"({snapshot_id_at_entry[:12]} -> {snapshot_id_at_exit[:12]}); "
            f"downstream consumers MUST refuse attribution"
        )

    return {
        "walked_at": walked_at,
        "snapshot_id_at_entry": snapshot_id_at_entry,
        "snapshot_id_at_exit": snapshot_id_at_exit,
        "consistency_warning": consistency_warning,
        "binaries_scanned_count": len(per_binary),
        "binaries_total_count": binaries_total,
        "per_binary": per_binary,
        "protocol_family_counts": dict(family_counts),
        "manifest_ids_seen": manifest_ids,
        "manifest_sources_seen": manifest_sources,
        "errors": errors,
    }


# ---------------------------------------------------------------------------
# OUTER state-machine wrapper (Rule #33 .a + Rule #39).
# ---------------------------------------------------------------------------


async def run_ics_protocol_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER wrapper — owns the Rule #33 .a state machine + outer guard.

    Transitions ``firmware.ics_protocol_walk_status``:
        queued (set by caller via MCP trigger)
          → running (this fn, on entry)
          → completed | failed (this fn, on exit)

    Outer guard: any exception escaping the inner runner gets captured
    into ``ics_protocol_walk_error`` + status=``failed`` via a FRESH
    session (because the inner session may have rolled back on the
    exception). On failure, ``ics_protocol_walk_result`` is cleared to
    NULL per W2-β §SC5-NEW-ICS-S2-δ.
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                logger.warning(
                    "ics_protocol_walk: firmware %s not found", firmware_id,
                )
                return
            firmware.ics_protocol_walk_status = "running"
            firmware.ics_protocol_walk_started_at = dt.datetime.now(dt.timezone.utc)
            firmware.ics_protocol_walk_error = None
            await db.commit()
            try:
                result = await _do_ics_protocol_walk(db, firmware_id)
                firmware.ics_protocol_walk_status = "completed"
                firmware.ics_protocol_walk_finished_at = dt.datetime.now(dt.timezone.utc)
                firmware.ics_protocol_walk_result = (
                    _stamp_firmware_ics_protocol_walk_result(result)
                )
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(type(exc), exc, exc.__traceback__)
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.ics_protocol_walk_status = "failed"
                        fail_row.ics_protocol_walk_finished_at = dt.datetime.now(dt.timezone.utc)
                        fail_row.ics_protocol_walk_error = err
                        # W2-β §SC5-NEW-ICS-S2-δ — clear partial JSONB on fail.
                        fail_row.ics_protocol_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "ics_protocol_walk: inner runner failed for %s", firmware_id,
                )
    except Exception:
        logger.exception(
            "ics_protocol_walk: unrecoverable outer failure for %s", firmware_id,
        )


# ---------------------------------------------------------------------------
# SAFE unpack-post-detection hook (Rule #39 — never raises).
# ---------------------------------------------------------------------------


async def auto_ics_protocol_walk_firmware_safe(firmware_id: uuid.UUID) -> None:
    """Auto-triggered post-detection hook (Rule #39 .safe contract).

    Owns own session. Runs the inner walker to populate the
    ``ics_protocol_walk_result`` JSONB so operators see the last-known
    result even on the first upload. DOES NOT mutate
    ``ics_protocol_walk_status`` — leaves it ``idle`` so an
    operator-triggered re-walk via ``trigger_ics_protocol_walk`` MCP tool
    works without a 409 conflict (Rule #39 .safe; Rule #47 manual
    re-trigger contract).

    Swallows exceptions silently with structured ``logger.exception`` per
    W2-β §SC5-NEW-ICS-S2-κ (silent-failure visibility — Rule #51
    partner). On exception, clears ``ics_protocol_walk_result`` to NULL
    per W2-β §SC5-NEW-ICS-S2-δ (no partial JSONB stamped on auto-fire
    failure).
    """
    try:
        async with async_session_factory() as db:
            firmware = await db.get(Firmware, firmware_id)
            if firmware is None:
                return
            try:
                result = await _do_ics_protocol_walk(db, firmware_id)
                firmware.ics_protocol_walk_result = (
                    _stamp_firmware_ics_protocol_walk_result(result)
                )
                # No status flip per Rule #39 .safe — operator MCP trigger
                # can still re-run from `idle` without 409 conflict.
                await db.commit()
            except Exception:
                await db.rollback()
                # W2-β §SC5-NEW-ICS-S2-δ — clear partial JSONB on fail.
                async with async_session_factory() as fail_db:
                    fail_row = await fail_db.get(Firmware, firmware_id)
                    if fail_row is not None:
                        fail_row.ics_protocol_walk_result = None
                        await fail_db.commit()
                logger.exception(
                    "auto_ics_protocol_walk_firmware_safe: inner failed for %s",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "auto_ics_protocol_walk_firmware_safe: unrecoverable for %s",
            firmware_id,
        )


__all__ = [
    "_do_ics_protocol_walk",
    "auto_ics_protocol_walk_firmware_safe",
    "run_ics_protocol_walk_background",
]
