"""Windows processes walker (Phase λ.β — memory-forensic-godmode).

Second Vol3-backed walker after λ.α.D. Invokes Volatility 3's
``windows.pslist`` / ``windows.psscan`` / ``windows.pstree`` /
``windows.cmdline`` plugin family against every ``memory_dump_image``
row whose ``os_family`` is ``"windows"`` OR ``"unknown"`` for a given
firmware, de-dupes process observations across the four plugins per
``(memory_image_id, pid, image_filename, create_time)``, and stamps:

- per-process ``VolatilityProcessRecord`` rows with bitfield columns
  ``seen_in_pslist`` / ``seen_in_psscan`` / ``seen_in_pstree``, the
  ``windows.cmdline``-derived ``command_line`` + ``image_path_full``,
  and a ``anomaly_flags`` JSONB with derived signals (unlinked,
  terminated, orphan, suspicious_path);
- per-firmware aggregate ``windows_processes_walk_result`` JSONB on
  ``Firmware``.

The pslist/psscan **delta** is the highest-value forensic signal — a
row with ``seen_in_psscan=True AND seen_in_pslist=False`` is the
canonical T1014 Rootkit DKOM-unlink indicator. Downstream finding-
emit hooks (deferred) consume the ``anomaly_flags`` directly without
re-deriving.

The walker is a CLAUDE.md Rule #39 inner/outer/safe triplet:

- :func:`_do_windows_processes_walk` — INNER pure-logic orchestrator.
  Caller owns ``db`` and the transaction. Resolves detection roots
  via :func:`app.services.firmware_paths.get_detection_roots`
  (Rule #16). Iterates ``MemoryDumpImage`` rows for the firmware,
  invokes :func:`app.services.vol3_runner.run_vol3_plugin` per
  (image, plugin) combination, dedupes via in-memory key, persists
  ``VolatilityProcessRecord`` rows, returns aggregate UNSTAMPED.
- :func:`run_windows_processes_walk_background` — OUTER state-machine
  wrapper. Owns its own session via ``async_session_factory``,
  transitions ``firmware.windows_processes_walk_status`` through
  ``idle → running → completed | failed``, stamps the aggregate.
- :func:`auto_windows_processes_walk_firmware_safe` — UNPACK-POST-
  DETECTION hook. Fire-and-forget; swallows all exceptions; does NOT
  mutate ``windows_processes_walk_status`` (leaves ``idle`` so an
  operator-driven re-trigger via the ``trigger_windows_processes_walk``
  MCP tool works without 409 conflict per Rule #33 .a).

Per CLAUDE.md Rule #36 + #45: argv discipline + deny-list discipline
are enforced at the ``vol3_runner`` boundary; the walker MUST NOT
construct its own argv or shell out — only call
``run_vol3_plugin(plugin="windows.pslist" | ...)``. The 4 plugin names
this walker invokes are HARD-PINNED in :data:`_PLUGINS_TO_RUN`; the
plugin name list is NOT operator-configurable through any caller path.

Per CLAUDE.md Rule #45 metadata-walker discipline: this walker is
PARSE-ONLY. It surfaces ``command_line`` strings AS DATA — never
executes the command, never resolves the binary, never expands
environment variables at scan time. The Rule #46 canary at
``test_windows_processes_walker.py::test_walker_source_scan_gate_canary_fires``
confirms the no-decrypt gate fires on synthetic violations.

Per CLAUDE.md Rule #33 .d (asyncio.create_task vs arq rubric): the
walker dispatches via ``asyncio.create_task`` because (i) the work is
in-process Python coordinated with subprocess-invocation of trusted
``vol`` parsing, (ii) per-process state is incrementally persisted
within the same outer task (mid-run crash recoverable via re-run +
unique-key replace), and (iii) "fire and observe via row-status" is
sufficient.
"""
from __future__ import annotations

import datetime as _dt
import logging
import time
import traceback
import uuid
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.memory_dump_image import MemoryDumpImage
from app.models.volatility_process_record import VolatilityProcessRecord
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import (
    _stamp_firmware_windows_processes_walk_result,
    _stamp_volatility_process_records_anomaly_flags,
)
from app.services.vol3_runner import (
    Vol3InvocationFailed,
    Vol3NotInstalled,
    Vol3PluginForbidden,
    Vol3Timeout,
    run_vol3_plugin,
)

logger = logging.getLogger(__name__)


# OS families this walker invokes Vol3 against. Raw acquisitions (no
# magic bytes) classify as ``unknown`` by the λ.α.B enumerator; Vol3's
# automagic LayerStacker can still classify them at scan time. Linux /
# Mac images are out-of-scope (the windows.* plugins fail on those).
_WALK_OS_FAMILIES: frozenset[str] = frozenset({"windows", "unknown"})

# HARD-PINNED plugin list per Rule #45/#36 discipline. The walker
# invokes exactly these 4 plugins per Windows image. The pslist/psscan
# delta is the canonical T1014 indicator; pstree supplements with parent
# linkage; cmdline supplements with command-line + image path.
_PLUGINS_TO_RUN: tuple[str, ...] = (
    "windows.pslist",
    "windows.psscan",
    "windows.pstree",
    "windows.cmdline",
)


# Canonical Microsoft system paths — used by the suspicious_path heuristic.
# Case-folded; the heuristic case-folds the image_path_full before lookup.
_TRUSTED_PATH_PREFIXES: tuple[str, ...] = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",  # fallback for top-level binaries (smss.exe etc.)
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "\\systemroot\\system32\\",
    "\\??\\c:\\windows\\system32\\",
)


def _empty_aggregate() -> dict:
    """Default aggregate when no work was done."""
    return {
        "image_count": 0,
        "process_count": 0,
        "by_plugin_seen": {
            "pslist": 0,
            "psscan": 0,
            "pstree": 0,
            "cmdline": 0,
        },
        "by_anomaly": {
            "unlinked": 0,
            "terminated": 0,
            "orphan": 0,
            "suspicious_path": 0,
        },
        "total_elapsed_s": 0.0,
        "errors_per_image": [],
    }


def _parse_vol3_datetime(raw: Any) -> _dt.datetime | None:
    """Coerce a Vol3 record's CreateTime / ExitTime value to a UTC datetime.

    Vol3 emits timestamps as ISO-8601 strings in jsonl mode (e.g.
    ``"2023-10-15T03:42:11+00:00"``) or as ``"N/A"`` / ``""`` when the
    field is unset. Returns ``None`` on any parse failure — the per-row
    persistence treats missing timestamps as legitimate (kernel idle
    process has no CreateTime).
    """
    if raw is None:
        return None
    if isinstance(raw, _dt.datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=_dt.UTC)
    if not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s or s.lower() in {"n/a", "none", "null"}:
        return None
    # Replace trailing "Z" with "+00:00" — fromisoformat accepts the latter.
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = _dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.UTC)
    return dt


def _int_or_none(raw: Any) -> int | None:
    """Coerce a Vol3 record's PID / PPID value to an int or None."""
    if raw is None:
        return None
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw
    if isinstance(raw, str):
        s = raw.strip()
        if not s or s.lower() in {"n/a", "none", "null"}:
            return None
        try:
            return int(s, 0)
        except ValueError:
            return None
    return None


def _record_key(rec: dict[str, Any]) -> tuple[int, str, _dt.datetime | None] | None:
    """De-dup key for a Vol3 process record across the 4 plugins.

    Returns ``None`` if the record lacks the essential identifying
    fields (PID + ImageFileName). The CreateTime portion is part of the
    key because Win10 recycles PIDs aggressively — two processes with
    the same PID at different times are legitimately distinct.
    """
    pid = _int_or_none(rec.get("PID"))
    if pid is None:
        return None
    name = rec.get("ImageFileName")
    if not isinstance(name, str) or not name:
        return None
    create_time = _parse_vol3_datetime(rec.get("CreateTime"))
    return (pid, name, create_time)


def _is_suspicious_path(image_path: str | None) -> bool:
    """Heuristic: image_path_full outside the Microsoft-vetted prefixes.

    PARSE-ONLY — does not invoke the binary, does not stat the path on
    disk, does not extract digital signatures. The heuristic is
    deliberately coarse so it's robust against Win10 build drift
    (System32 ⇄ SysWOW64 ⇄ %SystemRoot% indirection).
    """
    if not image_path:
        return False
    p = image_path.strip().lower()
    if not p:
        return False
    # Common kernel-side image paths use \\??\\ or \\SystemRoot\\
    # prefixes — case-fold once and check membership.
    for prefix in _TRUSTED_PATH_PREFIXES:
        if p.startswith(prefix.lower()):
            return False
    # Heuristic: also trust paths whose first component is windows.
    # Some Win10 images render System32 paths as
    # "\\Device\\HarddiskVolume3\\Windows\\System32\\..." — match these
    # tail-wise to avoid false positives.
    if "\\windows\\system32\\" in p or "\\windows\\syswow64\\" in p:
        return False
    return True


def _compute_anomaly_flags(
    seen_pslist: bool,
    seen_psscan: bool,
    exit_time: _dt.datetime | None,
    image_path: str | None,
    ppid: int | None,
    observed_pids: set[int],
) -> dict[str, Any]:
    """Derive the ``anomaly_flags`` dict for a single process row.

    ``observed_pids`` is the set of PIDs already de-duped across all
    plugins for the SAME memory image — used to detect orphans (ppid
    points to no observed parent). The kernel idle process (PID 0)
    legitimately has no parent and gets ``orphan=False``.
    """
    unlinked = seen_psscan and not seen_pslist
    terminated = exit_time is not None
    suspicious_path = _is_suspicious_path(image_path)
    orphan = False
    if ppid is not None and ppid != 0 and ppid not in observed_pids:
        orphan = True
    return _stamp_volatility_process_records_anomaly_flags(
        {
            "unlinked": unlinked,
            "terminated": terminated,
            "orphan": orphan,
            "suspicious_path": suspicious_path,
        }
    )


async def _walk_one_image(
    db: AsyncSession,
    image: MemoryDumpImage,
    aggregate: dict[str, Any],
) -> tuple[int, float, list[str]]:
    """Run the 4-plugin family against ONE memory image and persist records.

    Returns ``(processes_persisted, elapsed_s_total, per_image_errors)``.

    Vol3 invocations that fail mid-walk are recorded per-image AND
    counted toward aggregate.errors_per_image; the walk continues with
    the next plugin (or, in the case of Vol3NotInstalled, propagates up
    so the caller can abort the whole walk).
    """
    # Per-image deduped map keyed by (pid, image_filename, create_time).
    by_key: dict[
        tuple[int, str, _dt.datetime | None],
        dict[str, Any],
    ] = {}
    total_elapsed: float = 0.0
    per_image_errors: list[str] = []

    for plugin in _PLUGINS_TO_RUN:
        try:
            result = await run_vol3_plugin(image.image_path, plugin)
        except Vol3PluginForbidden:
            raise
        except Vol3NotInstalled:
            raise
        except (Vol3Timeout, Vol3InvocationFailed) as exc:
            msg = f"{image.image_filename}/{plugin}: {type(exc).__name__}: {exc}"[:512]
            logger.warning("windows_processes_walk: %s", msg)
            per_image_errors.append(msg)
            continue

        total_elapsed += result.elapsed_s
        plugin_short = plugin.split(".")[-1]  # pslist / psscan / pstree / cmdline
        aggregate["by_plugin_seen"][plugin_short] += len(result.records)

        for rec in result.records:
            key = _record_key(rec)
            if key is None:
                continue
            slot = by_key.setdefault(
                key,
                {
                    "pid": key[0],
                    "image_filename": key[1],
                    "create_time": key[2],
                    "ppid": None,
                    "command_line": None,
                    "image_path_full": None,
                    "exit_time": None,
                    "seen_in_pslist": False,
                    "seen_in_psscan": False,
                    "seen_in_pstree": False,
                },
            )
            if plugin_short == "pslist":
                slot["seen_in_pslist"] = True
                if slot["ppid"] is None:
                    slot["ppid"] = _int_or_none(rec.get("PPID"))
                if slot["exit_time"] is None:
                    slot["exit_time"] = _parse_vol3_datetime(rec.get("ExitTime"))
            elif plugin_short == "psscan":
                slot["seen_in_psscan"] = True
                if slot["ppid"] is None:
                    slot["ppid"] = _int_or_none(rec.get("PPID"))
                if slot["exit_time"] is None:
                    slot["exit_time"] = _parse_vol3_datetime(rec.get("ExitTime"))
            elif plugin_short == "pstree":
                slot["seen_in_pstree"] = True
                if slot["ppid"] is None:
                    slot["ppid"] = _int_or_none(rec.get("PPID"))
            elif plugin_short == "cmdline":
                args = rec.get("Args")
                if isinstance(args, str) and args.strip():
                    slot["command_line"] = args[:65536]
                    # Best-effort image-path extraction: split on first
                    # whitespace; strip surrounding quotes.
                    head = args.strip()
                    if head.startswith('"'):
                        end = head.find('"', 1)
                        if end > 1:
                            slot["image_path_full"] = head[1:end][:1024]
                    elif head:
                        slot["image_path_full"] = head.split()[0][:1024]

    # Persist de-duped rows. Replace any pre-existing rows for this
    # image (re-run dedup) — DELETE-then-INSERT semantics keep the
    # row identity simple for the SCAN_BY_KEY contract.
    await db.execute(
        delete(VolatilityProcessRecord).where(
            VolatilityProcessRecord.memory_image_id == image.id
        )
    )

    observed_pids: set[int] = {slot["pid"] for slot in by_key.values()}
    persisted = 0
    for slot in by_key.values():
        flags = _compute_anomaly_flags(
            seen_pslist=slot["seen_in_pslist"],
            seen_psscan=slot["seen_in_psscan"],
            exit_time=slot["exit_time"],
            image_path=slot["image_path_full"],
            ppid=slot["ppid"],
            observed_pids=observed_pids,
        )
        record = VolatilityProcessRecord(
            firmware_id=image.firmware_id,
            memory_image_id=image.id,
            pid=slot["pid"],
            ppid=slot["ppid"],
            image_filename=slot["image_filename"][:256],
            command_line=slot["command_line"],
            image_path_full=slot["image_path_full"],
            create_time=slot["create_time"],
            exit_time=slot["exit_time"],
            seen_in_pslist=slot["seen_in_pslist"],
            seen_in_psscan=slot["seen_in_psscan"],
            seen_in_pstree=slot["seen_in_pstree"],
            anomaly_flags=flags,
        )
        db.add(record)
        persisted += 1
        if flags.get("unlinked"):
            aggregate["by_anomaly"]["unlinked"] += 1
        if flags.get("terminated"):
            aggregate["by_anomaly"]["terminated"] += 1
        if flags.get("orphan"):
            aggregate["by_anomaly"]["orphan"] += 1
        if flags.get("suspicious_path"):
            aggregate["by_anomaly"]["suspicious_path"] += 1

    image.last_walked_at = _dt.datetime.now(_dt.UTC)
    return (persisted, total_elapsed, per_image_errors)


async def _do_windows_processes_walk(
    db: AsyncSession,
    firmware_id: uuid.UUID,
) -> dict:
    """INNER orchestrator — run the 4-plugin process family on every Windows image.

    Returns the per-firmware aggregate dict UNSTAMPED. Does NOT mutate
    ``firmware.windows_processes_walk_status`` — that's the OUTER
    wrapper's job. Does NOT commit — caller controls the transaction.
    """
    firmware = (
        await db.execute(select(Firmware).where(Firmware.id == firmware_id))
    ).scalar_one_or_none()
    if firmware is None:
        logger.warning(
            "windows_processes_walk: firmware %s vanished pre-walk", firmware_id
        )
        return _empty_aggregate()

    aggregate = _empty_aggregate()
    t0 = time.monotonic()

    # Rule #16 sanity — detection roots must exist; image enumeration uses
    # the MemoryDumpImage rows the λ.α.B enumerator persisted.
    detection_roots = await get_detection_roots(firmware, db=db, use_cache=True)
    if not detection_roots:
        aggregate["total_elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    images = (
        (
            await db.execute(
                select(MemoryDumpImage)
                .where(MemoryDumpImage.firmware_id == firmware_id)
                .where(MemoryDumpImage.os_family.in_(_WALK_OS_FAMILIES))
            )
        )
        .scalars()
        .all()
    )
    if not images:
        aggregate["total_elapsed_s"] = round(time.monotonic() - t0, 3)
        return aggregate

    for image in images:
        try:
            persisted, elapsed_s, errs = await _walk_one_image(
                db, image, aggregate
            )
        except Vol3NotInstalled as exc:
            aggregate["errors_per_image"].append(
                f"Vol3 not installed — rebuild worker with INCLUDE_VOL3=1 "
                f"({exc})"
            )
            break
        aggregate["image_count"] += 1
        aggregate["process_count"] += persisted
        aggregate["total_elapsed_s"] += elapsed_s
        if errs:
            aggregate["errors_per_image"].extend(errs)

    await db.flush()
    aggregate["total_elapsed_s"] = round(aggregate["total_elapsed_s"], 3)
    logger.info(
        "windows_processes_walk: firmware %s walked %d images "
        "(persisted=%d, unlinked=%d, errors=%d) in %.2fs",
        firmware_id,
        aggregate["image_count"],
        aggregate["process_count"],
        aggregate["by_anomaly"]["unlinked"],
        len(aggregate["errors_per_image"]),
        aggregate["total_elapsed_s"],
    )
    return aggregate


async def run_windows_processes_walk_background(firmware_id: uuid.UUID) -> None:
    """OUTER state-machine wrapper (Rule #33 .a + Rule #39 triplet)."""
    try:
        async with async_session_factory() as db:
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.windows_processes_walk_status = "running"
            firmware.windows_processes_walk_started_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_processes_walk_error = None
            await db.commit()

            try:
                aggregate = await _do_windows_processes_walk(db, firmware_id)
            except Exception as exc:  # noqa: BLE001 — outer guard captures all
                await db.rollback()
                err = "\n".join(
                    traceback.format_exception(
                        type(exc), exc, exc.__traceback__
                    )
                )[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (
                        await fail_db.execute(
                            select(Firmware).where(Firmware.id == firmware_id)
                        )
                    ).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.windows_processes_walk_status = "failed"
                        fail_row.windows_processes_walk_finished_at = (
                            _dt.datetime.now(_dt.UTC)
                        )
                        fail_row.windows_processes_walk_error = err
                        await fail_db.commit()
                logger.exception(
                    "windows_processes_walk failed for firmware %s", firmware_id
                )
                return

            firmware.windows_processes_walk_status = "completed"
            firmware.windows_processes_walk_finished_at = _dt.datetime.now(_dt.UTC)
            firmware.windows_processes_walk_result = (
                _stamp_firmware_windows_processes_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard; never crash the worker
        logger.exception(
            "unrecoverable error in run_windows_processes_walk_background"
        )


async def auto_windows_processes_walk_firmware_safe(
    firmware_id: uuid.UUID,
) -> None:
    """UNPACK-POST-DETECTION hook — fire-and-forget walker (Rule #39).

    Stamps the aggregate but leaves ``windows_processes_walk_status`` at
    ``idle`` so a future operator-driven re-trigger via the
    ``trigger_windows_processes_walk`` MCP tool succeeds without 409
    conflict (Rule #33 .a).
    """
    try:
        async with async_session_factory() as db:
            try:
                aggregate = await _do_windows_processes_walk(db, firmware_id)
            except Exception:  # noqa: BLE001 — safe-runner swallows per Rule #39
                logger.exception(
                    "auto windows_processes_walk failed for firmware %s",
                    firmware_id,
                )
                return
            firmware = (
                await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
            ).scalar_one_or_none()
            if firmware is None:
                return
            firmware.windows_processes_walk_result = (
                _stamp_firmware_windows_processes_walk_result(aggregate)
            )
            await db.commit()
    except Exception:  # noqa: BLE001 — outermost guard
        logger.exception(
            "unrecoverable error in auto_windows_processes_walk_firmware_safe"
        )


__all__ = [
    "_PLUGINS_TO_RUN",
    "_WALK_OS_FAMILIES",
    "_compute_anomaly_flags",
    "_do_windows_processes_walk",
    "_is_suspicious_path",
    "_record_key",
    "auto_windows_processes_walk_firmware_safe",
    "run_windows_processes_walk_background",
]
