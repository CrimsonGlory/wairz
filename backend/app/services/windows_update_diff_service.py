"""Phase δ.5: Windows-Update KB-vs-KB diff background runner.

Dispatched via ``asyncio.create_task`` (Rule #33 .d — in-process pure-
Python diff + per-DLL incremental DB persistence; distinct from δ.4's
dotnet decompile which uses arq because ilspycmd is a worker-only
resource).

The runner walks every (older_kb, newer_kb) pair across the firmware's
``windows_update_packages`` rows (δ.1), SHA256s each DLL on both sides,
and UPSERTs a per-DLL row to ``windows_update_dll_diffs`` (δ.5). The
UniqueConstraint on (firmware_id, dll_path) means restart recovery is
automatic — a mid-run crash leaves already-completed rows in place;
the next run UPSERTs them with identical verdicts (idempotent).

Rule #36 no-execute discipline: this service operates on already-
extracted CAB/MSU contents (α-phase unpacker outputs); no installer
entry-point is invoked at any stage. SHA256 computation reads bytes
AS DATA via ``hashlib`` and ``open()``.

State machine (Rule #33 .a):
- idle → queued (set by the trigger MCP tool in δ.7)
- queued → running (set here at task start)
- running → completed | failed (set here at terminal)

Per-DLL incremental persistence: the runner emits one DB row per DLL
encountered, flushed in small batches (every ~100 DLLs) to bound the
transaction size. The per-DLL UniqueConstraint makes the
``insert(...).on_conflict_do_update`` UPSERT path natural — a re-run
overwrites prior verdicts with the latest computation.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import traceback
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.database import async_session_factory
from app.models.firmware import Firmware
from app.models.windows_update_dll_diff import WindowsUpdateDllDiff
from app.models.windows_update_package import WindowsUpdatePackage
from app.services.jsonb_normalizers import (
    _stamp_firmware_windows_update_diff_result,
)


logger = logging.getLogger(__name__)


# Tunables -------------------------------------------------------------------

# Hard ceiling on total run time. Pathological diffs (millions of DLLs across
# many KB pairs) shouldn't wedge the backend's task pool.
MAX_RUN_SECONDS = 1800

# Per-DLL UPSERT batch size. Smaller = more DB round-trips but smaller
# transaction recovery boundary; bigger = fewer round-trips but larger
# rollback cost on failure. 100 is the firmware-row aggregate sweet spot.
UPSERT_BATCH_SIZE = 100


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def run_windows_update_diff_background(firmware_id: uuid.UUID) -> None:
    """Run the KB-vs-KB diff workflow for a firmware (asyncio.create_task entry).

    Owns the full Rule #33 .a state machine: queued → running →
    completed/failed. Per-DLL state is incrementally persisted to
    windows_update_dll_diffs via UPSERT — restart recovery is automatic.
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
                    "run_windows_update_diff_background: firmware not "
                    "found (id=%s)",
                    firmware_id,
                )
                return

            row.windows_update_diff_status = "running"
            row.windows_update_diff_started_at = datetime.utcnow()
            await db.commit()

            try:
                aggregate = await asyncio.wait_for(
                    _do_diff_run(db, firmware_id),
                    timeout=MAX_RUN_SECONDS,
                )
                row = (
                    await db.execute(
                        select(Firmware).where(Firmware.id == firmware_id)
                    )
                ).scalar_one()
                row.windows_update_diff_status = "completed"
                row.windows_update_diff_finished_at = datetime.utcnow()
                row.windows_update_diff_result = (
                    _stamp_firmware_windows_update_diff_result(aggregate)
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
                        fail_row.windows_update_diff_status = "failed"
                        fail_row.windows_update_diff_finished_at = datetime.utcnow()
                        fail_row.windows_update_diff_error = err_msg
                        await fail_db.commit()
                logger.exception(
                    "run_windows_update_diff_background failed (firmware=%s)",
                    firmware_id,
                )
    except Exception:
        logger.exception(
            "run_windows_update_diff_background outer guard caught "
            "unrecoverable error (firmware=%s)",
            firmware_id,
        )


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


async def _do_diff_run(db, firmware_id: uuid.UUID) -> dict:
    """Inner runner — gathers KB pairs, computes per-DLL diffs, UPSERTs
    rows. Outer ``run_windows_update_diff_background`` owns transaction +
    status state.
    """
    start = time.monotonic()

    # Gather all packages for the firmware via the per-blob FK.
    from app.models.hardware_firmware import HardwareFirmwareBlob

    packages = (
        (
            await db.execute(
                select(WindowsUpdatePackage, HardwareFirmwareBlob)
                .join(
                    HardwareFirmwareBlob,
                    WindowsUpdatePackage.blob_id == HardwareFirmwareBlob.id,
                )
                .where(HardwareFirmwareBlob.firmware_id == firmware_id)
            )
        )
        .all()
    )

    # Build the (older_kb, newer_kb) pair set. The trigger MCP tool's
    # input shape (δ.7) lets the operator choose specific pairs; the
    # default mode used here is "all chronological pairs" — sort by
    # release_date and pair successive entries.
    pkg_rows = [pkg for pkg, _ in packages if pkg.kb_id]
    pkg_rows.sort(
        key=lambda p: (p.release_date or datetime.min, p.kb_id or "")
    )
    pairs: list[tuple[WindowsUpdatePackage, WindowsUpdatePackage]] = []
    for older, newer in zip(pkg_rows, pkg_rows[1:]):
        if older.kb_id != newer.kb_id:
            pairs.append((older, newer))

    by_pair: list[dict] = []
    dlls_added = dlls_removed = dlls_modified = dlls_unchanged = 0
    total_compared = 0
    errors: list[str] = []

    pending_rows: list[dict] = []

    for older, newer in pairs:
        try:
            older_files = _scan_pkg_dlls_sync(older)
            newer_files = _scan_pkg_dlls_sync(newer)
        except Exception as exc:
            errors.append(
                f"{older.kb_id}→{newer.kb_id}: scan failed: {exc}"
            )
            continue

        added = removed = modified = unchanged = 0
        for path, newer_meta in newer_files.items():
            older_meta = older_files.get(path)
            if older_meta is None:
                added += 1
                pending_rows.append(
                    _build_diff_row(
                        firmware_id=firmware_id,
                        dll_path=path,
                        older_kb=None,
                        newer_kb=newer.kb_id,
                        older_sha=None,
                        newer_sha=newer_meta["sha256"],
                        diff_type="added",
                        size_delta=None,
                    )
                )
            elif older_meta["sha256"] != newer_meta["sha256"]:
                modified += 1
                pending_rows.append(
                    _build_diff_row(
                        firmware_id=firmware_id,
                        dll_path=path,
                        older_kb=older.kb_id,
                        newer_kb=newer.kb_id,
                        older_sha=older_meta["sha256"],
                        newer_sha=newer_meta["sha256"],
                        diff_type="modified",
                        size_delta=newer_meta["size"] - older_meta["size"],
                    )
                )
            else:
                unchanged += 1
                pending_rows.append(
                    _build_diff_row(
                        firmware_id=firmware_id,
                        dll_path=path,
                        older_kb=older.kb_id,
                        newer_kb=newer.kb_id,
                        older_sha=older_meta["sha256"],
                        newer_sha=newer_meta["sha256"],
                        diff_type="unchanged",
                        size_delta=newer_meta["size"] - older_meta["size"],
                    )
                )
        for path, older_meta in older_files.items():
            if path not in newer_files:
                removed += 1
                pending_rows.append(
                    _build_diff_row(
                        firmware_id=firmware_id,
                        dll_path=path,
                        older_kb=older.kb_id,
                        newer_kb=None,
                        older_sha=older_meta["sha256"],
                        newer_sha=None,
                        diff_type="removed",
                        size_delta=None,
                    )
                )

        # Periodic flush so the DB carries durable state mid-run.
        if len(pending_rows) >= UPSERT_BATCH_SIZE:
            await _upsert_diff_rows(db, pending_rows)
            pending_rows = []

        dlls_added += added
        dlls_removed += removed
        dlls_modified += modified
        dlls_unchanged += unchanged
        total_compared += added + removed + modified + unchanged
        by_pair.append(
            {
                "older_kb": older.kb_id,
                "newer_kb": newer.kb_id,
                "added": added,
                "removed": removed,
                "modified": modified,
                "unchanged": unchanged,
            }
        )

    if pending_rows:
        await _upsert_diff_rows(db, pending_rows)

    return {
        "run_seconds": round(time.monotonic() - start, 2),
        "package_count": len(pkg_rows),
        "kb_pair_count": len(pairs),
        "dlls_compared": total_compared,
        "dlls_added": dlls_added,
        "dlls_removed": dlls_removed,
        "dlls_modified": dlls_modified,
        "dlls_unchanged": dlls_unchanged,
        "by_kb_pair": by_pair,
        "errors": errors,
    }


def _build_diff_row(
    *,
    firmware_id: uuid.UUID,
    dll_path: str,
    older_kb: str | None,
    newer_kb: str | None,
    older_sha: str | None,
    newer_sha: str | None,
    diff_type: str,
    size_delta: int | None,
) -> dict:
    """Build a dict suitable for ``insert(...).on_conflict_do_update``.
    Routing through a typed Pydantic Literal at the call site is the
    Rule #33 .c writer-boundary gate; this helper just shapes the row.
    """
    return {
        "firmware_id": firmware_id,
        "dll_path": dll_path,
        "older_kb": older_kb,
        "newer_kb": newer_kb,
        "older_sha256": older_sha,
        "newer_sha256": newer_sha,
        "diff_type": diff_type,
        "file_size_delta": size_delta,
    }


async def _upsert_diff_rows(db, rows: list[dict]) -> None:
    """UPSERT a batch of per-DLL diff rows on the
    (firmware_id, dll_path) natural key. Restart recovery: re-run
    overwrites prior verdicts with identical-or-fresher computation.
    """
    stmt = pg_insert(WindowsUpdateDllDiff).values(rows)
    stmt = stmt.on_conflict_do_update(
        constraint="uq_windows_update_dll_diffs_fw_path",
        set_={
            "older_kb": stmt.excluded.older_kb,
            "newer_kb": stmt.excluded.newer_kb,
            "older_sha256": stmt.excluded.older_sha256,
            "newer_sha256": stmt.excluded.newer_sha256,
            "diff_type": stmt.excluded.diff_type,
            "file_size_delta": stmt.excluded.file_size_delta,
            "updated_at": datetime.utcnow(),
        },
    )
    await db.execute(stmt)
    await db.flush()


def _scan_pkg_dlls_sync(pkg: WindowsUpdatePackage) -> dict[str, dict[str, Any]]:
    """Walk a package's extracted tree and return ``{rel_path: {sha256, size}}``.

    Reads the package's ``update_metadata['files']`` BOM if present; falls
    back to a filesystem walk under the package directory otherwise. Per
    Rule #36, this is pure DATA reading.
    """
    out: dict[str, dict[str, Any]] = {}
    meta = pkg.update_metadata or {}
    files = meta.get("files") if isinstance(meta, dict) else None
    if isinstance(files, list) and files:
        for entry in files:
            if not isinstance(entry, dict):
                continue
            path = entry.get("path")
            sha = entry.get("sha256")
            size = entry.get("size")
            if isinstance(path, str) and isinstance(sha, str):
                if not path.lower().endswith((".dll", ".exe", ".sys")):
                    continue
                out[path] = {"sha256": sha, "size": size if isinstance(size, int) else 0}
        return out
    # Fallback — walk the directory adjacent to package_path.
    base = os.path.dirname(pkg.package_path or "")
    if not base or not os.path.isdir(base):
        return out
    for dirpath, _dirs, filenames in os.walk(base):
        for fn in filenames:
            if not fn.lower().endswith((".dll", ".exe", ".sys")):
                continue
            full = os.path.join(dirpath, fn)
            try:
                st = os.stat(full)
                sha = hashlib.sha256(open(full, "rb").read()).hexdigest()
            except Exception:
                continue
            rel = os.path.relpath(full, base)
            out[rel] = {"sha256": sha, "size": st.st_size}
    return out
