"""arq background worker for heavy operations.

Runs as a separate process (``arq app.workers.arq_worker.WorkerSettings``)
and picks up jobs enqueued by the FastAPI backend.  Each job creates its own
async DB session via ``async_session_factory`` so it is fully independent of
the request lifecycle.
"""

import asyncio
import logging
import os
import shutil
import uuid

from arq.connections import RedisSettings
from arq.cron import cron
from sqlalchemy import select

from app.config import get_settings
from app.database import async_session_factory
from app.logging_config import configure_logging
from app.models.firmware import Firmware
from app.models.project import Project

# Route worker logs through structlog JSON pipeline (Phase 3 / O3). Called at
# import time so arq's own boot-phase logs (connection, registered functions)
# come out as JSON rather than plain text.
configure_logging(level=os.environ.get("LOG_LEVEL", "INFO"))

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Redis connection helper
# ---------------------------------------------------------------------------

def get_redis_settings() -> RedisSettings:
    """Build ``arq.RedisSettings`` from the app ``REDIS_URL``."""
    url = get_settings().redis_url  # e.g. redis://redis:6379/0
    return RedisSettings.from_dsn(url)


# ---------------------------------------------------------------------------
# Job: firmware unpacking
# ---------------------------------------------------------------------------

async def unpack_firmware_job(
    ctx: dict,
    *,
    project_id: str,
    firmware_id: str,
    storage_path: str,
) -> None:
    """Unpack firmware in the background (arq job).

    Mirrors ``_run_unpack_background`` from ``routers/firmware.py`` but runs
    inside the arq worker process rather than inside an ``asyncio.create_task``
    on the web server.
    """
    from app.workers.unpack import unpack_firmware  # local import to avoid circular

    pid = uuid.UUID(project_id)
    fid = uuid.UUID(firmware_id)

    from app.services.event_service import event_service
    try:
        await event_service.connect()
    except Exception:
        pass  # SSE is best-effort

    async def _update_progress(stage: str, progress: int) -> None:
        async with async_session_factory() as db:
            fw_result = await db.execute(
                select(Firmware).where(Firmware.id == fid)
            )
            firmware = fw_result.scalar_one_or_none()
            if firmware:
                firmware.unpack_stage = stage
                firmware.unpack_progress = progress
                await db.commit()
        try:
            await event_service.publish_progress(
                project_id, "unpacking",
                status="unpacking",
                progress=progress / 100.0,
                message=stage,
            )
        except Exception:
            pass

    try:
        output_base = os.path.dirname(storage_path)
        result = await unpack_firmware(storage_path, output_base, _update_progress, firmware_id=fid)

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == pid)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == fid)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("arq unpack job: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.binary_info = result.binary_info
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    # Vendor-AES auto-decrypt audit (Rule #16 companion).
                    if result.vendor_decryption:
                        meta = dict(firmware.device_metadata or {})
                        meta["vendor_decryption"] = result.vendor_decryption
                        firmware.device_metadata = meta
                    # Uniform detection_roots write — single-source-of-
                    # truth helper shared with the in-process /unpack
                    # runner and the upload-time shortcuts.
                    from app.services.firmware_paths import populate_detection_roots
                    populate_detection_roots(
                        firmware,
                        extra_roots=result.decryption_output_dirs,
                    )
                    project.status = "ready"
                else:
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    project.status = "error"

                await db.commit()

                # Fire hardware-firmware detection AFTER the commit so it
                # sees the latest device_metadata (vendor_decryption +
                # detection_roots). Used to be spawned inside
                # unpack_firmware() — moved here to avoid a race where
                # the HW detection's concurrent write clobbered the
                # decrypt audit on firmwares where detection finished
                # quickly (e.g. 0 detection roots).
                if result.success and result.extracted_path:
                    from app.workers.unpack import _run_hardware_firmware_detection_safe
                    asyncio.create_task(
                        _run_hardware_firmware_detection_safe(
                            uuid.UUID(firmware_id), result.extracted_path,
                        ),
                    )

                try:
                    await event_service.publish_progress(
                        project_id, "unpacking",
                        status="completed" if result.success else "error",
                        progress=1.0 if result.success else None,
                        message="Extraction complete" if result.success else "Extraction failed",
                    )
                except Exception:
                    pass
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("arq unpack job failed for firmware %s", firmware_id)
    finally:
        try:
            async with async_session_factory() as db:
                proj_result = await db.execute(
                    select(Project).where(Project.id == pid)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == fid)
                )
                firmware = fw_result.scalar_one_or_none()

                changed = False
                if project and project.status == "unpacking":
                    project.status = "error"
                    changed = True
                # Always clean up stuck firmware fields
                if firmware and (firmware.unpack_stage is not None or firmware.unpack_progress is not None):
                    if not firmware.extracted_path:
                        # Extraction never completed — record a useful log
                        if not firmware.unpack_log:
                            firmware.unpack_log = (
                                f"Extraction timed out or was interrupted at stage: "
                                f"{firmware.unpack_stage or 'unknown'} "
                                f"({firmware.unpack_progress or 0}% complete).\n"
                                f"The firmware may be too large for the current timeout. "
                                f"Try uploading a smaller image or increasing the worker timeout."
                            )
                        firmware.unpack_stage = None
                        firmware.unpack_progress = None
                        changed = True
                if changed:
                    await db.commit()
        except Exception:
            logger.exception("Failed to reset status for project %s", project_id)


# ---------------------------------------------------------------------------
# Job: Ghidra decompilation
# ---------------------------------------------------------------------------

async def run_ghidra_analysis_job(
    ctx: dict,
    *,
    binary_path: str,
    function_name: str,
    firmware_id: str,
) -> str:
    """Run Ghidra decompilation as a queued job.

    Returns the decompiled source text (or an error message).
    """
    from app.services.ghidra_service import decompile_function

    fid = uuid.UUID(firmware_id)

    async with async_session_factory() as db:
        try:
            result = await decompile_function(binary_path, function_name, fid, db)
            await db.commit()
            return result
        except Exception:
            await db.rollback()
            logger.exception(
                "arq Ghidra job failed: %s:%s", binary_path, function_name
            )
            raise


# ---------------------------------------------------------------------------
# Job: Grype vulnerability scan
# ---------------------------------------------------------------------------

async def run_vulnerability_scan_job(
    ctx: dict,
    *,
    firmware_id: str,
    project_id: str,
) -> dict:
    """Run Grype vulnerability scan as a queued job."""
    from app.services.grype_service import scan_with_grype

    fid = uuid.UUID(firmware_id)
    pid = uuid.UUID(project_id)

    async with async_session_factory() as db:
        try:
            result = await scan_with_grype(fid, pid, db)
            await db.commit()
            return result
        except Exception:
            await db.rollback()
            logger.exception("arq vulnerability scan job failed for firmware %s", firmware_id)
            raise


# ---------------------------------------------------------------------------
# Job: YARA scan
# ---------------------------------------------------------------------------

async def run_yara_scan_job(
    ctx: dict,
    *,
    project_id: str,
    extracted_paths: list[str],
) -> dict:
    """Run YARA scan across extracted firmware paths as a queued job.

    ``extracted_paths`` is a list of root paths (one per firmware version) to
    scan.  Results are stored as findings in the database.
    """
    import asyncio

    from sqlalchemy import delete

    from app.models.finding import Finding
    from app.schemas.finding import FindingCreate
    from app.services.finding_service import FindingService
    from app.services.security_audit import SecurityFinding

    pid = uuid.UUID(project_id)

    try:
        from app.services.yara_service import scan_firmware as yara_scan_firmware
    except ImportError:
        logger.warning("yara_service not available; skipping YARA scan job")
        return {"status": "unavailable"}

    async with async_session_factory() as db:
        try:
            # Clear previous yara_scan findings
            await db.execute(
                delete(Finding).where(
                    Finding.project_id == pid,
                    Finding.source == "yara_scan",
                )
            )
            await db.flush()

            loop = asyncio.get_running_loop()
            total_rules = 0
            total_scanned = 0
            total_matched = 0
            all_findings: list[SecurityFinding] = []

            for path in extracted_paths:
                scan_result = await loop.run_in_executor(
                    None, yara_scan_firmware, path
                )
                total_rules = max(total_rules, scan_result.rules_loaded)
                total_scanned += scan_result.files_scanned
                total_matched += scan_result.files_matched
                all_findings.extend(scan_result.findings)

            # Persist findings using the same pattern as security_audit router
            svc = FindingService(db)
            for sf in all_findings:
                await svc.create(
                    pid,
                    FindingCreate(
                        title=sf.title,
                        severity=sf.severity,
                        description=sf.description,
                        evidence=sf.evidence,
                        file_path=sf.file_path,
                        line_number=sf.line_number,
                        cwe_ids=sf.cwe_ids,
                        source="yara_scan",
                    ),
                )

            await db.commit()

            return {
                "status": "success",
                "rules_loaded": total_rules,
                "files_scanned": total_scanned,
                "files_matched": total_matched,
                "findings_created": len(all_findings),
            }
        except Exception:
            await db.rollback()
            logger.exception("arq YARA scan job failed for project %s", project_id)
            raise


# ---------------------------------------------------------------------------
# Job: kernel.org vulns.git sync (Phase 4 — kernel_subsystem Tier 5 backing)
# ---------------------------------------------------------------------------

async def sync_kernel_vulns_job(ctx: dict) -> dict:
    """Daily cron: sync ``vulns.git`` and rebuild the Redis subsystem index.

    Feeds :func:`cve_matcher._match_kernel_subsystem` (Tier 5).  Fail-soft
    at every step — a failed sync must never crash the arq worker.
    """
    from app.services.hardware_firmware import kernel_vulns_index as kvi

    try:
        result = await kvi.sync()
        logger.info("kernel_vulns sync: %s", result)
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("kernel_vulns sync failed: %s", exc)
        return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Job: emulation session spawn (Rule #29 202+polling refactor)
# ---------------------------------------------------------------------------

async def spawn_emulation_session_job(
    ctx: dict,
    *,
    session_id: str,
    firmware_id: str,
    kernel_name: str | None = None,
    init_path: str | None = None,
    pre_init_script: str | None = None,
    stub_profile: str = "none",
) -> None:
    """Spawn an emulation session's QEMU container (arq job).

    The REST handler POST /emulation/start creates a `pending` row,
    returns 202, and enqueues this job. The job runs the heavy Docker
    work — tar-stream firmware into container, fix permissions, inject
    stubs, launch QEMU, await health probe — and transitions the row
    through booting → ready (or error).

    Delegates to :meth:`EmulationService.spawn_session_background`,
    which owns the lifecycle logic. This job is a thin adapter for the
    arq queue; an `asyncio.create_task` fallback lives in
    `routers/emulation.py` for deployments without arq.
    """
    from app.services.emulation import EmulationService

    sid = uuid.UUID(session_id)
    fid = uuid.UUID(firmware_id)

    async with async_session_factory() as db:
        svc = EmulationService(db)
        await svc.spawn_session_background(
            session_id=sid,
            firmware_id=fid,
            kernel_name=kernel_name,
            init_path=init_path,
            pre_init_script=pre_init_script,
            stub_profile=stub_profile,
        )


# ---------------------------------------------------------------------------
# Cron: cleanup_emulation_expired (Phase 3 / O1)
# ---------------------------------------------------------------------------

async def cleanup_emulation_expired_job(ctx: dict) -> dict:
    """Reap emulation containers whose DB session exceeded ``emulation_timeout_minutes``.

    Delegates to :meth:`EmulationService.cleanup_expired`, which iterates
    ``EmulationSession`` rows with ``status='running'`` and calls
    ``stop_session`` on each row whose ``started_at`` is older than the
    configured timeout. Fail-soft — a docker-daemon blip must not crash
    the arq worker.
    """
    from app.services.emulation import EmulationService

    async with async_session_factory() as db:
        try:
            svc = EmulationService(db)
            reaped = await svc.cleanup_expired()
            await db.commit()
            logger.info("cleanup_emulation_expired: reaped=%s", reaped)
            return {"status": "ok", "reaped": reaped}
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            logger.exception("cleanup_emulation_expired failed: %s", exc)
            return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Cron: cleanup_fuzzing_orphans (Phase 3 / O1)
# ---------------------------------------------------------------------------

async def cleanup_fuzzing_orphans_job(ctx: dict) -> dict:
    """Reconcile fuzzing DB rows with live containers every 30 min.

    Delegates to :meth:`FuzzingService.cleanup_orphans`, which handles both
    sides of the reconciliation (DB-says-running-but-container-gone AND
    container-exists-but-DB-is-terminal). Fail-soft.
    """
    from app.services.fuzzing_service import FuzzingService

    async with async_session_factory() as db:
        try:
            svc = FuzzingService(db)
            result = await svc.cleanup_orphans()
            await db.commit()
            logger.info("cleanup_fuzzing_orphans: %s", result)
            return {"status": "ok", **result}
        except Exception as exc:  # noqa: BLE001
            await db.rollback()
            logger.exception("cleanup_fuzzing_orphans failed: %s", exc)
            return {"status": "error", "error": str(exc)}


# ---------------------------------------------------------------------------
# Cron: reconcile_firmware_storage (infra-volumes V4) — log-only
# ---------------------------------------------------------------------------

async def reconcile_firmware_storage_job(ctx: dict) -> dict:
    """Daily reconcile: find DB-vs-disk drift in firmware extractions.

    Two classes of drift:
      1. **Missing extractions** — a ``Firmware`` row points at an
         ``extracted_path`` that no longer exists on disk (user deleted it
         manually, volume got recreated, etc).
      2. **Orphan directories** — an extraction directory exists on disk
         with no corresponding ``Firmware`` row (crashed during upload,
         row was deleted but disk wasn't cleaned up).

    v1: LOG ONLY. Do not auto-delete. Operators review ``worker`` logs for
    any ``missing_dirs`` / ``orphan_dirs`` counts and decide manually.
    Auto-cleanup of orphan dirs is planned for v2 once the default has been
    validated against a few months of real-world deployment.

    When ``settings.firmware_retention_days`` is set to an integer N, rows
    older than N days are also surfaced in the log output so operators
    have a running tally for a future retention pass.
    """
    from datetime import datetime, timedelta

    settings = get_settings()
    root = settings.storage_root
    retention_days = settings.firmware_retention_days

    try:
        async with async_session_factory() as db:
            stmt = select(Firmware).where(Firmware.extracted_path.isnot(None))
            firmware_rows = (await db.execute(stmt)).scalars().all()
    except Exception as exc:
        logger.exception("reconcile_firmware_storage: DB query failed: %s", exc)
        return {"status": "error", "error": str(exc)}

    db_paths = {r.extracted_path for r in firmware_rows if r.extracted_path}

    missing_dirs = [
        str(r.id) for r in firmware_rows
        if r.extracted_path and not os.path.isdir(r.extracted_path)
    ]

    # Scan the projects tree for orphan extraction directories. Guard
    # against the root volume missing (fresh install with nothing uploaded
    # yet) and against individual per-project permission glitches — log
    # and move on.
    orphan_dirs: list[str] = []
    projects_root = os.path.join(root, "projects")
    if os.path.isdir(projects_root):
        try:
            project_ids = os.listdir(projects_root)
        except OSError as exc:
            logger.warning(
                "reconcile_firmware_storage: cannot list %s: %s",
                projects_root, exc,
            )
            project_ids = []

        for pid in project_ids:
            proj_fw_dir = os.path.join(projects_root, pid, "firmware")
            if not os.path.isdir(proj_fw_dir):
                continue
            try:
                fw_entries = os.listdir(proj_fw_dir)
            except OSError:
                continue
            for fw_id in fw_entries:
                extracted = os.path.join(proj_fw_dir, fw_id, "extracted")
                if os.path.isdir(extracted) and extracted not in db_paths:
                    orphan_dirs.append(extracted)

    # Retention-days signal. We intentionally do NOT auto-delete; log the
    # count so operators can run a retention sweep at their own cadence.
    aged_rows = 0
    if retention_days is not None and retention_days > 0:
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        aged_rows = sum(
            1 for r in firmware_rows
            if r.created_at and r.created_at < cutoff
        )

    if missing_dirs:
        logger.warning(
            "reconcile_firmware_storage: %d firmware rows have missing "
            "extraction directories: %s",
            len(missing_dirs),
            missing_dirs[:10] + (["…"] if len(missing_dirs) > 10 else []),
        )
    if orphan_dirs:
        logger.warning(
            "reconcile_firmware_storage: %d extraction directories have no "
            "DB row: %s",
            len(orphan_dirs),
            orphan_dirs[:10] + (["…"] if len(orphan_dirs) > 10 else []),
        )
    if aged_rows:
        logger.warning(
            "reconcile_firmware_storage: %d firmware rows are older than the "
            "configured retention (%d days) — review for manual cleanup",
            aged_rows, retention_days,
        )
    if not (missing_dirs or orphan_dirs or aged_rows):
        logger.info(
            "reconcile_firmware_storage: %d firmware rows, no drift",
            len(firmware_rows),
        )
    return {
        "status": "ok",
        "missing_dirs": len(missing_dirs),
        "orphan_dirs": len(orphan_dirs),
        "aged_rows": aged_rows,
        "total_rows": len(firmware_rows),
        "retention_days": retention_days,
    }


# ---------------------------------------------------------------------------
# Cron: cleanup_tmp_dumps (infra-volumes V2)
# ---------------------------------------------------------------------------

async def cleanup_tmp_dumps_job(ctx: dict) -> dict:
    """Daily cleanup of ``/tmp/wairz-dumps`` — 7-day age cut.

    The dump directory is a host bind-mount (``docker-compose.yml:155,
    213``) used by the device-acquisition bridge. Dumps persist across
    container restarts and may contain sensitive firmware bytes; without
    this reaper they accumulate until host reboot or manual cleanup.

    Strategy: walk top-level entries, delete any whose ``mtime`` is older
    than 7 days. Directories use ``shutil.rmtree``; files use
    ``os.unlink``. Individual-entry errors are logged but don't abort the
    sweep — partial progress is better than no progress on a noisy host.
    """
    import time
    from datetime import timedelta

    tmpdir = "/tmp/wairz-dumps"
    if not os.path.isdir(tmpdir):
        return {"status": "ok", "deleted": 0, "reason": "tmpdir-missing"}

    cutoff = time.time() - timedelta(days=7).total_seconds()
    deleted = 0
    errors = 0
    for name in os.listdir(tmpdir):
        path = os.path.join(tmpdir, name)
        try:
            if os.path.getmtime(path) >= cutoff:
                continue
            if os.path.isfile(path) or os.path.islink(path):
                os.unlink(path)
            elif os.path.isdir(path):
                shutil.rmtree(path, ignore_errors=False)
            else:
                continue
            deleted += 1
        except OSError as exc:
            logger.warning("cleanup_tmp_dumps: failed to delete %s: %s", path, exc)
            errors += 1

    if deleted or errors:
        logger.info(
            "cleanup_tmp_dumps: tmpdir=%s deleted=%d errors=%d",
            tmpdir, deleted, errors,
        )
    return {"status": "ok", "deleted": deleted, "errors": errors, "tmpdir": tmpdir}


# ---------------------------------------------------------------------------
# Cron: check_storage_quota (infra-volumes V1)
# ---------------------------------------------------------------------------

async def check_storage_quota_job(ctx: dict) -> dict:
    """Hourly disk-usage audit of ``settings.storage_root``.

    Logs at WARNING when usage exceeds 80% and at ERROR past 90%. Returns a
    dict with ``used_pct`` / ``free_gb`` for the arq result backend so
    operators can tail the history via ``docker compose logs worker`` or
    the arq Redis job result. Fail-soft — a transient ``OSError`` (NFS
    blip, volume unmount mid-scan) must not crash the worker.
    """
    settings = get_settings()
    root = settings.storage_root
    try:
        total, used, free = shutil.disk_usage(root)
    except OSError as exc:
        logger.exception("check_storage_quota: disk_usage(%s) failed: %s", root, exc)
        return {"status": "error", "error": str(exc)}

    used_pct = (used / total) * 100 if total else 0.0
    free_gb = free // (1024**3)
    payload = {
        "status": "ok",
        "root": root,
        "used_pct": round(used_pct, 2),
        "free_gb": free_gb,
        "total_gb": total // (1024**3),
    }
    if used_pct > 90:
        logger.error(
            "check_storage_quota: CRITICAL %s is %.1f%% full (%d GB free)",
            root, used_pct, free_gb,
        )
    elif used_pct > 80:
        logger.warning(
            "check_storage_quota: WARNING %s is %.1f%% full (%d GB free)",
            root, used_pct, free_gb,
        )
    else:
        logger.info(
            "check_storage_quota: %s is %.1f%% full (%d GB free)",
            root, used_pct, free_gb,
        )
    return payload


# ---------------------------------------------------------------------------
# Cron: cleanup_analysis_cache (backend-cache-module-extraction-and-ttl)
# ---------------------------------------------------------------------------

async def cleanup_analysis_cache_job(ctx: dict) -> dict:
    """Delete ``analysis_cache`` rows older than the configured retention.

    The JSONB ``result`` column on ``analysis_cache`` is used by Ghidra
    decompilations, JADX class dumps, mobsfscan reports, manifest scans,
    bytecode scans, and component maps — all multi-megabyte per row under
    realistic firmware loads. Without a TTL the table grows unboundedly.

    The retention window is ``settings.analysis_cache_retention_days``
    (default 30). Returns a dict with the deletion count for the arq
    result backend.
    """
    from app.services import _cache

    days = get_settings().analysis_cache_retention_days
    async with async_session_factory() as db:
        deleted = await _cache.cleanup_older_than(db, days=days)
        await db.commit()

    if deleted:
        logger.info(
            "cleanup_analysis_cache: retention_days=%d deleted=%d", days, deleted,
        )
    return {"status": "ok", "retention_days": days, "deleted": deleted}


# ---------------------------------------------------------------------------
# arq WorkerSettings — discovered by ``arq app.workers.arq_worker.WorkerSettings``
# ---------------------------------------------------------------------------

class WorkerSettings:
    """Configuration class consumed by the arq CLI runner."""

    functions = [
        unpack_firmware_job,
        run_ghidra_analysis_job,
        run_vulnerability_scan_job,
        run_yara_scan_job,
        sync_kernel_vulns_job,
        spawn_emulation_session_job,
        cleanup_emulation_expired_job,
        cleanup_fuzzing_orphans_job,
        check_storage_quota_job,
        cleanup_tmp_dumps_job,
        reconcile_firmware_storage_job,
        cleanup_analysis_cache_job,
    ]

    # Scheduled cron jobs. Phase 3 / O1 adds the two cleanup reapers;
    # infra-volumes-quotas-and-backup adds storage / tmp / reconcile;
    # backend-cache-module-extraction-and-ttl adds analysis_cache cleanup.
    #   - sync_kernel_vulns_job           : daily 03:00 UTC (Tier 5 CVE feed)
    #   - cleanup_emulation_expired_job   : every 30 min (timeout-based reap)
    #   - cleanup_fuzzing_orphans_job     : every 30 min, offset 15 min (DB<->container)
    #   - check_storage_quota_job         : every hour at :15 (V1 disk-quota audit)
    #   - cleanup_tmp_dumps_job           : daily 04:00 UTC (V2 dump reaper)
    #   - reconcile_firmware_storage_job  : daily 05:00 UTC (V4 drift detector, log-only)
    #   - cleanup_analysis_cache_job      : daily 06:00 UTC (analysis_cache TTL)
    # Staggering the reapers prevents them from contending for the same arq
    # worker slot on a busy host. ``unique=True`` (the arq default)
    # guarantees single execution across multiple worker processes.
    cron_jobs = [
        cron(sync_kernel_vulns_job, hour=3, minute=0),
        cron(cleanup_emulation_expired_job, minute={5, 35}),
        cron(cleanup_fuzzing_orphans_job, minute={20, 50}),
        cron(check_storage_quota_job, minute=15),
        cron(cleanup_tmp_dumps_job, hour=4, minute=0),
        cron(reconcile_firmware_storage_job, hour=5, minute=0),
        cron(cleanup_analysis_cache_job, hour=6, minute=0),
    ]

    redis_settings = get_redis_settings()

    # Must exceed the longest extraction pipeline (Android sparse → simg2img →
    # super partition scan → EROFS/ext4 extract → unblob fallback).  On RPi
    # hardware with multi-GB images the Android pipeline alone can take 15-20
    # minutes, and unblob's own timeout is 1200s.
    job_timeout = 1800  # 30 minutes
    max_jobs = 4
    poll_delay = 0.5  # seconds between Redis polls
