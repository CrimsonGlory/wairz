import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, Depends, Form, HTTPException, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import async_session_factory, get_db
from app.models.firmware import Firmware
from app.models.project import Project
from app.schemas.firmware import (
    FirmwareDetailResponse,
    FirmwareDetectionAuditResponse,
    FirmwareMetadataResponse,
    FirmwareUpdate,
    FirmwareUploadResponse,
    FirmwareUploadStatusResponse,
)
from app.config import get_settings
from app.rate_limit import limiter
from app.services.firmware_metadata_service import FirmwareMetadataService
from app.services.firmware_paths import get_detection_roots
from app.services.firmware_service import (
    FirmwareService,
    _run_upload_post_processing_background,
)
from app.services.extraction_pipeline import run_unpack
from app.services.format_detection import (
    CAPABILITY_NOTES,
    EXTRACTION_CAPABILITY,
    DetectedFormat,
)
from app.services.jsonb_normalizers import (
    _normalize_firmware_device_metadata,
    _stamp_firmware_binary_info,
    _stamp_firmware_device_metadata,
)
from app.workers.unpack import detect_kernel

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# arq pool (lazy-initialised, with fallback to asyncio.create_task)
# ---------------------------------------------------------------------------
_arq_pool = None
_arq_unavailable = False


async def _get_arq_pool():
    """Return a shared arq connection pool, or None if arq is unavailable."""
    global _arq_pool, _arq_unavailable
    if _arq_unavailable:
        return None
    if _arq_pool is not None:
        return _arq_pool
    try:
        from arq import create_pool
        from app.workers.arq_worker import get_redis_settings
        _arq_pool = await create_pool(get_redis_settings())
        logger.info("arq pool connected — background jobs will use the worker queue")
        return _arq_pool
    except Exception:
        _arq_unavailable = True
        logger.warning(
            "arq pool unavailable — falling back to asyncio.create_task for background jobs"
        )
        return None

MAX_UPLOAD_BYTES = get_settings().max_upload_size_mb * 1024 * 1024


async def _check_upload_size(file: UploadFile, label: str = "file") -> None:
    """Reject uploads that exceed MAX_UPLOAD_SIZE_MB without reading the full body."""
    if file.size is not None and file.size > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413,
            f"{label} too large ({file.size / 1024 / 1024:.0f} MB). "
            f"Maximum is {get_settings().max_upload_size_mb} MB.",
        )

router = APIRouter(prefix="/api/v1/projects/{project_id}/firmware", tags=["firmware"])


def get_firmware_service(db: AsyncSession = Depends(get_db)) -> FirmwareService:
    return FirmwareService(db)


def _firmware_to_upload_status(firmware: Firmware) -> FirmwareUploadStatusResponse:
    """Build an upload-status response from a Firmware row.

    Derives ``extraction_capability`` and ``capability_note`` from the
    ``detected_format`` value via ``EXTRACTION_CAPABILITY`` and
    ``CAPABILITY_NOTES`` in ``services/format_detection.py`` — keeping the
    canonical mapping in one place so the frontend banner copy never
    drifts from the detection logic.
    """
    capability: str | None = None
    note: str | None = None
    if firmware.detected_format:
        try:
            fmt = DetectedFormat(firmware.detected_format)
        except ValueError:
            fmt = None
        if fmt is not None:
            cap = EXTRACTION_CAPABILITY.get(fmt)
            capability = cap.value if cap is not None else None
            note = CAPABILITY_NOTES.get(fmt)
    return FirmwareUploadStatusResponse(
        id=firmware.id,
        upload_stage=firmware.upload_stage,
        upload_stage_error=firmware.upload_stage_error,
        detected_format=firmware.detected_format,
        extraction_capability=capability,
        capability_note=note,
        extracted_path=firmware.extracted_path,
        architecture=firmware.architecture,
        os_info=firmware.os_info,
        upload_stage_started_at=firmware.upload_stage_started_at,
        upload_stage_finished_at=firmware.upload_stage_finished_at,
        sha256=firmware.sha256,
        file_size=firmware.file_size,
        original_filename=firmware.original_filename,
    )


@router.post("", response_model=FirmwareUploadStatusResponse, status_code=202)
@limiter.limit("5/minute")
async def upload_firmware(
    request: Request,
    project_id: uuid.UUID,
    file: UploadFile,
    version_label: str | None = Form(None),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Upload firmware (Rule #29 + Rule #33 202+polling).

    Returns 202 Accepted with the firmware row in
    ``upload_stage='detecting'`` as soon as the bytes have streamed to
    disk and dedup has cleared. The frontend polls
    ``GET /firmware/{id}/upload-status`` every 2 s
    (firmware-unpack precedent) until ``upload_stage`` flips to
    ``ready`` or ``failed``.

    Why 202 rather than 201: the synchronous tier was holding the TCP
    connection idle for 5+ minutes of post-write CPU work (SHA-256
    over multi-GB body, archive extraction, filesystem-root detection,
    arch/endian/OS detection) on the 16 GB Illumisite recovery image.
    The frontend axios 600 s ceiling tripped before the backend
    finished, surfacing a phantom "timeout" toast even though the
    backend kept running detached and committed the firmware row. See
    CLAUDE.md Rule #29 / Rule #33 + intake
    ``firmware-upload-progress-visibility-2026-05-07``.

    Idempotency: the dedup check inside ``upload_bytes_only`` returns
    409 if the (project_id, sha256) tuple already exists. There is no
    cross-request "in-flight" state for new uploads — each upload is a
    fresh row with a fresh storage_path.
    """
    await _check_upload_size(file, "Firmware")
    firmware = await service.upload_bytes_only(
        project_id, file, version_label=version_label
    )
    # Rule #33 (d) rubric: in-process post-processing + DB-incremental
    # progress + restart-friendly = asyncio.create_task is correct
    # (cve-match / vuln-scan precedent). No worker-resource coordination
    # needed; intermediate state is incrementally persisted by
    # _post_process_pipeline.
    asyncio.create_task(_run_upload_post_processing_background(firmware.id))
    return _firmware_to_upload_status(firmware)


@router.get(
    "/{firmware_id}/upload-status",
    response_model=FirmwareUploadStatusResponse,
)
async def get_firmware_upload_status(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
) -> FirmwareUploadStatusResponse:
    """Return the current upload-stage snapshot for a firmware row.

    Frontend polls this every 2 s after a 202 from ``POST /firmware``
    until ``upload_stage`` flips to ``ready`` or ``failed``. Mirrors
    the polling shape used by the firmware-unpack progress endpoint
    and the SBOM vuln-scan status endpoint.
    """
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    return _firmware_to_upload_status(firmware)


@router.get("", response_model=list[FirmwareDetailResponse])
async def list_firmware(
    project_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    return await service.list_by_project(project_id)


@router.get("/{firmware_id}", response_model=FirmwareDetailResponse)
async def get_single_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    return firmware


@router.patch("/{firmware_id}", response_model=FirmwareDetailResponse)
async def update_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    data: FirmwareUpdate,
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    update_data = data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(firmware, key, value)
    await service.db.flush()
    return firmware


@router.delete("/{firmware_id}", status_code=204)
async def delete_firmware(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    await service.delete(firmware)


@router.post("/{firmware_id}/unpack", response_model=FirmwareDetailResponse, status_code=202)
async def unpack(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    # Lock the project row to prevent concurrent unpack requests (TOCTOU race)
    proj_result = await db.execute(
        select(Project).where(Project.id == project_id).with_for_update()
    )
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if firmware.extracted_path:
        raise HTTPException(409, "Firmware already unpacked")

    if project.status == "unpacking":
        raise HTTPException(409, "Firmware is already being unpacked")

    if not os.path.exists(firmware.storage_path):
        raise HTTPException(410, "Firmware file not found on disk — please re-upload")

    # Update status to unpacking (row is locked, so no race)
    project.status = "unpacking"
    await db.flush()

    # Launch background task — prefer arq worker queue, fall back to in-process
    pool = await _get_arq_pool()
    if pool is not None:
        await pool.enqueue_job(
            "unpack_firmware_job",
            project_id=str(project_id),
            firmware_id=str(firmware_id),
            storage_path=firmware.storage_path,
        )
        logger.info("Enqueued unpack_firmware_job for firmware %s via arq", firmware_id)
    else:
        asyncio.create_task(
            _run_unpack_background(project_id, firmware_id, firmware.storage_path)
        )

    return firmware


async def _run_unpack_background(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    storage_path: str,
) -> None:
    """Run firmware unpacking in the background with its own DB session."""
    from app.services.event_service import event_service

    async def _update_progress(stage: str, progress: int) -> None:
        """Update firmware progress fields in the database and push SSE event."""
        async with async_session_factory() as db:
            fw_result = await db.execute(
                select(Firmware).where(Firmware.id == firmware_id)
            )
            firmware = fw_result.scalar_one_or_none()
            if firmware:
                firmware.unpack_stage = stage
                firmware.unpack_progress = progress
                await db.commit()
        try:
            await event_service.publish_progress(
                str(project_id), "unpacking",
                status="unpacking",
                progress=progress / 100.0,
                message=stage,
            )
        except Exception:
            pass  # SSE is best-effort

    try:
        output_base = os.path.dirname(storage_path)
        # Fetch the firmware row up-front so the dispatcher can consult
        # firmware.detected_format. Uses a short-lived session that
        # closes before the (potentially multi-minute) unpack runs;
        # progress updates and the post-extraction commit each open
        # their own sessions so the long-running unpack doesn't hold a
        # DB connection idle.
        async with async_session_factory() as db:
            fw_lookup = await db.execute(
                select(Firmware).where(Firmware.id == firmware_id)
            )
            dispatch_firmware = fw_lookup.scalar_one_or_none()

        if dispatch_firmware is None:
            logger.error("Background unpack: firmware %s missing at dispatch time", firmware_id)
            return

        result = await run_unpack(
            dispatch_firmware,
            output_base,
            _update_progress,
            firmware_id=firmware_id,
        )

        async with async_session_factory() as db:
            try:
                proj_result = await db.execute(
                    select(Project).where(Project.id == project_id)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
                firmware = fw_result.scalar_one_or_none()

                if not project or not firmware:
                    logger.error("Background unpack: project or firmware not found")
                    return

                if result.success:
                    firmware.extracted_path = result.extracted_path
                    firmware.extraction_dir = result.extraction_dir
                    firmware.architecture = result.architecture
                    firmware.endianness = result.endianness
                    firmware.os_info = result.os_info
                    firmware.kernel_path = result.kernel_path
                    firmware.binary_info = _stamp_firmware_binary_info(result.binary_info)
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    # Record vendor-AES auto-decrypt audit trail so the
                    # operator can reproduce the decryption from
                    # device_metadata alone (Rule #16 companion).
                    if result.vendor_decryption:
                        meta = dict(_normalize_firmware_device_metadata(firmware.device_metadata))
                        meta["vendor_decryption"] = result.vendor_decryption
                        # Recompute extraction_diagnostics.partial_extraction
                        # against the actual post-decrypt residual — see the
                        # arq_worker mirror at workers/arq_worker.py:122 for
                        # the same discipline. Without this, the UI's
                        # partial-extraction banner remains asserted even
                        # when every encrypted archive was successfully
                        # decrypted by the auto-AES pass.
                        from app.services.unpack_audit_service import (
                            recompute_extraction_diagnostics,
                        )
                        meta = recompute_extraction_diagnostics(meta)
                        firmware.device_metadata = _stamp_firmware_device_metadata(meta)
                    # Uniform detection_roots write for every successful
                    # unpack — includes primary roots from extracted_path
                    # + any decrypt-output dirs, realpath-deduplicated.
                    # Same helper used by upload-time tar / zip-rootfs
                    # shortcuts and the arq worker: single source of truth.
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
                    # Promote unpack-time discoveries (vendor_decryption,
                    # extraction_diagnostics) to Finding rows. Same post-
                    # commit-task shape as HW detection below; owns its
                    # own AsyncSession.
                    from app.services.unpack_audit_service import (
                        _run_safe as _run_unpack_audit_safe,
                    )
                    asyncio.create_task(
                        _run_unpack_audit_safe(firmware_id),
                    )

                    from app.workers.unpack import _run_hardware_firmware_detection_safe
                    asyncio.create_task(
                        _run_hardware_firmware_detection_safe(
                            firmware_id, result.extracted_path,
                        ),
                    )

                # Push SSE completion/error event
                try:
                    await event_service.publish_progress(
                        str(project_id), "unpacking",
                        status="completed" if result.success else "error",
                        progress=1.0 if result.success else None,
                        message="Extraction complete" if result.success else "Extraction failed",
                        extra={"architecture": result.architecture} if result.success else None,
                    )
                except Exception:
                    pass
            except Exception:
                await db.rollback()
                raise
    except Exception:
        logger.exception("Background firmware unpack failed for firmware %s", firmware_id)
    finally:
        # Guarantee project/firmware state is never stuck at "unpacking"
        try:
            async with async_session_factory() as db:
                proj_result = await db.execute(
                    select(Project).where(Project.id == project_id)
                )
                project = proj_result.scalar_one_or_none()
                fw_result = await db.execute(
                    select(Firmware).where(Firmware.id == firmware_id)
                )
                fw = fw_result.scalar_one_or_none()

                changed = False
                if project and project.status == "unpacking":
                    project.status = "error"
                    changed = True
                if fw and (fw.unpack_stage is not None or fw.unpack_progress is not None):
                    if not fw.extracted_path:
                        if not fw.unpack_log:
                            fw.unpack_log = (
                                f"Extraction failed or was interrupted at stage: "
                                f"{fw.unpack_stage or 'unknown'} "
                                f"({fw.unpack_progress or 0}% complete)."
                            )
                        fw.unpack_stage = None
                        fw.unpack_progress = None
                        changed = True
                if changed:
                    await db.commit()
        except Exception:
            logger.exception("Failed to reset status for project %s", project_id)


@router.post("/{firmware_id}/upload-rootfs", response_model=FirmwareDetailResponse)
async def upload_rootfs(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    file: UploadFile,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Upload a pre-extracted rootfs archive (.tar.gz, .tar, .zip) for firmware
    whose automated extraction failed."""
    await _check_upload_size(file, "Rootfs archive")
    proj_result = await db.execute(select(Project).where(Project.id == project_id))
    project = proj_result.scalar_one_or_none()
    if not project:
        raise HTTPException(404, "Project not found")

    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if firmware.extracted_path:
        raise HTTPException(409, "Firmware already has an extracted filesystem")

    try:
        await service.upload_rootfs(firmware, file)
    except ValueError as e:
        raise HTTPException(400, str(e))

    project.status = "ready"
    await db.flush()
    return firmware


@router.post("/{firmware_id}/redetect-kernel", response_model=FirmwareDetailResponse)
async def redetect_kernel(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Re-run kernel detection on already-extracted firmware."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    if not firmware.extracted_path:
        raise HTTPException(400, "Firmware has not been unpacked yet")

    extraction_dir = os.path.dirname(firmware.extracted_path)
    firmware.kernel_path = detect_kernel(extraction_dir, firmware.extracted_path)
    await db.flush()

    return firmware


@router.get("/{firmware_id}/metadata", response_model=FirmwareMetadataResponse)
async def get_firmware_metadata(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Get structural metadata for a firmware image (partitions, U-Boot, MTD)."""
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")
    if not firmware.storage_path:
        raise HTTPException(400, "Firmware file not available")

    metadata_service = FirmwareMetadataService()
    metadata = await metadata_service.scan_firmware_image(
        firmware.storage_path, firmware.id, db,
    )
    return metadata


@router.get("/{firmware_id}/audit", response_model=FirmwareDetectionAuditResponse)
async def get_firmware_detection_audit(
    project_id: uuid.UUID,
    firmware_id: uuid.UUID,
    recompute: bool = False,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Return the Phase-5 extraction-integrity audit for a firmware row.

    Reads ``device_metadata['detection_audit']`` stamped by the detector
    (and by the backfill script). When ``?recompute=true`` is passed, the
    endpoint additionally walks the resolved detection roots and returns
    up to 10 unclassified filenames as ``orphans_preview`` — a cheap
    regression signal without a full re-detection.
    """
    firmware = await service.get_by_id(firmware_id)
    if not firmware or firmware.project_id != project_id:
        raise HTTPException(404, "Firmware not found")

    metadata = dict(_normalize_firmware_device_metadata(firmware.device_metadata))
    audit = dict(metadata.get("detection_audit") or {})

    # Resolve roots up-front — cheap (JSONB cache) and needed for orphan preview.
    roots = await get_detection_roots(firmware, db=db)

    orphans_preview: list[str] | None = None
    if recompute:
        # Lazy-imported: pulls in HardwareFirmwareBlob + sqlalchemy, only
        # needed when the caller explicitly asks for a disk walk.
        from app.models.hardware_firmware import HardwareFirmwareBlob

        blob_rows = await db.execute(
            select(HardwareFirmwareBlob.blob_path).where(
                HardwareFirmwareBlob.firmware_id == firmware_id
            )
        )
        detected_paths = {
            os.path.realpath(p)
            for (p,) in blob_rows.all()
            if isinstance(p, str) and p
        }

        def _collect_orphans(walk_roots: list[str]) -> list[str]:
            found: list[str] = []
            for root in walk_roots:
                try:
                    for dirpath, _dirs, files in os.walk(root):
                        for name in files:
                            full = os.path.join(dirpath, name)
                            try:
                                real = os.path.realpath(full)
                            except OSError:
                                continue
                            if real in detected_paths:
                                continue
                            found.append(full)
                            if len(found) >= 10:
                                return found
                except OSError:
                    continue
            return found

        orphans_preview = await asyncio.to_thread(_collect_orphans, roots)

    return FirmwareDetectionAuditResponse(
        firmware_id=firmware.id,
        extracted_path=firmware.extracted_path,
        detection_roots=roots,
        audit=audit,
        orphans_preview=orphans_preview,
    )


# ── Backward-compatible endpoints (no firmware_id in path) ──
# These use the first/only firmware for the project, preserving existing behavior.


@router.post("/unpack", response_model=FirmwareDetailResponse, status_code=202, deprecated=True)
async def unpack_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy unpack endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await unpack(project_id, firmware.id, db, service)


@router.post("/redetect-kernel", response_model=FirmwareDetailResponse, deprecated=True)
async def redetect_kernel_legacy(
    project_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    service: FirmwareService = Depends(get_firmware_service),
):
    """Legacy redetect-kernel endpoint — uses first firmware for the project."""
    firmware = await service.get_by_project(project_id)
    if not firmware:
        raise HTTPException(404, "No firmware uploaded for this project")

    return await redetect_kernel(project_id, firmware.id, db, service)
