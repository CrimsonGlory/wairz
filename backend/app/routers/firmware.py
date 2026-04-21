import asyncio
import logging
import os
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, Form, HTTPException, Request, UploadFile
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
)
from app.config import get_settings
from app.rate_limit import limiter
from app.services.firmware_metadata_service import FirmwareMetadataService
from app.services.firmware_paths import get_detection_roots
from app.services.firmware_service import FirmwareService
from app.workers.unpack import detect_kernel, unpack_firmware

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


@router.post("", response_model=FirmwareUploadResponse, status_code=201)
@limiter.limit("5/minute")
async def upload_firmware(
    request: Request,
    project_id: uuid.UUID,
    file: UploadFile,
    background_tasks: BackgroundTasks,
    version_label: str | None = Form(None),
    service: FirmwareService = Depends(get_firmware_service),
):
    await _check_upload_size(file, "Firmware")
    firmware = await service.upload(project_id, file, version_label=version_label)
    # Fire hardware-firmware detection for uploads that extract at upload-time
    # (tar shortcut, zip-rootfs shortcut). The /unpack path already fires its
    # own detection post-commit (bede8a5). Before this hook, shortcut uploads
    # skipped HW detection entirely, leaving hardware_firmware_blobs empty
    # until a manual re-unpack. BackgroundTasks runs AFTER the response is
    # returned — by which time get_db has committed the firmware row, so the
    # detection's own session reads a consistent snapshot (same
    # post-commit invariant as bede8a5).
    if firmware.extracted_path:
        from app.workers.unpack import _run_hardware_firmware_detection_safe
        background_tasks.add_task(
            _run_hardware_firmware_detection_safe,
            firmware.id,
            firmware.extracted_path,
        )
    return firmware


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
        result = await unpack_firmware(storage_path, output_base, _update_progress, firmware_id=firmware_id)

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
                    firmware.binary_info = result.binary_info
                    firmware.unpack_log = result.unpack_log
                    firmware.unpack_stage = None
                    firmware.unpack_progress = None
                    # Record vendor-AES auto-decrypt audit trail so the
                    # operator can reproduce the decryption from
                    # device_metadata alone (Rule #16 companion).
                    if result.vendor_decryption:
                        meta = dict(firmware.device_metadata or {})
                        meta["vendor_decryption"] = result.vendor_decryption
                        firmware.device_metadata = meta
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

    metadata = dict(firmware.device_metadata or {})
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
