"""REST endpoints for device acquisition via the wairz-device-bridge."""

import uuid
from typing import cast

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.models.device_dump import DeviceDumpSession
from app.schemas.device import (
    DeviceBridgeStatus,
    DeviceDetailResponse,
    DeviceInfo,
    DeviceListResponse,
    DumpImportRequest,
    DumpImportResponse,
    DumpPartitionRequest,
    DumpPartitionStatus,
    DumpStatus,
    DumpStatusResponse,
)
from app.services.device_service import DeviceService, _normalize_partitions

router = APIRouter(
    prefix="/api/v1/projects/{project_id}/device",
    tags=["device-acquisition"],
)


def get_device_service(db: AsyncSession = Depends(get_db)) -> DeviceService:
    return DeviceService(db)


def _row_to_status(row: DeviceDumpSession) -> DumpStatusResponse:
    items = _normalize_partitions(row.partitions)
    return DumpStatusResponse(
        dump_id=str(row.id),
        status=cast(DumpStatus, row.status),
        device_id=row.device_id,
        partitions=[DumpPartitionStatus(**p) for p in items],
        bytes_written=int(row.bytes_written or 0),
        total_bytes=row.total_bytes,
        error=row.error,
        started_at=row.started_at.isoformat() if row.started_at else None,
        finished_at=row.finished_at.isoformat() if row.finished_at else None,
        created_at=row.created_at.isoformat() if row.created_at else None,
    )


@router.get("/status", response_model=DeviceBridgeStatus)
async def bridge_status(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Check if the device bridge is reachable."""
    return await service.get_bridge_status()


@router.get("/devices", response_model=DeviceListResponse)
async def list_devices(
    project_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """List connected ADB devices."""
    try:
        devices = await service.list_devices()
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    return DeviceListResponse(
        devices=[DeviceInfo(**d) for d in devices],
    )


@router.get("/devices/{device_id}/info", response_model=DeviceDetailResponse)
async def device_info(
    project_id: uuid.UUID,
    device_id: str,
    service: DeviceService = Depends(get_device_service),
):
    """Get device details including getprop and partitions."""
    try:
        info = await service.get_device_info(device_id)
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))

    return DeviceDetailResponse(
        device=DeviceInfo(serial=device_id),
        getprop=info["getprop"],
        partitions=info["partitions"],
        device_metadata=info.get("device_metadata"),
        chipset=info.get("chipset"),
    )


@router.post("/dumps", response_model=DumpStatusResponse, status_code=202)
async def start_dump(
    project_id: uuid.UUID,
    request: DumpPartitionRequest,
    service: DeviceService = Depends(get_device_service),
):
    """Start dumping partitions from a device.

    Idempotent + 409-on-conflict per Rule #33a: if a dump for this project is
    already queued or running, returns 409 with the existing dump_id rather
    than silently spawning a second concurrent runner. The 202 ack is fast
    (sub-second) since the actual dump work happens in
    ``_run_dump_background``.
    """
    active = await service.find_active_dump(project_id)
    if active is not None:
        raise HTTPException(
            status_code=409,
            detail=f"Device dump {active.id} already {active.status} for this project",
        )

    try:
        row = await service.start_dump(project_id, request.device_id, request.partitions)
    except ConnectionError as e:
        raise HTTPException(502, f"Device bridge unreachable: {e}")
    except ValueError as e:
        raise HTTPException(400, str(e))

    return _row_to_status(row)


@router.get("/dumps/{dump_id}/status", response_model=DumpStatusResponse)
async def dump_status(
    project_id: uuid.UUID,
    dump_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Get the status of a specific dump session.

    Pairs with the frontend's 1-2 s ``setInterval`` polling loop. The
    response carries the full row state (status enum, per-partition items,
    aggregate bytes, started_at / finished_at) so the page can render the
    progress UI directly.
    """
    row = await service.get_dump(project_id, dump_id)
    if row is None:
        raise HTTPException(404, "Dump not found")
    return _row_to_status(row)


@router.post("/dumps/{dump_id}/cancel", response_model=DumpStatusResponse)
async def cancel_dump(
    project_id: uuid.UUID,
    dump_id: uuid.UUID,
    service: DeviceService = Depends(get_device_service),
):
    """Cancel a queued or running dump. Idempotent on terminal states."""
    row = await service.cancel_dump(project_id, dump_id)
    if row is None:
        raise HTTPException(404, "Dump not found")
    return _row_to_status(row)


@router.post("/import", response_model=DumpImportResponse, status_code=201)
async def import_dump(
    project_id: uuid.UUID,
    request: DumpImportRequest,
    service: DeviceService = Depends(get_device_service),
):
    """Import a completed dump as firmware into the project."""
    try:
        firmware = await service.import_dump(
            project_id,
            uuid.UUID(request.dump_id),
            request.device_id,
            request.version_label,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except ConnectionError as e:
        raise HTTPException(502, str(e))

    return DumpImportResponse(
        firmware_id=str(firmware.id),
        device_metadata=firmware.device_metadata,
        message="Dump imported — unpack pipeline started",
    )
