"""Pydantic schemas for device acquisition endpoints."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class DeviceInfo(BaseModel):
    serial: str
    model: str | None = None
    device: str | None = None
    transport_id: str | None = None
    state: str = "device"
    # Acquisition-mode fields for MediaTek BROM / preloader devices. The
    # bridge (scripts/wairz-device-bridge.py) already populates these for
    # BROM/preloader discoveries, but they were silently stripped at the
    # router boundary (Pydantic default extra="ignore") so the frontend
    # saw them only via `as any` casts. Wide typing ('adb' | 'brom' |
    # 'preloader') matches the only values the bridge emits today.
    mode: str | None = None
    available: bool | None = None
    error: str | None = None


class DeviceBridgeStatus(BaseModel):
    connected: bool
    bridge_host: str | None = None
    bridge_port: int | None = None
    error: str | None = None


class DeviceListResponse(BaseModel):
    devices: list[DeviceInfo]


class PartitionInfo(BaseModel):
    name: str
    size: int | None = None


class DeviceDetailResponse(BaseModel):
    device: DeviceInfo
    getprop: dict[str, str] = {}
    partitions: list[str] = []
    partition_sizes: list[PartitionInfo] = []
    device_metadata: dict | None = None
    # MediaTek chipset identifier populated when the bridge runs `mtk printgpt`
    # and parses a chipset header (e.g. "MT6765", "MT6789"). Only present for
    # BROM/preloader devices; null for ADB devices whose chipset is surfaced
    # via getprop['ro.hardware.chipname'] instead.
    chipset: str | None = None


class DumpPartitionRequest(BaseModel):
    device_id: str = Field(..., description="ADB serial number")
    partitions: list[str] = Field(..., min_length=1, description="Partition names to dump")


# Pydantic enum mirroring the DB CHECK constraint
# (ck_device_dump_sessions_status). Keep these two in sync per Rule #33c.
DumpStatus = Literal[
    "queued", "running", "completed", "partial", "failed", "cancelled",
]


class DumpPartitionStatus(BaseModel):
    partition: str
    status: str  # pending, active, complete, failed, skipped
    bytes_written: int = 0
    total_bytes: int | None = None
    progress_percent: float | None = None
    throughput_mbps: float | None = None
    size: int | None = None
    error: str | None = None
    path: str | None = None


class DumpStatusResponse(BaseModel):
    """Full dump-session view returned by POST /dumps and GET /dumps/{id}/status.

    The ``status`` field uses the Rule #33c Literal so OpenAPI clients pick
    up the closed enum and any unknown value at the API boundary triggers a
    422 instead of leaking through.
    """

    dump_id: str
    status: DumpStatus
    device_id: str
    partitions: list[DumpPartitionStatus] = []
    bytes_written: int = 0
    total_bytes: int | None = None
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    created_at: str | None = None


class DumpImportRequest(BaseModel):
    dump_id: str = Field(..., description="Dump session id from POST /dumps")
    device_id: str = Field(..., description="ADB serial number")
    version_label: str | None = None


class DumpImportResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    firmware_id: str
    device_metadata: dict | None = None
    message: str
