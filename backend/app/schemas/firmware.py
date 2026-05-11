import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

# State machine for the upload-side 202+polling refactor (Rule #29 + #33).
# Mirrors the CHECK constraint ck_firmware_upload_stage on the firmware
# table (alembic revision d2e3f4a5b6c7).
UploadStage = Literal[
    "uploading",
    "hashing",
    "detecting",
    "extracting",
    "analyzing",
    "ready",
    "failed",
]

# Phase η.B.B Scheduled Task XML walker — Rule #33 .c Pydantic Literal
# typo-gate at the trigger MCP tool / status reader boundary. The DB
# CHECK constraint ``ck_firmware_scheduled_task_walk_status`` (alembic
# revision f9a0b1c2d3e4) is the durable safety floor; this Literal
# adds compile-time typo detection for new callers. Mirrors the
# VulnScanStatus / CveMatchStatus shapes from sbom.py /
# hardware_firmware.py.
ScheduledTaskWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase η.C.B LNK walker — Rule #33 .c Pydantic Literal typo-gate at
# the trigger MCP tool / status reader boundary. The DB CHECK
# constraint ``ck_firmware_lnk_walk_status`` (alembic revision
# c2e3f4a5b6d7) is the durable safety floor; this Literal adds
# compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus shape from η.B.B.
LnkWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase η.A.B NTFS $MFT walker — Rule #33 .c Pydantic Literal typo-gate
# at the trigger MCP tool / status reader boundary. The DB CHECK
# constraint ``ck_firmware_mft_walk_status`` (alembic revision
# 2a4b3c5d6e7f) is the durable safety floor; this Literal adds
# compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus / LnkWalkStatus shapes.
MftWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]


class FirmwareUploadResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    version_label: str | None = None
    created_at: datetime


class FirmwareUploadStatusResponse(BaseModel):
    """Response shape for the upload 202+polling refactor.

    Returned both by ``POST /firmware`` (the 202 ack with stage='detecting')
    and by ``GET /firmware/{id}/upload-status`` (every 2s poll until
    stage flips to ``ready`` or ``failed``). The fields beyond ``id`` and
    ``upload_stage`` are populated incrementally by the background runner
    as each stage completes — frontend reads them directly without an
    extra round-trip on completion.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    upload_stage: UploadStage
    upload_stage_error: str | None = None
    detected_format: str | None = None
    # Derived in the router from EXTRACTION_CAPABILITY[detected_format].
    # Keeps the canonical mapping in one place (services/format_detection.py)
    # while still letting the frontend render the banner without re-deriving.
    extraction_capability: str | None = None
    capability_note: str | None = None
    extracted_path: str | None = None
    architecture: str | None = None
    os_info: str | None = None
    upload_stage_started_at: datetime | None = None
    upload_stage_finished_at: datetime | None = None
    sha256: str | None = None
    file_size: int | None = None
    original_filename: str | None = None


class FirmwareUpdate(BaseModel):
    version_label: str | None = None


class BinaryInfoResponse(BaseModel):
    """Structured binary analysis results (stored as JSONB on Firmware)."""
    format: str | None = None
    architecture: str | None = None
    endianness: str | None = None
    bits: int | None = None
    is_static: bool | None = None
    is_pie: bool | None = None
    interpreter: str | None = None
    dependencies: list[str] = []
    entry_point: int | None = None
    file_size: int | None = None
    extracted_filename: str | None = None


class FirmwareDetailResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    extracted_path: str | None = None
    extraction_dir: str | None = None
    kernel_path: str | None
    version_label: str | None = None
    unpack_log: str | None
    unpack_stage: str | None = None
    unpack_progress: int | None = None
    binary_info: BinaryInfoResponse | None = None
    device_metadata: dict | None = None
    created_at: datetime


# ── Firmware Image Metadata schemas ──


class FirmwareSectionResponse(BaseModel):
    offset: int
    size: int | None
    type: str
    description: str


class UBootHeaderResponse(BaseModel):
    magic: str
    header_crc: str
    timestamp: int
    data_size: int
    load_address: str
    entry_point: str
    data_crc: str
    os_type: str
    architecture: str
    image_type: str
    compression: str
    name: str


class MTDPartitionResponse(BaseModel):
    name: str
    offset: int | None
    size: int


class FirmwareMetadataResponse(BaseModel):
    file_size: int
    sections: list[FirmwareSectionResponse] = []
    uboot_header: UBootHeaderResponse | None = None
    uboot_env: dict[str, str] = {}
    mtd_partitions: list[MTDPartitionResponse] = []


# ── Detection audit (Phase 5 extraction-integrity observability) ──


class FirmwareDetectionAuditResponse(BaseModel):
    """Per-firmware detection audit — surfaces orphan-rate + root coverage.

    Mirrors ``device_metadata['detection_audit']`` written by the detector
    (and the backfill script) plus a live-recomputed ``orphans_preview``
    populated only when the caller passes ``?recompute=true``.
    """

    firmware_id: uuid.UUID
    extracted_path: str | None = None
    detection_roots: list[str] = []
    audit: dict = {}
    orphans_preview: list[str] | None = None
