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

# Phase θ.A.B Windows Boot Configuration Data (BCD) walker — Rule #33 .c
# Pydantic Literal typo-gate at the trigger MCP tool / status reader
# boundary. The DB CHECK constraint ``ck_firmware_bcd_walk_status``
# (alembic revision 2a5b3c4d5e6f) is the durable safety floor; this
# Literal adds compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus / LnkWalkStatus / MftWalkStatus shapes.
BcdWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase θ.B.C Windows WMI persistence walker — Rule #33 .c Pydantic
# Literal typo-gate at the trigger MCP tool / status reader boundary.
# The DB CHECK constraint ``ck_firmware_wmi_walk_status`` (alembic
# revision 5d8e6f9c0a2b) is the durable safety floor; this Literal
# adds compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus / LnkWalkStatus / MftWalkStatus /
# BcdWalkStatus shapes.
WmiWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase θ.C.B Windows ESP `.efi` PE chain walker — Rule #33 .c Pydantic
# Literal typo-gate at the trigger MCP tool / status reader boundary.
# The DB CHECK constraint ``ck_firmware_esp_walk_status`` (alembic
# revision 8b9c0d1e2f3a) is the durable safety floor; this Literal
# adds compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus / LnkWalkStatus / MftWalkStatus /
# BcdWalkStatus / WmiWalkStatus shapes.
EspWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase θ.C.A WindowsEspEntry.authenticode_state — Rule #33 .c Pydantic
# Literal typo-gate. The DB CHECK constraint
# ``ck_windows_esp_entries_authenticode_state`` (alembic revision
# 7a8b9c0d1e2f) is the durable safety floor.
EspAuthenticodeState = Literal[
    "signed_valid",
    "signed_expired",
    "signed_revoked",
    "unsigned",
    "parse_failed",
]

# Phase θ.E.B Windows MBR/VBR boot-sector walker — Rule #33 .c Pydantic
# Literal typo-gate at the trigger MCP tool / status reader boundary.
# The DB CHECK constraint ``ck_firmware_mbr_vbr_walk_status`` (alembic
# revision bc0d1e2f3a4b) is the durable safety floor; this Literal
# adds compile-time typo detection for new callers. Mirrors the
# ScheduledTaskWalkStatus / LnkWalkStatus / MftWalkStatus /
# BcdWalkStatus / WmiWalkStatus / EspWalkStatus shapes.
MbrVbrWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase θ.E.A WindowsMbrVbrSector.sector_kind — Rule #33 .c Pydantic
# Literal typo-gate. The DB CHECK constraint
# ``ck_windows_mbr_vbr_sectors_sector_kind`` (alembic revision
# ab0c1d2e3f4a) is the durable safety floor.
MbrVbrSectorKind = Literal[
    "mbr",
    "vbr_fat32",
    "vbr_ntfs",
    "vbr_fat16",
    "vbr_exfat",
    "unknown",
]

# Phase θ.D.C SDB shim walker — Rule #33 .c Pydantic Literal typo-gate
# at the trigger MCP tool / status reader boundary. The DB CHECK
# constraint ``ck_firmware_sdb_walk_status`` (alembic revision
# bc1d2e3f4a5b) is the durable safety floor; this Literal adds
# compile-time typo detection for new callers. Mirrors the
# MbrVbrWalkStatus / EspWalkStatus / WmiWalkStatus / BcdWalkStatus
# shapes.
SdbWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase ι.A.B Linux journald walker — Rule #33 .c Pydantic Literal
# typo-gate at the trigger MCP tool / status reader boundary. FIRST
# LINUX walker in wairz's portfolio (Phases η + θ shipped 10
# Windows-only walkers). The DB CHECK constraint
# ``ck_firmware_journald_walk_status`` (alembic revision fb3a4b5c6d7e)
# is the durable safety floor; this Literal adds compile-time typo
# detection for new callers. Mirrors the SdbWalkStatus / MbrVbrWalkStatus
# / EspWalkStatus / WmiWalkStatus / BcdWalkStatus shapes.
JournaldWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase ι.B.B Linux systemd unit-file walker — Rule #33 .c Pydantic
# Literal typo-gate at the trigger MCP tool / status reader boundary.
# SECOND LINUX walker in wairz's portfolio (ι.A shipped journald;
# Phases η + θ shipped 10 Windows-only walkers). The DB CHECK
# constraint ``ck_firmware_systemd_walk_status`` (alembic revision
# aabbccddee02) is the durable safety floor; this Literal adds
# compile-time typo detection for new callers. Mirrors the
# JournaldWalkStatus / SdbWalkStatus / MbrVbrWalkStatus shapes.
SystemdWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase ι.C.B Windows ETW .etl walker — Rule #33 .c Pydantic Literal
# typo-gate at the trigger MCP tool / status reader boundary. FIRST ι
# Windows-side walker (ι.A + ι.B shipped Linux walkers — journald +
# systemd). The DB CHECK constraint ``ck_firmware_etl_walk_status``
# (alembic revision aabbccddee05) is the durable safety floor; this
# Literal adds compile-time typo detection for new callers. Mirrors
# the SystemdWalkStatus / JournaldWalkStatus / SdbWalkStatus shapes.
EtlWalkStatus = Literal[
    "idle", "queued", "running", "completed", "failed"
]

# Phase θ.D.B WindowsSdbEntry.sdb_kind — Rule #33 .c Pydantic
# Literal typo-gate. The DB CHECK constraint
# ``ck_windows_sdb_entries_sdb_kind`` (alembic revision
# ab1c2d3e4f5a) is the durable safety floor.
SdbKind = Literal[
    "microsoft",
    "custom",
    "unknown",
]

# Phase θ.D.B WindowsSdbEntry.shim_class — Rule #33 .c Pydantic
# Literal typo-gate. The DB CHECK constraint
# ``ck_windows_sdb_entries_shim_class`` (alembic revision
# ab1c2d3e4f5a) is the durable safety floor. The 4 known-bad shim
# primitives (RedirectEXE / InjectDll / GetCommandLineW /
# RedirectShortcut) are the canonical T1546.011 Application
# Shimming attacker tradecraft (DLL injection, EXE replacement,
# argument-injection, shortcut hijack).
SdbShimClass = Literal[
    "RedirectEXE",
    "InjectDll",
    "GetCommandLineW",
    "RedirectShortcut",
    "Custom",
    "Patch",
    "Other",
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
