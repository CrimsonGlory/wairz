import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class ProjectCreate(BaseModel):
    name: str
    description: str | None = None


class ProjectUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class FirmwareResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    original_filename: str | None
    sha256: str
    file_size: int | None
    architecture: str | None
    endianness: str | None
    os_info: str | None
    version_label: str | None = None
    firmware_kind: Literal["linux", "rtos", "unknown"] = "unknown"
    firmware_kind_source: Literal["detected", "manual"] | None = None
    rtos_flavor: Literal["freertos", "zephyr", "baremetal-cortexm"] | None = None
    created_at: datetime


class ProjectResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    firmware: list[FirmwareResponse] = []


class ProjectListResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    description: str | None
    status: str
    created_at: datetime
    updated_at: datetime
    # Surface the active firmware's kind so the sidebar can filter analysis
    # tabs without fetching each project's full detail. Null when no
    # firmware has been uploaded for the project yet.
    firmware_kind: Literal["linux", "rtos", "unknown"] | None = None
    rtos_flavor: Literal["freertos", "zephyr", "baremetal-cortexm"] | None = None
