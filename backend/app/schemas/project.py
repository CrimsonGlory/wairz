import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, model_validator

from app.utils.firmware_selection import pick_active_firmware


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
    # Surfaced so the frontend can tell which versions are browsable (and
    # default the active-version picker to a loadable one).
    extracted_path: str | None = None
    storage_path: str | None = None
    version_label: str | None = None
    firmware_kind: Literal["linux", "rtos", "unknown"] = "unknown"
    firmware_kind_source: Literal["detected", "manual"] | None = None
    rtos_flavor: Literal["freertos", "zephyr", "baremetal-cortexm", "baremetal-mips16e"] | None = None
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
    # Mirrors ProjectListResponse so that the frontend Project type stays
    # consistent across list / detail / create / update flows.
    firmware_kind: Literal["linux", "rtos", "unknown"] | None = None
    rtos_flavor: Literal["freertos", "zephyr", "baremetal-cortexm", "baremetal-mips16e"] | None = None

    @model_validator(mode="after")
    def _populate_kind_from_firmware(self) -> "ProjectResponse":
        # Derive the project-level kind/flavor from the most recent *loadable*
        # firmware so a newer upload that failed to unpack doesn't flip the
        # project's kind (and hide analysis tabs) for a working older version.
        if self.firmware_kind is None and self.firmware:
            active = pick_active_firmware(self.firmware)
            if active is not None:
                self.firmware_kind = active.firmware_kind
                self.rtos_flavor = active.rtos_flavor
        return self


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
    rtos_flavor: Literal["freertos", "zephyr", "baremetal-cortexm", "baremetal-mips16e"] | None = None
