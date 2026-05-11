"""Pydantic schemas for the structured report flow."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field

from app.schemas.finding import FindingResponse


class ReportStatus(str, Enum):
    draft = "draft"
    final = "final"


class TemplateSectionResponse(BaseModel):
    slug: str
    title: str
    required: bool
    order: int
    max_words: int | None = None
    guidance: str = ""


class ReportTemplateResponse(BaseModel):
    id: str
    name: str
    version: int
    language: str
    findings_order: int
    sections: list[TemplateSectionResponse]


class ReportSectionResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    report_id: uuid.UUID
    slug: str
    title: str
    content_md: str
    order_index: int
    updated_by: str
    updated_at: datetime


class ReportFindingResponse(BaseModel):
    """A finding attached to a report, with its inclusion flag."""

    finding: FindingResponse
    included: bool


class ReportRenderResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    report_id: uuid.UUID
    content_hash: str
    format: str
    byte_size: int
    created_at: datetime


class ReportSummary(BaseModel):
    """Lightweight report row for list views."""
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    template_id: str
    status: str
    title: str
    created_at: datetime
    finalized_at: datetime | None
    last_modified_at: datetime
    filled_section_count: int
    total_section_count: int


class ReportResponse(BaseModel):
    """Full report with sections and attached findings."""
    model_config = {"from_attributes": True}

    id: uuid.UUID
    project_id: uuid.UUID
    template_id: str
    status: str
    title: str
    created_at: datetime
    finalized_at: datetime | None
    sections: list[ReportSectionResponse]
    findings: list[ReportFindingResponse]
    renders: list[ReportRenderResponse]


class ReportCreate(BaseModel):
    template_id: str | None = None
    title: str | None = None


class ReportRename(BaseModel):
    title: str = Field(min_length=1, max_length=255)


class SectionUpsert(BaseModel):
    content_md: str = Field(default="")


class FindingInclusionUpdate(BaseModel):
    included: bool


class RenderRequest(BaseModel):
    format: str = Field(default="pdf", pattern="^(pdf|html)$")


class RenderResult(BaseModel):
    content_hash: str
    format: str
    byte_size: int
    download_url: str
    cached: bool
