import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class CraAssessment(Base):
    __tablename__ = "cra_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    firmware_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("firmware.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    assessor_name: Mapped[str | None] = mapped_column(String(255))
    product_name: Mapped[str | None] = mapped_column(String(255))
    product_version: Mapped[str | None] = mapped_column(String(100))
    overall_status: Mapped[str] = mapped_column(
        String(20), default="in_progress", server_default="in_progress"
    )
    auto_pass_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    auto_fail_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    manual_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    not_tested_count: Mapped[int] = mapped_column(
        Integer, default=0, server_default="0"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    requirement_results: Mapped[list["CraRequirementResult"]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan"
    )
    project: Mapped["Project"] = relationship()  # noqa: F821


class CraRequirementResult(Base):
    __tablename__ = "cra_requirement_results"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cra_assessments.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    requirement_id: Mapped[str] = mapped_column(String(50), nullable=False)
    requirement_title: Mapped[str] = mapped_column(String(255), nullable=False)
    annex_part: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="not_tested", server_default="not_tested"
    )
    auto_populated: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default="false"
    )
    evidence_summary: Mapped[str | None] = mapped_column(Text)
    finding_ids: Mapped[list[str]] = mapped_column(
        JSONB, server_default="[]"
    )
    tool_sources: Mapped[list[str]] = mapped_column(
        JSONB, server_default="[]"
    )
    manual_notes: Mapped[str | None] = mapped_column(Text)
    manual_evidence: Mapped[str | None] = mapped_column(Text)
    related_cwes: Mapped[list[str]] = mapped_column(
        JSONB, server_default="[]"
    )
    related_cves: Mapped[list[str]] = mapped_column(
        JSONB, server_default="[]"
    )
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    assessment: Mapped["CraAssessment"] = relationship(
        back_populates="requirement_results"
    )
