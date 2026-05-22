import uuid
from datetime import datetime

from sqlalchemy import ARRAY, DateTime, ForeignKey, Index, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Finding(Base):
    __tablename__ = "findings"

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
    conversation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("conversations.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # title bumped 512 → 1024 on 2026-05-22 (over-constraint sweep, Rule #15
    # family). CRA / compliance / windows / ICS finding titles can include
    # OEM model + CWE list + check description and approach 512 chars;
    # 1024 covers the worst observed without runaway growth risk.
    title: Mapped[str] = mapped_column(String(1024), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    evidence: Mapped[str | None] = mapped_column(Text)
    # file_path bumped 512 → 2048 on 2026-05-22 — Windows long-paths in
    # Win11 ISO firmware (\Windows\WinSxS\amd64_microsoft-windows-...
    # nested paths) routinely exceed 512 chars; cf. windows_mft_record
    # already at String(4096) and windows_lnk_record at String(2048).
    file_path: Mapped[str | None] = mapped_column(String(2048))
    line_number: Mapped[int | None] = mapped_column(Integer)
    cve_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    cwe_ids: Mapped[list[str] | None] = mapped_column(ARRAY(String))
    confidence: Mapped[str | None] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open", server_default="open")
    source: Mapped[str] = mapped_column(String(50), default="manual", server_default="manual")
    component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="findings")  # noqa: F821

    __table_args__ = (
        Index("idx_findings_source", "source"),
    )
