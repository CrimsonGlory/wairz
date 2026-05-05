import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Index, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EmulationSession(Base):
    __tablename__ = "emulation_sessions"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"),
        nullable=False,
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20), default="created", server_default="created"
    )
    binary_path: Mapped[str | None] = mapped_column(String(512))
    arguments: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(String(50))
    port_forwards: Mapped[list[dict] | None] = mapped_column(JSONB, server_default="'[]'")
    container_id: Mapped[str | None] = mapped_column(String(100))
    error_message: Mapped[str | None] = mapped_column(Text)
    logs: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    stopped_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # System emulation (FirmAE) columns
    discovered_services: Mapped[list[dict] | None] = mapped_column(JSONB, nullable=True)
    system_emulation_stage: Mapped[str | None] = mapped_column(String(50), nullable=True)
    kernel_used: Mapped[str | None] = mapped_column(String(200), nullable=True)
    firmware_ip: Mapped[str | None] = mapped_column(String(50), nullable=True)
    nvram_state: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    idle_since: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    pcap_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    project: Mapped["Project"] = relationship(back_populates="emulation_sessions")  # noqa: F821

    __table_args__ = (
        Index("idx_emulation_project", "project_id"),
        Index("idx_emulation_status", "status"),
        Index("ix_emulation_sessions_container_id", "container_id"),
    )
