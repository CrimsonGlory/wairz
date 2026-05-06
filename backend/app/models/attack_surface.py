import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, Integer, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class AttackSurfaceEntry(Base):
    __tablename__ = "attack_surface_entries"

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
    )
    binary_path: Mapped[str] = mapped_column(Text, nullable=False)
    binary_name: Mapped[str] = mapped_column(Text, nullable=False)
    architecture: Mapped[str | None] = mapped_column(Text, nullable=True)
    file_size: Mapped[int | None] = mapped_column(Integer, nullable=True)
    attack_surface_score: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0",
    )
    score_breakdown: Mapped[dict] = mapped_column(
        JSONB, nullable=False, default=dict, server_default="{}",
    )
    is_setuid: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    is_network_listener: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    is_cgi_handler: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    has_dangerous_imports: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false",
    )
    dangerous_imports: Mapped[list | None] = mapped_column(
        JSONB, default=list, server_default="[]",
    )
    input_categories: Mapped[list | None] = mapped_column(
        JSONB, default=list, server_default="[]",
    )
    auto_findings_generated: Mapped[bool | None] = mapped_column(
        Boolean, default=False, server_default="false",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="attack_surface_entries")  # noqa: F821

    __table_args__ = (
        Index(
            "ix_attack_surface_project_firmware_score",
            "project_id",
            "firmware_id",
            attack_surface_score.desc(),
        ),
        Index("ix_attack_surface_firmware_id", "firmware_id"),
    )
