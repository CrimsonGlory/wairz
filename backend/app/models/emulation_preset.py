import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class EmulationPreset(Base):
    __tablename__ = "emulation_presets"

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
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    mode: Mapped[str] = mapped_column(String(20), nullable=False)
    binary_path: Mapped[str | None] = mapped_column(String(512))
    arguments: Mapped[str | None] = mapped_column(Text)
    architecture: Mapped[str | None] = mapped_column(String(50))
    port_forwards: Mapped[list[dict] | None] = mapped_column(JSONB, server_default="'[]'")
    kernel_name: Mapped[str | None] = mapped_column(String(255))
    init_path: Mapped[str | None] = mapped_column(String(512))
    pre_init_script: Mapped[str | None] = mapped_column(Text)
    stub_profile: Mapped[str] = mapped_column(String(50), nullable=False, server_default="none")
    # System-mode QEMU/boot overrides (all optional; None = auto-selected default).
    # Mirror start_emulation's agent-controllable knobs so a working bring-up
    # configuration can be saved and replayed.
    cpu: Mapped[str | None] = mapped_column(String(50))
    machine: Mapped[str | None] = mapped_column(String(50))
    nic_model: Mapped[str | None] = mapped_column(String(50))
    mem: Mapped[int | None] = mapped_column(Integer)
    smp: Mapped[int | None] = mapped_column(Integer)
    kernel_append: Mapped[str | None] = mapped_column(Text)
    initrd_path: Mapped[str | None] = mapped_column(String(512))
    dtb_path: Mapped[str | None] = mapped_column(String(512))
    drive_interface: Mapped[str | None] = mapped_column(String(20))
    root_dev: Mapped[str | None] = mapped_column(String(50))
    qemu_extra_args: Mapped[str | None] = mapped_column(Text)
    # Extra disk/partition images to attach + optionally mount, as a list of
    # {"path", "mount"?, "fstype"?} dicts.
    extra_drives: Mapped[list | None] = mapped_column(JSONB, server_default="'[]'")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="emulation_presets")  # noqa: F821
