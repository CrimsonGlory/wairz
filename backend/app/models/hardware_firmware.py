from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String, Text, UniqueConstraint, func, text
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class HardwareFirmwareBlob(Base):
    """Hardware firmware blob detected in an extracted firmware image."""

    __tablename__ = "hardware_firmware_blobs"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Location
    blob_path: Mapped[str] = mapped_column(String(1024), nullable=False)
    partition: Mapped[str | None] = mapped_column(String(64))
    blob_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Classification
    # category: modem|tee|wifi|bluetooth|gpu|dsp|camera|audio|sensor|touchpad|nfc|usb|
    #           display|fingerprint|dtb|kernel_module|bootloader|other
    category: Mapped[str] = mapped_column(String(32), nullable=False)
    # vendor: qualcomm|mediatek|samsung|broadcom|nvidia|imagination|arm|apple|cypress|
    #         unisoc|hisilicon|intel|realtek|unknown
    vendor: Mapped[str | None] = mapped_column(String(64))
    # format: qcom_mbn|mbn_v3|mbn_v5|mbn_v6|elf|dtb|dtbo|ko|fw_bcm|raw_bin|
    #         tzbsp|kinibi_mclf|optee_ta|shannon_toc|mtk_gfh|mtk_preloader
    format: Mapped[str] = mapped_column(String(32), nullable=False)

    # Versioning & signing
    version: Mapped[str | None] = mapped_column(String(128))
    signed: Mapped[str] = mapped_column(String(16), default="unknown")
    signature_algorithm: Mapped[str | None] = mapped_column(String(64))
    cert_subject: Mapped[str | None] = mapped_column(Text)
    chipset_target: Mapped[str | None] = mapped_column(String(64))

    # Graph refs
    driver_references: Mapped[list[str] | None] = mapped_column(ARRAY(Text))
    sbom_component_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("sbom_components.id", ondelete="SET NULL"),
    )

    # Parser extras (MBN header flags, DTB compatible strings, entry points, etc.)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, server_default=text("'{}'"))

    # Rule #52 — domain triple "vendor/family/domain" from the chip-family
    # catalog (services/hardware_firmware/chip_catalog.py). Populated by
    # the bare_metal_audit walker post-match (auto-detected) OR by an
    # operator-supplied descriptor (bare_metal_descriptors table).
    chip_target: Mapped[str | None] = mapped_column(String(128), nullable=True)

    detection_source: Mapped[str] = mapped_column(String(64), nullable=False)
    detection_confidence: Mapped[str] = mapped_column(String(16), default="medium")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint("firmware_id", "blob_sha256", name="uq_hwfw_firmware_sha256"),
        Index("ix_hwfw_firmware_category", "firmware_id", "category"),
        Index("ix_hwfw_vendor", "vendor"),
        Index("ix_hwfw_sha256", "blob_sha256"),
        Index("ix_hardware_firmware_blobs_chip_target", "chip_target"),
    )
