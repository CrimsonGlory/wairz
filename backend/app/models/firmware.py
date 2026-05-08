import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class Firmware(Base):
    __tablename__ = "firmware"

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
    original_filename: Mapped[str | None] = mapped_column(String(255))
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int | None] = mapped_column(BigInteger)
    storage_path: Mapped[str | None] = mapped_column(String(512))
    extracted_path: Mapped[str | None] = mapped_column(String(512))
    extraction_dir: Mapped[str | None] = mapped_column(String(512))
    architecture: Mapped[str | None] = mapped_column(String(50))
    endianness: Mapped[str | None] = mapped_column(String(10))
    os_info: Mapped[str | None] = mapped_column(Text)
    kernel_path: Mapped[str | None] = mapped_column(String(512))
    version_label: Mapped[str | None] = mapped_column(String(100))
    unpack_log: Mapped[str | None] = mapped_column(Text)
    unpack_stage: Mapped[str | None] = mapped_column(String(100))
    unpack_progress: Mapped[int | None] = mapped_column(Integer)
    binary_info: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    device_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    cve_match_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    cve_match_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cve_match_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cve_match_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    cve_match_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    # SBOM vulnerability-scan 202+polling state (Rule #29 + Rule #33).
    # The synchronous endpoint at routers/sbom.py POST /vulnerabilities/scan
    # held a TCP connection idle for ~4m10s on 72 components; with the 16 GB
    # Illumisite image incoming and a cold Grype DB sync the scan can blow
    # past the SECURITY_SCAN_TIMEOUT (600s) ceiling. The persisted
    # SbomVulnerability rows ARE the result — no JSONB result column.
    vuln_scan_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    vuln_scan_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vuln_scan_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    vuln_scan_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Upload-time post-processing state (Rule #29 + Rule #33).
    # Synchronous tier was holding the TCP connection for 5+ minutes of
    # post-write CPU work (hash, archive extract, filesystem detection,
    # arch/endian/OS detect); the 16 GB Illumisite upload tripped the
    # frontend axios 600s ceiling. Detected_format is populated by
    # services/format_detection.detect_format() before the extracting
    # stage; capability is derived in the schema layer (no CHECK).
    upload_stage: Mapped[str] = mapped_column(
        String(16), nullable=False, server_default="ready"
    )
    upload_stage_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    upload_stage_finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    upload_stage_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_format: Mapped[str | None] = mapped_column(String(48), nullable=True)
    # Phase β Authenticode batch-validation 202+polling state.
    # _run_authenticode_chain_background walks every PE in the firmware's
    # hardware_firmware_blobs, runs the signify validator, and writes a
    # WindowsPESignature row per PE. The aggregate result lives here so
    # the frontend's last-known-result render survives session reloads.
    # Rule #33 .c CHECK constraint enforces the 5-state machine.
    authenticode_chain_status: Mapped[str] = mapped_column(
        String(20), nullable=False, server_default="idle"
    )
    authenticode_chain_started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authenticode_chain_finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    authenticode_chain_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    authenticode_chain_result: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    project: Mapped["Project"] = relationship(back_populates="firmware")  # noqa: F821

    __table_args__ = (
        Index("ix_firmware_project_id", "project_id"),
        UniqueConstraint("project_id", "sha256", name="uq_firmware_project_sha256"),
    )
