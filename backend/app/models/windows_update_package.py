"""Windows-Update package table.

One row per detected update package in a hardware-firmware blob
(FK→``hardware_firmware_blobs.id``, ON DELETE CASCADE). A single firmware
may carry multiple packages (cumulative + security-only + servicing-stack
+ .NET cumulative side-by-side in a captured WIM; or successive KBs
side-by-side after a pending-reboot install).

The ``update_metadata`` JSONB column carries the parsed manifest payload
under the canonical schema documented in
``app.services.jsonb_normalizers._normalize_windows_update_packages_update_metadata``.
Schema version is stamped by the writer via the matching ``_stamp_*``
helper so future manifest-parser shape revisions can be discriminated at
the read boundary (Rule #35c).

CHECK on ``package_type`` enforces the discriminator allowlist (Rule #33
.c gate). Matching Pydantic ``WindowsUpdatePackageType`` Literal at the
writer boundary catches code-side typos at load time.

Rule #36 no-execute discipline: this table holds DATA only — the δ-phase
workers parse package manifests (msitools / cabextract / pefile) and
write parsed metadata here; nothing in wairz invokes ``setup.exe``,
``wusa.exe``, ``dism.exe /Add-Package``, or any update-installer entry
point. The package is read AS DATA via cab/msu unpacking; never executed.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    String,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsUpdatePackage(Base):
    """Per-package Windows-Update record for a hardware-firmware blob."""

    __tablename__ = "windows_update_packages"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the hardware-firmware blob that contained this package. Cascade
    # DELETE so removing a blob row removes its update-package rows.
    blob_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path within the blob's extracted tree; e.g.
    # "Windows/servicing/Packages/Package_for_KB5036893~....cab".
    package_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Discriminator. The matching DB CHECK + Pydantic Literal pair
    # (Rule #33 .c) gate writes at both layers. Common values: msu,
    # cab_cumulative (LCU), cab_security, cab_sru (servicing-stack
    # update), cab_lcu, cab_dotnet (.NET CU), msi, msix, unknown.
    package_type: Mapped[str] = mapped_column(
        String(32), nullable=False, server_default="unknown"
    )

    # KB identifier extracted from the manifest (typically "KB5036893").
    # NULL = manifest didn't surface a KB.
    kb_id: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Most-recent KB known to supersede this package. NULL = this is the
    # latest in the supersedence chain. The full chain lives in
    # ``update_metadata.supersedence``; this scalar column is the indexed
    # answer to "is this still effective?".
    superseded_by_kb: Mapped[str | None] = mapped_column(String(32), nullable=True)

    # Release date from the package manifest (the "Last Modified" header
    # on the support article). NULL = manifest didn't carry it.
    release_date: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Full parsed manifest payload. See the matching normaliser for the
    # canonical shape; writers stamp schema_version via
    # ``_stamp_windows_update_packages_update_metadata``.
    update_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )

    __table_args__ = (
        # Rule #33 .c — DB-side allowlist matched by the writer-side
        # Pydantic ``WindowsUpdatePackageType`` Literal.
        CheckConstraint(
            "package_type IN ("
            "'msu', 'cab_cumulative', 'cab_security', 'cab_sru', "
            "'cab_lcu', 'cab_dotnet', 'msi', 'msix', 'unknown'"
            ")",
            name="ck_windows_update_packages_type",
        ),
        # One package per (blob, package_path); re-detections UPDATE-not-INSERT.
        UniqueConstraint(
            "blob_id",
            "package_path",
            name="uq_windows_update_packages_blob_path",
        ),
        Index("ix_windows_update_packages_blob_id", "blob_id"),
        Index("ix_windows_update_packages_kb_id", "kb_id"),
        Index("ix_windows_update_packages_package_type", "package_type"),
        Index(
            "ix_windows_update_packages_superseded_by_kb",
            "superseded_by_kb",
        ),
    )
