"""Per-record Windows SRUM (System Resource Usage Monitor) table (Phase ζ.3.A).

One row per record extracted from a parsed ``SRUDB.dat`` ESEDB file.
Captures ~30-60 days of per-application + per-user resource usage —
network bytes sent/received, CPU foreground/background time, push
notifications, energy usage. Fed by the Phase ζ.3.B SRUM walker
(Rule #39 inner/outer/safe runner triplet).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. The ``source_path`` column stores
the path RELATIVE to the detection root (so multi-root firmware
re-extraction yields stable identifiers).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — SRUM is parsed by libesedb-python (read-only ESEDB binding);
nothing in wairz invokes esedbutil / Get-CimInstance SRUMState /
scriptable replay.

Per CLAUDE.md Rule #35c JSONB discipline: ``extra_metadata`` JSONB
carries type-specific overflow with schema_version stamping. See
``app.services.jsonb_normalizers._normalize_windows_srum_records_extra_metadata``.

Single-table strategy with ``record_type`` discriminator: see the
ζ.3.A migration docstring for rationale (schema simplicity, indexing
efficiency, future ζ.X SRUM extensions).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsSrumRecord(Base):
    """Per-record row from a walked ``SRUDB.dat`` ESEDB file."""

    __tablename__ = "windows_srum_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this record was parsed from.
    # Cascade DELETE so removing a firmware row removes its records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Discriminator — which SRUM GUID-table this row came from.
    # Tightened by ck_windows_srum_records_record_type CHECK constraint.
    record_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Path to the SRUDB.dat within the detection root.
    # Stored relative for stable cross-extraction identifiers.
    source_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Resolved app identifier (SruDbIdMapTable lookup at walker time).
    # Common values: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
    # "Microsoft.Windows.Cortana_cw5n1h2txyewy!CortanaUI". Falls back to
    # "id:N" when the lookup fails. Indexed.
    app_identifier: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # Resolved user identifier (SID or username). Falls back to "id:N".
    user_identifier: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # SRUM TimeStamp (the source row's authoritative timestamp).
    # Indexed jointly with firmware_id + record_type.
    recorded_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Per-record-type metric columns (nullable; only populated when
    # the discriminator matches the relevant SRUM GUID-table).

    # network_data_usage: bytes sent/received per app per interface.
    bytes_sent: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_received: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # application_resource_usage: bytes read/written by the app from
    # disk during the recorded interval.
    bytes_read: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    bytes_written: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # network_data_usage / network_connectivity: interface LUID
    # (locally unique identifier — joins with NetworkInterface.LUID
    # from a side-table SRUM provides; we surface the raw LUID for
    # operator triage).
    interface_luid: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # network_connectivity: connection duration in seconds.
    duration_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # application_resource_usage: foreground/background CPU seconds.
    cpu_foreground_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )
    cpu_background_seconds: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # push_notification: counter of push notifications during interval.
    push_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # energy_usage: estimated battery drain (charge units +
    # full-charge capacity at recording time).
    energy_charge: Mapped[int | None] = mapped_column(Integer, nullable=True)
    energy_capacity: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Type-specific overflow + future-proofing. Rule #35c stamped envelope.
    extra_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # "All rows of type X for firmware Y, newest first" — the
        # canonical operator query shape.
        Index(
            "ix_windows_srum_records_firmware_type_time",
            "firmware_id",
            "record_type",
            "recorded_at",
        ),
        # "All rows for app chrome.exe across types".
        Index(
            "ix_windows_srum_records_firmware_app",
            "firmware_id",
            "app_identifier",
        ),
    )
