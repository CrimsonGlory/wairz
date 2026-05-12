"""add windows_etl_events table (Phase ι.C.A — FIRST ι WINDOWS-SIDE WALKER)

Revision ID: aabbccddee04
Revises: aabbccddee03
Create Date: 2026-05-12 18:00:00.000000

Phase ι.C.A — adds the per-event landing zone for the THIRD ι walker
in wairz's portfolio (FIRST ι Windows-side; ι.A + ι.B were both Linux).
The Phase ι.C.C walker parses Event Tracing for Windows (ETW) ``.etl``
binary trace-log files extracted from Windows firmware captures
(typically under ``Windows/System32/WDI/LogFiles/*.etl`` /
``Windows/System32/winevt/Logs/*.etl`` /
``Windows/System32/LogFiles/WMI/*.etl`` / ``Windows/Logs/CBS/*.etl`` /
``Windows/Logs/NetSetup/*.etl`` / ``Windows/Logs/WindowsBackup/*.etl`` /
``Windows/Logs/WindowsUpdate/*.etl`` paths per Rule #16) via the
Fox-IT ``dissect.etl`` library (AGPL-3.0, v3.14 released 2025-11-20;
**Rule #19 evidence-first probe ran 2026-05-12T15:45Z**: package
installs cleanly; API surface confirmed: ``ETL(fh)`` consumes a
binary file-handle, iteration yields ``EventRecord`` instances whose
``.header`` carries ``provider_id`` (UUID) + ``timestamp`` (datetime)
+ standard fields, and ``.event`` lazily resolves manifest-bound
payloads when available — perfect fit for the wairz walker shape).

Surfaces per-event forensic-triage metadata:

- **Path + session identity** (etl_file_path + etl_session_name) —
  absolute path inside firmware extract + ETW logger session name
  pulled from the file's LogfileHeader.
- **Provider identity** (provider_guid + provider_name) — canonical
  ETW provider GUID and manifest-resolved provider name when available.
- **Event identity** (event_id + event_version + event_channel +
  event_level + event_opcode + event_keywords + event_task) — full
  EventDescriptor surface, capturing the schema-versioned event ID
  per provider.
- **Timing** (timestamp_ft) — Windows FILETIME (100ns intervals
  since 1601-01-01) preserving full ETL resolution + range.
- **Process context** (process_id + thread_id + processor_id +
  kernel_time_us + user_time_us) — originating PID/TID/CPU and
  kernel/user mode CPU time.
- **Payload** (JSONB) — decoded event payload fields when a manifest
  matched the provider; raw-bytes preview otherwise.
- **anomaly_flags JSONB** — heuristic detection summary for the ι.C.D
  classifier. Canonical shape:
  ``{"kernel_proc_after_evtx_clear": bool,
  "provider_disable_evidence": bool, "unusual_provider": bool,
  "non_microsoft_in_diagtrack": bool, "schema_version": 1}``.
- **raw_record_size** — bytes consumed by the event record (for
  accounting; full bytes NOT persisted to keep DB size bounded).

Real-world Persona-E ETW relevance (Phase ι Scout 2 refresh):

- **FortiGuard 2024 IR case** — adversary cleared ``Security.evtx``;
  kernel ETL (``AutoLogger-Diagtrack-Listener.etl``) retained on disk
  exposed the entire post-clear process tree.
- **Microsoft DART team disclosures** — multiple APT campaigns where
  ETL was the only surviving execution trail because the adversary
  cleared EVTX but did not clear ETL.
- **ProcMon-author Russinovich blog** — kernel ETL as forensic gold-
  standard when EVTX has been tampered.

Per CLAUDE.md Rule #16: the ι.C.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system
images) surfaces every .etl candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses ETL records via dissect.etl as untrusted
input; nothing in wairz starts a kernel trace session, registers an
ETW logger, or invokes any process referenced in the event records.
The process_id / thread_id / event payload fields are surfaced for
operator review only.

Per CLAUDE.md Rule #35c JSONB discipline: each JSONB column gets a
dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers`` (2 helpers for this table:
payload / anomaly_flags).

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee04``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from ι.B.D head ``aabbccddee03``.

Indexes:

- ``ix_windows_etl_events_firmware_provider`` — ``(firmware_id,
  provider_guid)`` covers "all events for firmware Y from provider X"
  AND backs the ι.C.E ``lookup_etl_provider_across_firmwares`` cross-
  firmware aggregation query (the wairz competitive differentiator).
- ``ix_windows_etl_events_firmware_event_id`` — ``(firmware_id,
  event_id)`` covers per-event-ID forensic pivots.
- ``ix_windows_etl_events_firmware_timestamp`` — ``(firmware_id,
  timestamp_ft)`` backs forensic-timeline reconstruction.
- ``ix_windows_etl_events_firmware_session`` — ``(firmware_id,
  etl_session_name)`` covers per-session triage queries (e.g.
  "all events from Diagtrack-Listener for firmware Y").
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee04"
down_revision: str | None = "aabbccddee03"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_etl_events",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "firmware_id",
            UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Path + session identity.
        sa.Column("etl_file_path", sa.String(1024), nullable=False),
        sa.Column("etl_session_name", sa.String(255), nullable=True),
        # Provider identity.
        sa.Column("provider_guid", sa.String(36), nullable=True),
        sa.Column("provider_name", sa.String(255), nullable=True),
        # Event identity.
        sa.Column("event_id", sa.Integer, nullable=True),
        sa.Column("event_version", sa.SmallInteger, nullable=True),
        sa.Column("event_channel", sa.String(64), nullable=True),
        sa.Column("event_level", sa.SmallInteger, nullable=True),
        sa.Column("event_opcode", sa.SmallInteger, nullable=True),
        sa.Column("event_keywords", sa.BigInteger, nullable=True),
        sa.Column("event_task", sa.Integer, nullable=True),
        # Timing.
        sa.Column("timestamp_ft", sa.BigInteger, nullable=False),
        # Process context.
        sa.Column("process_id", sa.Integer, nullable=True),
        sa.Column("thread_id", sa.Integer, nullable=True),
        sa.Column("processor_id", sa.SmallInteger, nullable=True),
        sa.Column("kernel_time_us", sa.Integer, nullable=True),
        sa.Column("user_time_us", sa.Integer, nullable=True),
        # Payload + anomaly_flags.
        sa.Column("payload", JSONB, nullable=True),
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # Accounting.
        sa.Column("raw_record_size", sa.Integer, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_etl_events_firmware_provider",
        "windows_etl_events",
        ["firmware_id", "provider_guid"],
    )
    op.create_index(
        "ix_windows_etl_events_firmware_event_id",
        "windows_etl_events",
        ["firmware_id", "event_id"],
    )
    op.create_index(
        "ix_windows_etl_events_firmware_timestamp",
        "windows_etl_events",
        ["firmware_id", "timestamp_ft"],
    )
    op.create_index(
        "ix_windows_etl_events_firmware_session",
        "windows_etl_events",
        ["firmware_id", "etl_session_name"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_etl_events_firmware_session",
        table_name="windows_etl_events",
    )
    op.drop_index(
        "ix_windows_etl_events_firmware_timestamp",
        table_name="windows_etl_events",
    )
    op.drop_index(
        "ix_windows_etl_events_firmware_event_id",
        table_name="windows_etl_events",
    )
    op.drop_index(
        "ix_windows_etl_events_firmware_provider",
        table_name="windows_etl_events",
    )
    op.drop_table("windows_etl_events")
