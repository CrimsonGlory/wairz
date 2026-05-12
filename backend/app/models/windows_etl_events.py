"""Per-event Windows ETL trace-event row (Phase ι.C.A — THIRD LINUX/WINDOWS, FIRST ι Windows-side walker).

One row per parsed Event Tracing for Windows (ETW) event record decoded
from a ``.etl`` binary trace-log file found under Windows-firmware
detection roots (typically ``Windows/System32/WDI/LogFiles/*.etl``,
``Windows/System32/winevt/Logs/*.etl``, ``Windows/Logs/CBS/*.etl``,
``Windows/Logs/NetSetup/*.etl``, ``Windows/Logs/WindowsBackup/*.etl``,
``Windows/Logs/WindowsUpdate/*.etl``,
``Windows/System32/LogFiles/WMI/*.etl``).

Captures forensic-triage metadata for the T1070.001 (Clear Windows
Event Logs) + T1562.002 (Disable Windows Event Logging) + T1574
(Hijack Execution Flow — providers) post-compromise tradecraft surface.
Adversaries who clear EVTX often forget to clear ETL — FortiGuard 2024
documented ``AutoLogger-Diagtrack-Listener.etl`` retaining kernel
process-trace evidence AFTER the Security EVTX log was cleared.

Real-world Persona-E ETW relevance (Phase ι Scout 2 refresh):

- FortiGuard 2024 IR case — adversary cleared Security.evtx; kernel
  ETL retained on-disk and exposed the entire process tree.
- Microsoft DART team disclosures — multiple APT campaigns where ETL
  was the only surviving execution trail.
- ProcMon-author-Russinovich blog — kernel ETL as forensic gold-standard
  when EVTX has been tampered.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. The .etl files appear in multiple
Windows partition layouts.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses ETL binary records via the Fox-IT
``dissect.etl`` library AS DATA (no provider manifest is loaded, no
ETW logger is started, no kernel trace session is created). Provider
GUIDs, event IDs, payloads, and process/thread IDs are all surfaced
as untrusted strings/ints.

Per CLAUDE.md Rule #35c JSONB discipline: every JSONB column (``payload``,
``anomaly_flags``) carries its own normalizer + schema_version stamp;
see ``app.services.jsonb_normalizers``.

ι.C.D finding emit leverages the parsed event metadata to flag
adversary-residue indicators (kernel process events retained after a
EVTX clear, provider disable evidence, third-party providers inside
Microsoft-only sessions, unusual provider GUIDs).

Reference for the ETL file format:
- https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
- https://github.com/fox-it/dissect.etl (AGPL-3.0, v3.14)
- ETW EVENT_TRACE_HEADER + EVENT_TRACE_LOGFILE struct documentation.
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
    SmallInteger,
    String,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsEtlEvent(Base):
    """Per-event row decoded from a Windows ETL trace-log file."""

    __tablename__ = "windows_etl_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this ETL event was parsed
    # from. Cascade DELETE so removing a firmware row removes its
    # ETL events.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute path inside the firmware extract (or relative to detection
    # root). E.g. ``Windows/System32/WDI/LogFiles/BootCKCL.etl`` or
    # ``Windows/System32/winevt/Logs/Microsoft-Windows-Diagnosis-PCW%4Operational.etl``.
    etl_file_path: Mapped[str] = mapped_column(
        String(1024), nullable=False
    )

    # ETW logger session name (LogFileName field from the file's
    # LOGFILE_HEADER). E.g. ``AutoLogger-Diagtrack-Listener``,
    # ``Eventlog-Security``, ``NT Kernel Logger``. NULL when the session
    # name cannot be extracted (rare — old systems).
    etl_session_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # ETW provider GUID — canonical 8-4-4-4-12 lowercase form with
    # hyphens (e.g. ``c651f5f6-1c0d-492e-8ae1-b4efd7c9d503``). NULL on
    # system-level header events that lack a provider.
    provider_guid: Mapped[str | None] = mapped_column(
        String(36), nullable=True
    )

    # Resolved provider name from the manifest (if dissect.etl was able
    # to match the GUID to a known provider). E.g.
    # ``Microsoft-Windows-Kernel-Process`` / ``Microsoft-Windows-Diagtrack``.
    # NULL when no manifest match — most non-Microsoft providers fall here.
    provider_name: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )

    # ETW event ID — provider-scoped integer identifier for the event.
    # NULL on system events (logger control records).
    event_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # ETW event version — provider-scoped event-schema versioning.
    event_version: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True
    )

    # ETW event channel — Operational / Analytic / Debug / Admin
    # (resolved from the manifest, optional).
    event_channel: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # ETW event level — 0=info, 1=critical, 2=error, 3=warning,
    # 4=informational, 5=verbose. NULL on system records.
    event_level: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True
    )

    # ETW event opcode — start/stop/info/data-collection markers.
    event_opcode: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True
    )

    # ETW event keywords bitmask — provider-defined bit categorisation.
    event_keywords: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # ETW event task — provider-defined activity identifier.
    event_task: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Windows FILETIME (100ns intervals since 1601-01-01 UTC) — the
    # event's wall-clock timestamp. Stored as raw FILETIME so the
    # full resolution + range is preserved (DateTime would clip).
    timestamp_ft: Mapped[int] = mapped_column(
        BigInteger, nullable=False
    )

    # Originating process ID. NULL on system events.
    process_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Originating thread ID. NULL on system events.
    thread_id: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # CPU processor the event was raised on.
    processor_id: Mapped[int | None] = mapped_column(
        SmallInteger, nullable=True
    )

    # Kernel-mode CPU time consumed by the event's originating thread
    # in microseconds.
    kernel_time_us: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # User-mode CPU time consumed by the event's originating thread
    # in microseconds.
    user_time_us: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Decoded event payload — manifest-resolved field key/value pairs
    # when available, or a small raw-bytes preview when no manifest is
    # available. Rule #35c stamped envelope.
    payload: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Anomaly flags — heuristic detection summary for the ι.C.D
    # classifier. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "kernel_proc_after_evtx_clear": bool,
    #     "provider_disable_evidence": bool,
    #     "unusual_provider": bool,
    #     "non_microsoft_in_diagtrack": bool,
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Raw bytes of the event record (size). For operator forensic review;
    # the full bytes are NOT persisted (size cap concerns) — only the
    # size in bytes for accounting.
    raw_record_size: Mapped[int] = mapped_column(
        Integer, nullable=False
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    __table_args__ = (
        # "All events for firmware Y by provider" — canonical provider-
        # GUID query AND the ι.C.E lookup_etl_provider_across_firmwares
        # cross-firmware aggregation back-index.
        Index(
            "ix_windows_etl_events_firmware_provider",
            "firmware_id",
            "provider_guid",
        ),
        # "All events for firmware Y of a specific event_id" — common
        # forensic-pivot shape.
        Index(
            "ix_windows_etl_events_firmware_event_id",
            "firmware_id",
            "event_id",
        ),
        # "All events for firmware Y by time-range" — backs the
        # forensic-timeline reconstruction surface.
        Index(
            "ix_windows_etl_events_firmware_timestamp",
            "firmware_id",
            "timestamp_ft",
        ),
        # "All events for firmware Y by session-name" — covers
        # per-session triage queries.
        Index(
            "ix_windows_etl_events_firmware_session",
            "firmware_id",
            "etl_session_name",
        ),
    )
