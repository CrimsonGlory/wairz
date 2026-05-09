"""Per-event Windows EVTX record table (Phase ε.2.A).

One row per event record extracted from a parsed ``.evtx`` file across
a firmware's detection roots. ε.1.b.3's ``run_evtx_walk_background``
aggregates summaries into ``firmware.evtx_walk_result`` JSONB; ε.2.A
adds the per-event landing zone so future search-events MCP tools
(ε.2.C, deferred to a follow-up session) can paginate filtered
results without re-walking the firmware.

Per CLAUDE.md Rule #16: writers populate from the SAME walker that
fills ``evtx_walk_result`` and resolve detection roots via
``get_detection_roots(firmware)`` — NEVER ``firmware.extracted_path``
alone. The ``evtx_file_path`` column stores the path RELATIVE to the
detection root that contained the file (so multi-root firmware
re-extraction yields stable identifiers).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — events are parsed by python-evtx (read-only mmap binding,
never invokes wevtutil / Get-WinEvent / scriptable replay).

Per CLAUDE.md Rule #35c JSONB discipline: the ``message_xml`` JSONB
column carries the parsed event-detail tree under the canonical
schema documented in
``app.services.jsonb_normalizers._normalize_windows_event_records_message_xml``.
Schema version is stamped by the writer via the matching ``_stamp_*``
helper.

Indexes:

- ``ix_windows_event_records_firmware_provider_eid`` —
  ``(firmware_id, provider, event_id)`` covers the common
  "find every Sysmon-1 / Security-4624 / Security-4625 event for
  this firmware" filter.
- ``ix_windows_event_records_firmware_recorded_at`` —
  ``(firmware_id, recorded_at DESC)`` covers time-bounded queries
  ("last 24h of events", forensic-timeline reconstruction).

Per Phase ε.2 campaign decision: this is the per-event landing zone;
the per-firmware aggregate (counts by EID, providers, time range,
sample records) continues to live in ``firmware.evtx_walk_result``
JSONB. The two are populated together by the walker (ε.2.B —
deferred to a follow-up session).
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
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsEventRecord(Base):
    """Per-event row from a walked ``.evtx`` file."""

    __tablename__ = "windows_event_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this event was parsed from.
    # Cascade DELETE so removing a firmware row removes its events.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the source .evtx within the detection root that contained
    # it. Stored relative so multi-root re-extraction produces stable IDs.
    # Common values: "Windows/System32/winevt/Logs/Security.evtx",
    # "Windows/System32/winevt/Logs/Microsoft-Windows-Sysmon%4Operational.evtx".
    evtx_file_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # EVTX provider (System.Provider.@Name). Common values:
    # "Microsoft-Windows-Security-Auditing", "Microsoft-Windows-Sysmon",
    # "Service Control Manager", "Microsoft-Windows-Windows Defender".
    provider: Mapped[str] = mapped_column(String(256), nullable=False)

    # EVTX EventID (System.EventID). Common values:
    # 4624/4625 (Security: logon success/failure), 1 (Sysmon: process
    # create), 4634 (Security: account logoff), 7045 (System: service
    # install). 32-bit signed range.
    event_id: Mapped[int] = mapped_column(Integer, nullable=False)

    # EVTX Level (System.Level). 0=undefined, 1=critical, 2=error,
    # 3=warning, 4=info, 5=verbose. Nullable for events that omit it.
    level: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # EVTX Channel (System.Channel). E.g. "Security", "System",
    # "Application", "Microsoft-Windows-Sysmon/Operational".
    channel: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # EVTX Computer (System.Computer). Hostname at event time.
    computer: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # EVTX Task (System.Task). 16-bit unsigned, but stored as Integer
    # for portability. Nullable.
    task: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # EVTX TimeCreated (System.TimeCreated.@SystemTime). Authoritative
    # event timestamp. Indexed for time-bounded queries.
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # EVTX EventData / UserData parsed into a JSONB tree. The shape
    # depends on provider+EID; see normaliser docstring for the
    # canonical envelope. Schema version stamped by writer.
    message_xml: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Original event XML for full-text fallback search. Operators rarely
    # query this directly, but it's the source of truth if message_xml
    # parsing surprised us. Nullable to allow walkers that skip raw-XML
    # capture for storage budget reasons.
    raw_xml: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Record number within the source .evtx (System.EventRecordID).
    # 64-bit. Useful for pagination + dedup across re-walks.
    record_number: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # Common filter: "find every Sysmon-1 / 4624 / 4625 event for
        # this firmware". Covers the operator-MCP search-by-EID use case.
        Index(
            "ix_windows_event_records_firmware_provider_eid",
            "firmware_id",
            "provider",
            "event_id",
        ),
        # Time-bounded queries — forensic-timeline reconstruction reads
        # in recorded_at DESC for "last N events" or time-window slicing.
        Index(
            "ix_windows_event_records_firmware_recorded_at",
            "firmware_id",
            "recorded_at",
        ),
    )
