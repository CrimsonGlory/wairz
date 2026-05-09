"""Per-execution Windows Prefetch record table (Phase ζ.2.A).

One row per ``.pf`` file extracted from a firmware's detection roots.
Captures application-execution history — last run times, run counts,
files referenced. Fed by the Phase ζ.2.B Prefetch walker (Rule #39
inner/outer/safe runner triplet).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. The ``prefetch_file_path`` column
stores the path RELATIVE to the detection root that contained the file
(so multi-root firmware re-extraction yields stable identifiers).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — Prefetch files are parsed by the ``windowsprefetch`` Python
library (read-only file open + struct unpack), never invokes
pftriage / Get-CimInstance Win32_PrefetchedApp / scriptable replay.

Per CLAUDE.md Rule #35c JSONB discipline: three JSONB columns
(``all_run_times``, ``filenames_referenced``, ``volumes``) carry
schema-versioned payloads. See
``app.services.jsonb_normalizers._normalize_windows_prefetch_records_*``
for the canonical shapes.

Indexes:

- ``ix_windows_prefetch_records_firmware_executable`` —
  ``(firmware_id, executable_name)`` covers the common "find every
  CHROME.EXE / CMD.EXE / RUNDLL32.EXE entry" filter.
- ``ix_windows_prefetch_records_firmware_last_run`` —
  ``(firmware_id, last_run_time DESC)`` covers forensic-timeline
  queries (most-recently-executed-first, time-window slicing).
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
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


class WindowsPrefetchRecord(Base):
    """Per-execution row from a walked ``.pf`` (Prefetch) file."""

    __tablename__ = "windows_prefetch_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this prefetch was parsed from.
    # Cascade DELETE so removing a firmware row removes its records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the source .pf within the detection root that contained
    # it. Stored relative so multi-root re-extraction produces stable IDs.
    # Common values: "Windows/Prefetch/CHROME.EXE-AB1234CD.pf",
    # "Windows/Prefetch/CMD.EXE-12345678.pf".
    prefetch_file_path: Mapped[str] = mapped_column(String(1024), nullable=False)

    # Executable name from the Prefetch header (60-byte UTF-16 field;
    # padded; truncated at first \\0). Common: "CHROME.EXE",
    # "POWERSHELL.EXE", "RUNDLL32.EXE", "SVCHOST.EXE".
    executable_name: Mapped[str] = mapped_column(String(256), nullable=False)

    # Prefetch hash (header bytes 76-79). Hex string. Combined with
    # executable_name forms the canonical .pf filename:
    # "<NAME>-<HASH>.pf". Different exec paths of the same binary
    # (e.g. system32 vs syswow64) produce different hashes.
    prefetch_hash: Mapped[str | None] = mapped_column(String(16), nullable=True)

    # Prefetch format version: 17=WinXP, 23=Win7/Vista, 26=Win8.1,
    # 30=Win10+ (MAM-compressed). Recorded for forensic context;
    # parser dispatches per-version internally.
    version: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Number of times the executable has been run (32-bit unsigned in
    # Prefetch; stored as Integer for portability). Saturates at MAX_INT.
    run_count: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Most-recent run time. Authoritative timestamp for timeline
    # queries — indexed jointly with firmware_id.
    last_run_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # All recorded run times (up to 8 on Win10+, 1 on earlier versions).
    # JSONB list of ISO-8601 strings, newest-first.
    # Schema-versioned per Rule #35c via
    # ``_stamp_windows_prefetch_records_all_run_times``.
    all_run_times: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Files referenced during the most-recent execution (from the
    # Filename Strings block). JSONB list[str], typically 100-300
    # entries for complex apps. Schema-versioned per Rule #35c.
    filenames_referenced: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Volumes referenced during exec (volume serial + path).
    # JSONB list[dict], typically 1-2 entries.
    # Schema-versioned per Rule #35c.
    volumes: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # Common filter: "find every CHROME.EXE / RUNDLL32.EXE entry
        # for this firmware". Covers the operator-MCP filter shape.
        Index(
            "ix_windows_prefetch_records_firmware_executable",
            "firmware_id",
            "executable_name",
        ),
        # Time-bounded queries — forensic-timeline reconstruction reads
        # in last_run_time DESC.
        Index(
            "ix_windows_prefetch_records_firmware_last_run",
            "firmware_id",
            "last_run_time",
        ),
    )
