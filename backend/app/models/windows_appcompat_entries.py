"""Per-entry Windows AppCompat/Shimcache row (Phase κ.B.A — SEVENTH κ-era walker).

One row per AppCompatCache entry extracted from a Windows SYSTEM
registry hive (``ControlSet00X\\Control\\Session Manager\\AppCompatCache
\\AppCompatCache`` REG_BINARY value). The Phase κ.B.C walker locates
SYSTEM hives under Windows-firmware detection roots, parses the
ControlSet's AppCompatCache REG_BINARY value via a pure-Python
``struct``-based parser, and surfaces metadata about WHICH EXECUTABLES
THE OS HAS SEEN — file path + last-modified FILETIME + insertion
position. Each entry is a row.

**Real-world Persona-E AppCompat/Shimcache relevance** (T1106 / LotL):

- **AppCompatCache is execution evidence** — the Application Compatibility
  Engine records EVERY executable the system has seen, regardless of
  whether it actually ran. Forensic gold for "what did the adversary
  bring with them" hunts. Mandiant's ShimCacheParser predates 2014;
  Eric Zimmerman's AppCompatCacheParser is the modern reference.

- **Persona-E execution-evidence patterns:**
  - **Suspicious path execution** (T1106 Native API / T1059 Command and
    Scripting Interpreter) — an executable under ``\\Users\\Public\\``,
    ``\\Windows\\Temp\\``, ``\\AppData\\Local\\Temp\\``, ``\\ProgramData
    \\Microsoft\\Windows\\Caches\\``, or ``C:\\Temp\\`` is canonical
    adversary staging. Healthy estates rarely have user-writable paths
    in AppCompat; an exec there means SOMEONE ran the binary or it
    triggered AppCompat by being loaded as a DLL.
  - **Temp execution with mismatched extension** (T1036 Masquerading) —
    files ending in ``.tmp`` / ``.dat`` but actually executed indicate
    extension hiding. AppCompat captures the path regardless of double-
    extension renaming.
  - **Unusual extension** (T1036.005 Match Legitimate Name or Location
    + T1027 Obfuscated Files) — extensions outside the standard
    {exe, dll, bat, cmd, ps1, vbs, js, scr, com, msi, cpl} set are
    suspicious. AppCompat normally catches .exe/.dll/.sys; .png or
    .jpg in AppCompat means something weird ran.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Multi-rootfs Windows firmware (VHDX
/ NTFS / FAT32 / system images) surfaces every SYSTEM hive candidate
(typically one per Windows installation; mirror windows for backup).

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column carries its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #36 (no-execute discipline): the κ.B.C walker parses
the AppCompatCache REG_BINARY value AS DATA via pure-Python ``struct``
unpacking. NO sub-process invocations, NO Windows API calls, NO
``rundll32`` or ``cscript`` or ``wmic`` — the walker reads bytes,
unpacks structs, and emits rows. The walker's source is tokenized
against forbidden invocation tokens in ``test_appcompat_walker_no_execute``.

κ.B.D finding emit leverages the parsed metadata to flag adversary-
residue indicators (suspicious-path executables, temp-extension
mismatches, recent baseline anomalies). Wairz NEVER executes the
parsed binaries — those are surfaced to operator review as DATA only.

Reference for the AppCompatCache binary format:

- Eric Zimmerman, ``AppCompatCacheParser`` (C# reference) — the
  canonical open-source AppCompatCache parser, public under MIT.
- Mandiant, ``ShimCacheParser`` (Python) — original 2013 reverse-
  engineering reference, plus 2015 follow-up for Win8 / Win10 format
  evolution.
- Microsoft, ``Application Compatibility Database`` documentation
  (only documents semantics; the binary layout is community-derived).
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
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsAppCompatEntry(Base):
    """Per-entry row decoded from the SYSTEM hive's AppCompatCache REG_BINARY.

    PARSE-ONLY discipline (Rule #36): rows surface execution-evidence
    METADATA — path, FILETIME, insertion position, anomaly flags. The
    walker NEVER invokes the referenced binary; operators triage paths
    as DATA.
    """

    __tablename__ = "windows_appcompat_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this AppCompat entry was located in.
    # Cascade DELETE so removing a firmware row removes its AppCompat rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Absolute file_path inside the Windows volume as recorded by AppCompat.
    # Format: ``\\??\\C:\\Users\\Public\\evil.exe`` or
    # ``C:\\Windows\\System32\\cmd.exe``. Case is preserved as recorded by
    # the OS at the time AppCompat saw the file. NULL when the entry has
    # no parseable path (corrupted blob, truncated entry, etc.).
    file_path: Mapped[str | None] = mapped_column(
        String(1024), nullable=True
    )

    # Position within the cache when the entry was extracted (0 = MRU,
    # higher = older). AppCompat is an LRU cache; the most-recently-seen
    # entry is at position 0. Position can correlate with timeline
    # ordering even when individual FILETIME values are nonsense (some
    # builds zero them).
    insertion_position: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="0"
    )

    # Last-modified FILETIME of the binary at the time AppCompat saw it,
    # converted from Windows FILETIME (100-ns intervals since
    # 1601-01-01) to a Python UTC datetime. NULL when the entry's
    # FILETIME is zero, malformed, or pre-epoch (some Win10 builds
    # zero this field).
    last_modified_ts: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Anomaly flags — heuristic detection summary for the κ.B.D classifier.
    # Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "suspicious_path": bool,        # file_path under known adversary-staging directories
    #     "temp_execution": bool,         # .tmp/.dat extension on executable-shape path
    #     "unusual_extension": bool,      # extension not in the standard set
    #     "parse_error": bool,            # entry failed structured parse
    #   }
    # Rule #35c stamped envelope.
    anomaly_flags: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    # Source hive path (the relative path of the SYSTEM hive that
    # contained this AppCompat entry). Format
    # ``<container>!Windows/System32/config/SYSTEM`` for the active
    # control set; useful for cross-correlating findings back to a
    # specific hive in multi-partition firmware. Truncated to 512 chars.
    source_hive_path: Mapped[str | None] = mapped_column(
        String(512), nullable=True
    )

    # ControlSet ordinal (e.g. ControlSet001 / ControlSet002). Reflects
    # which ControlSet's AppCompatCache value this entry came from.
    # Stored as integer to allow easy filtering ("show me entries from
    # CurrentControlSet only"). NULL when the parser couldn't determine
    # the control set ordinal.
    control_set: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    # Schema version of the binary format this entry was parsed under
    # (Win10/11 = 1; reserved for future format support). NOT the JSONB
    # schema_version — that lives in anomaly_flags. This is a parser-
    # discriminator field per κ.B.A spec.
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="1"
    )

    # If the entry's structured parse failed (truncated path bytes,
    # malformed length prefix, etc.), record the error so operators can
    # triage without losing the row. The walker still emits the row
    # (with parse_error anomaly bit set) rather than silently skipping.
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional raw entry size in bytes, for forensic accounting. Useful
    # for spotting oversized / undersized entries that may signal
    # parser disagreement vs the actual format.
    entry_size_bytes: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
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
        # "All AppCompat entries for firmware Y by insertion position" —
        # quick filter for MRU vs LRU + timeline reconstruction.
        Index(
            "ix_windows_appcompat_entries_firmware_insertion",
            "firmware_id",
            "insertion_position",
        ),
        # "All AppCompat entries for firmware Y by last_modified_ts" —
        # timeline-correlation queries for incident response.
        Index(
            "ix_windows_appcompat_entries_firmware_last_modified",
            "firmware_id",
            "last_modified_ts",
        ),
        # "All AppCompat entries for firmware Y by file_path" — fast
        # path-substring filtering for cross-firmware joins on the same
        # binary path.
        Index(
            "ix_windows_appcompat_entries_firmware_file_path",
            "firmware_id",
            "file_path",
        ),
    )
