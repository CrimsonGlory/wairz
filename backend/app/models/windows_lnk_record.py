"""Per-LNK Windows Shell Link row (Phase η.C.A).

One row per parsed ``.lnk`` (Microsoft Shell Link / MS-SHLLINK) file
extracted from a Windows install's user profile / system shortcut
locations. Captures persistence-candidate metadata: target path,
working directory, command-line arguments, hotkey, show-window,
icon ref, and MAC times (creation/accessed/modified per the LNK
header — these are the LNK's own MAC times, NOT the on-disk
``.lnk`` file's filesystem mtime).

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. The ``source_path`` column stores
the path RELATIVE to the detection root (so multi-root firmware
re-extraction yields stable identifiers).

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the parsed ``target_path`` / ``arguments`` are surfaced for
operator review, NEVER invoked. The walker treats the LNK binary as
untrusted input via ``LnkParse3.lnk_file(fhandle=...)`` (a pure-
Python parser; no shell-out, no resolved-target invocation).

Per CLAUDE.md Rule #35c JSONB discipline: ``target_metadata`` JSONB
column carries its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``
``_normalize_windows_lnk_records_target_metadata`` /
``_stamp_windows_lnk_records_target_metadata``. The flat columns
above (target_path / working_directory / arguments / etc.) are
materialized for fast indexed lookup; the FULL parsed JSON
(LnkParse3 ``.get_json()`` shape — header + link_info + data +
extra) is stamped into ``target_metadata`` for full-fidelity
forensic triage when the operator needs it.

Persistence-finding emit (η.C.D — ``windows_lnk_abnormal_target``,
T1547.009 Shortcut Modification) leverages the parsed data to flag:

- ``cmd.exe /c <encoded-PS>`` action shape — target path resolves
  to ``cmd.exe`` AND arguments contain encoded-PowerShell pattern
  (-EncodedCommand / FromBase64String / IEX). HIGH confidence.
- Non-Microsoft target binary — target path NOT under
  ``\\Windows\\``, ``\\Program Files\\``, or
  ``\\Program Files (x86)\\``. MEDIUM confidence.
- Baseline rows — LOW confidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Index,
    String,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class WindowsLnkRecord(Base):
    """Per-LNK row from a walked ``\\Users\\<profile>\\...\\*.lnk`` shortcut."""

    __tablename__ = "windows_lnk_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this LNK was parsed from.
    # Cascade DELETE so removing a firmware row removes its LNK records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the .lnk file within the detection root (Rule #16).
    # Stored relative for stable cross-extraction identifiers.
    # E.g. ``Users/dustin/AppData/Roaming/Microsoft/Windows/Recent/foo.lnk``.
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # The .lnk file basename. Fast operator search and finding-emit
    # filename column. E.g. ``foo.lnk``.
    lnk_filename: Mapped[str] = mapped_column(String(512), nullable=False)

    # Resolved target path. Preference order at parse time:
    #   1. link_info.local_base_path  (most common; e.g. C:\Windows\System32\cmd.exe)
    #   2. data.relative_path         (e.g. ..\..\..\Windows\System32\cmd.exe)
    #   3. None                       (target unresolvable; rare)
    # NULL when the LNK lacks both. Indexed jointly with firmware_id
    # for "find all LNKs pointing at cmd.exe" forensic queries.
    target_path: Mapped[str | None] = mapped_column(String(2048), nullable=True)

    # Working directory from data.working_directory. NULL when absent.
    working_directory: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # Command-line arguments from data.command_line_arguments. Stored
    # as Text — encoded-PowerShell args can exceed 8 KB after Base64
    # expansion, blowing past String(N) limits.
    arguments: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Description / NAME_STRING from data.description. Common values:
    # localised app name (e.g. "Mozilla Firefox"), localised resource
    # ref (e.g. "@%SystemRoot%\system32\..."). NULL when absent.
    description: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    # Icon reference from data.icon_location. Typically the same as
    # target_path (LNK reuses target binary's icon). NULL when absent.
    icon_location: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    # Show command from header.windowstyle. Values: SW_SHOWNORMAL (1),
    # SW_SHOWMAXIMIZED (3), SW_SHOWMINIMIZED (7), SW_SHOWMINNOACTIVE,
    # SW_SHOW. NULL when absent. Stored as the parser's enum string
    # (e.g. "SW_SHOWNORMAL") for operator readability.
    show_command: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    # Hotkey assignment from header.hotkey. Free-form string per
    # parser output (e.g. "CTRL+SHIFT+F1 - F1 {0x0931}"). NULL when
    # unset. Hotkey-bound LNKs are unusual on systems that don't
    # actively use them — operator triage signal.
    hotkey: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # MAC times from the LNK header (NOT the on-disk .lnk file's
    # filesystem mtime). LnkParse3 surfaces these as
    # creation_time / accessed_time / modified_time (datetime objects
    # — already tz-aware UTC at parse time).
    creation_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    accessed_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    modified_time: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Full parsed LnkParse3 ``.get_json()`` output, schema-stamped.
    # Top-level keys: header / link_info / data / extra (+ size).
    # See ``_normalize_windows_lnk_records_target_metadata`` for
    # canonical envelope. NULL only when parse partially failed but
    # we still wanted the row landed (rare — typically the row is
    # skipped entirely on parse failure).
    target_metadata: Mapped[dict | None] = mapped_column(
        JSONB, nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    __table_args__ = (
        # "All LNKs for firmware Y, newest LNK-modified first" — the
        # canonical operator query shape for LNK forensic timeline.
        Index(
            "ix_windows_lnk_records_firmware_modified",
            "firmware_id",
            "modified_time",
        ),
        # "Find all LNKs pointing at cmd.exe / powershell.exe" —
        # T1547.009 finding-emit query shape.
        Index(
            "ix_windows_lnk_records_firmware_target",
            "firmware_id",
            "target_path",
        ),
        # "Lookup by .lnk filename" — operator UX for "show me
        # firefox.lnk" or "show me Recent/foo.lnk".
        Index(
            "ix_windows_lnk_records_firmware_filename",
            "firmware_id",
            "lnk_filename",
        ),
    )
