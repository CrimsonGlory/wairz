"""Per-record Windows NTFS $UsnJrnl:$J row (Phase κ.E.A — TENTH κ-era walker).

One row per USN journal record parsed from the ``$Extend\\$UsnJrnl:$J``
alternate data stream of an NTFS volume extracted from a firmware capture.
The Phase κ.E.C walker locates raw NTFS images via the η.A MFT walker
precedent (boot-sector magic check), opens each with ``dissect.ntfs.NTFS``,
reads the ``$Extend/$UsnJrnl`` MFT record's ``$J`` ADS, and iterates USN
records via ``dissect.ntfs.usnjrnl.UsnJrnl.records()``.

**Real-world Persona-E USN Journal relevance** (T1070.004 / anti-forensics):

- **USN Journal is FILE-SYSTEM CHANGE evidence** — Windows NTFS records
  every create / delete / rename / data-modify / EA-change / security-
  change / object-id-change against tracked files. Adversaries who
  delete payloads (``T1070.004 File Deletion``) cannot delete the
  $J record of the create+delete pair — the journal is forensic gold
  for "what files did the adversary touch."

- **Persona-E adversary-residue patterns:**
  - **File deletion residue** (T1070.004) — reason_flags has
    ``FILE_DELETE`` AND filename ends in an executable extension
    (``.exe``, ``.dll``, ``.ps1``, ``.bat``, ``.vbs``, ``.scr``).
    Deletion of attacker artifacts after staging.
  - **Temp-create-delete pair** (T1059 + T1070.004 chained) — the
    SAME file (matched by parent_file_reference_number + file_name)
    has both a ``FILE_CREATE`` AND a ``FILE_DELETE`` record within a
    short window AND the parent path lives under a temp / staging
    directory. Adversary drops → executes → deletes.
  - **Renamed executable** (T1036 Masquerading) — ``RENAME_OLD_NAME``
    + ``RENAME_NEW_NAME`` pair with an extension change
    (``.tmp`` → ``.exe``, ``.dat`` → ``.dll``, ``.png`` → ``.bat``).
    Adversary stages a non-executable extension to evade scanners,
    then renames to executable at runtime.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Raw NTFS images live alongside the
rest of the extraction; the η.A walker enumerates ``.dd`` / ``.raw``
/ ``.ntfs`` / ``.img`` / ``.bin`` candidates under each detection root
and opens each via ``with open(path, "rb") as fh: NTFS(fh)``.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker treats raw NTFS images as untrusted input via
``dissect.ntfs`` (pure-Python parser; no shell-out, no ``ntfs-3g`` /
``mount`` / ``qemu-system`` invocation). The walker NEVER invokes any
file referenced by the journal entries; the file names are surfaced as
DATA for operator review.

Per CLAUDE.md Rule #35c JSONB discipline: the ``reason_flags`` JSONB
column carries its own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``.

κ.E.D finding emit (windows_usnjrnl_file_deletion +
windows_usnjrnl_temp_create_delete_pair +
windows_usnjrnl_renamed_executable) leverages the parsed metadata to
flag adversary-residue indicators. Wairz NEVER executes the parsed
binaries — those are surfaced to operator review as DATA only.

Reference for the USN Journal binary format:

- Microsoft, MS-FSCC §2.3 USN_REASON_* / USN_RECORD_V2 / V3 / V4 —
  the canonical wire format.
- dissect.ntfs, ``usnjrnl.UsnJrnl`` — pure-Python parser (Apache 2.0)
  that decodes the change-log records AS DATA.
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


class WindowsUsnJrnlEntry(Base):
    """Per-record row decoded from an NTFS volume's $UsnJrnl:$J ADS.

    PARSE-ONLY discipline (Rule #36): rows surface change-log METADATA
    — usn / mft references / file_name / reason_flags / timestamp. The
    walker NEVER invokes the referenced file; operators triage paths as
    DATA.
    """

    __tablename__ = "windows_usnjrnl_entries"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this USN entry was located in.
    # Cascade DELETE so removing a firmware row removes its USN rows.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the raw NTFS image within the detection root (Rule #16),
    # stored relative for stable cross-extraction identifiers. E.g.
    # ``images/disk0.raw`` or ``vhdx/root.dd``. Truncated to 1024 chars.
    source_file_path: Mapped[str] = mapped_column(
        String(1024), nullable=False
    )

    # USN identifier — 64-bit monotonically-increasing change-log
    # offset assigned by Windows when the record was written. Globally
    # unique per volume; useful as a "MRU/LRU ordering key" and for
    # cross-correlating records emitted close together in time.
    usn: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # MFT segment number of the file the change applies to (low 48
    # bits of the MFT_SEGMENT_REFERENCE). 64-bit BigInt holds the
    # natural range. Joined against ``windows_mft_records.segment_number``
    # for operators correlating $J entries with MFT triage rows from η.A.
    file_reference_number: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # MFT segment number of the parent directory. Same shape as
    # file_reference_number — useful for "all $J events under this
    # directory" queries.
    parent_file_reference_number: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # File name from the USN record (UTF-16LE in the wire format,
    # decoded to UTF-8 here). Truncated to 512 chars (most filenames
    # are <260 NTFS limit; oversize is record corruption or attacker
    # artefact). NULL when the record's name length is zero (rare —
    # most $J records carry a file_name).
    file_name: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Decoded reason flags. Canonical shape (boolean bits + schema_version):
    #   {
    #     "schema_version": 1,
    #     "data_overwrite": bool,        # 0x00000001
    #     "data_extend": bool,           # 0x00000002
    #     "data_truncation": bool,       # 0x00000004
    #     "named_data_overwrite": bool,  # 0x00000010
    #     "named_data_extend": bool,     # 0x00000020
    #     "named_data_truncation": bool, # 0x00000040
    #     "file_create": bool,           # 0x00000100
    #     "file_delete": bool,           # 0x00000200
    #     "ea_change": bool,             # 0x00000400
    #     "security_change": bool,       # 0x00000800
    #     "rename_old_name": bool,       # 0x00001000
    #     "rename_new_name": bool,       # 0x00002000
    #     "indexable_change": bool,      # 0x00004000
    #     "basic_info_change": bool,     # 0x00008000
    #     "hard_link_change": bool,      # 0x00010000
    #     "compression_change": bool,    # 0x00020000
    #     "encryption_change": bool,     # 0x00040000
    #     "object_id_change": bool,      # 0x00080000
    #     "reparse_point_change": bool,  # 0x00100000
    #     "stream_change": bool,         # 0x00200000
    #     "transacted_change": bool,     # 0x00400000
    #     "integrity_change": bool,      # 0x00800000
    #     "close": bool,                 # 0x80000000
    #     "_raw": int,                   # original DWORD for round-trip
    #   }
    # Rule #35c stamped envelope. Per Rule #35c: legacy rows produced
    # by the bitmask wire format (a single int) are normalized at the
    # boundary to the canonical dict shape; the normalizer accepts both.
    reason_flags: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # USN_SOURCE_* flag value (the wire DWORD). 0 = NORMAL (no special
    # source); non-zero values indicate the change came from a data-
    # management / replication / auxiliary-data system rather than a
    # user-initiated change. Stored as Integer (the wire DWORD fits).
    source_info: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # SecurityId from the record's USN_RECORD_V2/V3 SecurityId field
    # (32-bit DWORD).
    security_id: Mapped[int | None] = mapped_column(Integer, nullable=True)

    # Wire FILETIME converted to a UTC datetime. NULL when the record's
    # TimeStamp field is zero (some corrupted records) or pre-epoch.
    timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # If the record's structured parse failed (truncated record,
    # malformed length prefix, etc.), record the error so operators can
    # triage without losing the row. The walker still emits the row
    # (with the parsed-portion of fields populated) rather than silently
    # skipping.
    parse_error: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Schema version of the record format this entry was parsed under
    # (USN_RECORD_V2/V3 == 2 or 3 per the wire MajorVersion). NOT the
    # JSONB schema_version — that lives in reason_flags. This is a
    # parser-discriminator field per κ.E.A spec.
    schema_version: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="2"
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
        # "All USN entries for firmware Y by USN ordering" — quick
        # timeline reconstruction (USN is monotonic per volume).
        Index(
            "ix_windows_usnjrnl_entries_firmware_usn",
            "firmware_id",
            "usn",
        ),
        # "All USN entries for firmware Y by timestamp" — timeline
        # correlation for incident response.
        Index(
            "ix_windows_usnjrnl_entries_firmware_timestamp",
            "firmware_id",
            "timestamp",
        ),
        # "All USN entries for firmware Y by file_name" — fast filename
        # filtering for cross-firmware joins on the same artefact name.
        Index(
            "ix_windows_usnjrnl_entries_firmware_file_name",
            "firmware_id",
            "file_name",
        ),
        # "All USN entries for firmware Y under directory ref N" —
        # parent-mft-ref join for "show me everything that happened in
        # this directory" queries.
        Index(
            "ix_windows_usnjrnl_entries_firmware_parent_ref",
            "firmware_id",
            "parent_file_reference_number",
        ),
    )
