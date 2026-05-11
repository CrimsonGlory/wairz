"""Per-record Windows NTFS $MFT row (Phase η.A.A).

One row per parsed MFT segment from a raw NTFS image extracted from
a firmware capture. Captures forensic-triage metadata: per-segment
$STANDARD_INFORMATION and $FILE_NAME timestamps (the four-tuple of
creation / last_modification / last_change / last_access used for
timestomp detection — $SI older than $FN is the classic
anti-forensics tell), $DATA AttributeCollection summary (file size +
named Alternate Data Streams), allocated/deleted state via the
FILE_RECORD_SEGMENT_IN_USE flag, type flags (file / directory),
parent segment reference, full path string.

Per CLAUDE.md Rule #16: writers populate from a walker that resolves
detection roots via ``get_detection_roots(firmware)`` — NEVER
``firmware.extracted_path`` alone. Raw NTFS images live alongside
the rest of the extraction; the walker enumerates ``.dd`` / ``.raw``
/ ``.ntfs`` candidates under each detection root and opens each via
``with open(path, "rb") as fh: NTFS(fh)``.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker treats raw NTFS images as untrusted input via
dissect.ntfs (a pure-Python parser; no shell-out, no
``ntfs-3g`` / ``mount`` / ``qemu-system`` invocation). The parsed
ADS stream metadata is surfaced for operator review; ADS *content*
sampling reads up to a small evidence cap (no execution).

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns carry
their own normalizer + schema_version stamp; see
``app.services.jsonb_normalizers``
``_normalize_windows_mft_records_ads_streams`` /
``_stamp_windows_mft_records_ads_streams`` and
``_normalize_windows_mft_records_target_metadata`` /
``_stamp_windows_mft_records_target_metadata``. The flat columns
(timestamps / sizes / flags / paths) are materialized for fast
indexed lookup; the JSONB columns carry the per-record ADS roster +
the catchall metadata (parent_segment_ref, reparse_point flag, raw
attribute_flags) for full-fidelity forensic triage.

η.A.D finding emit (windows_mft_ads_hidden_content +
windows_mft_timestomping) leverages the parsed data to flag:

- ADS hidden content — named ADS stream with non-trivial size (>1 KB
  excluding Zone.Identifier ~100-byte tag). HIGH confidence.
- Timestomping — $SI mtime older than $FN mtime (classic anti-
  forensics tell — timestomp.exe / SetMACE / PowerShell SetCreation
  pattern). MEDIUM confidence.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    Boolean,
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


class WindowsMftRecord(Base):
    """Per-MFT-segment row from a walked raw NTFS image."""

    __tablename__ = "windows_mft_records"

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
        server_default=func.gen_random_uuid(),
    )

    # FK to the firmware whose extraction this NTFS image was parsed
    # from. Cascade DELETE so removing a firmware row removes its MFT
    # records.
    firmware_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("firmware.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Path to the raw NTFS image within the detection root (Rule #16).
    # Stored relative for stable cross-extraction identifiers.
    # E.g. ``images/disk0.raw`` or ``vhdx/root.dd``.
    source_path: Mapped[str] = mapped_column(String(2048), nullable=False)

    # MFT segment number (0-indexed). Together with firmware_id +
    # source_path forms the natural triage key for "show me segment N
    # of this volume". Stored as BigInt because 64-bit NTFS volumes
    # can hold >2^31 segments in extreme cases.
    segment_number: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # FILE_RECORD_SEGMENT_IN_USE flag — True for allocated records,
    # False for deleted-but-unreaped slots (NTFS reuses segment numbers
    # by overwriting). Both are emitted by fs.mft.segments(); the
    # deleted ones are forensically valuable (recovered file metadata
    # for files an attacker tried to wipe).
    in_use: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Type flag: True for directories, False for regular files. Indexed
    # jointly with firmware_id for "all files / all dirs" queries.
    is_directory: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )

    # Full path within the volume. NULL for orphaned deleted records
    # (the parent reference may point at a segment that's already been
    # overwritten). E.g. ``Windows\\System32\\cmd.exe``.
    full_path: Mapped[str | None] = mapped_column(String(4096), nullable=True)

    # Basename of full_path (filename component). NULL when full_path
    # is NULL. Useful for "find all entries named cmd.exe" forensic
    # queries; indexed jointly with firmware_id.
    filename: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # File size in bytes (resident + non-resident $DATA total). NULL
    # for directories or records without a $DATA attribute. Stored as
    # BigInt for large files (>2 GB).
    file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)

    # $STANDARD_INFORMATION timestamps — nanosecond-precision integers
    # since the dissect.ntfs API exposes both *_time (datetime) and
    # *_time_ns (int). We store the ns variant because:
    #   (a) ns-precision is REQUIRED for timestomp detection (a
    #       timestomp.exe attacker truncates to second-precision when
    #       writing $FN, leaving the $SI ns tail at 0 — diff math
    #       needs full precision).
    #   (b) Datetime arithmetic at second precision masks the diff.
    #   (c) Stored ns since 1601-01-01T00:00:00Z (NTFS FILETIME epoch
    #       converted to ns-since-epoch via FILETIME_to_ns).
    si_creation_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    si_last_modification_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    si_last_change_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    si_last_access_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # $FILE_NAME timestamps — same encoding as $SI columns. NTFS keeps
    # an INDEPENDENT four-tuple in the $FN attribute; the kernel writes
    # both on create/rename but does NOT update $FN on every $SI write.
    # Timestomp.exe / SetMACE rewrite $SI only, leaving $FN intact —
    # detection compares the two tuples (η.A.D windows_mft_timestomping
    # emit fires when $SI mtime < $FN mtime).
    fn_creation_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    fn_last_modification_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    fn_last_change_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )
    fn_last_access_ns: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # Named Alternate Data Streams. Canonical shape:
    #   [{"name": str, "size": int}, ...]
    # Empty list when the file has no ADS (the common case — only ~1 in
    # 1000 files has an ADS in normal use). Rule #35c stamped envelope.
    # The PRIMARY unnamed $DATA stream is NOT included here (that's
    # what file_size captures); this column is exclusively for *named*
    # streams (Zone.Identifier, the typical MOTW tag — but also any
    # attacker-planted "$DATA:hidden" payload).
    ads_streams: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Catchall per-record metadata for fields that don't warrant their
    # own flat column. Canonical shape:
    #   {
    #     "schema_version": 1,
    #     "parent_segment_ref": int | None,
    #     "reparse_point": bool,
    #     "attribute_flags": int,    # raw header.Flags value
    #     "hard_link_count": int | None,
    #     "sequence_number": int | None,
    #   }
    # NULL when no extras are surfaced (rare — defensive shape). Rule
    # #35c stamped envelope.
    target_metadata: Mapped[dict | None] = mapped_column(JSONB, nullable=True)

    # Walker run timestamp — when this row was inserted. Distinct from
    # the MFT timestamps above (which describe the file ON disk).
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Source-image MFT total segments — for context when paginating
    # large volumes; the walker stamps this from len(fs.mft.segments())
    # at run start. NULL only when the walker hasn't completed yet
    # (rare — rows aren't typically inserted before total is known).
    image_segment_count: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    __table_args__ = (
        # "All MFT records for firmware Y, oldest $FN creation first" —
        # the canonical forensic-timeline query shape.
        Index(
            "ix_windows_mft_records_firmware_fn_creation",
            "firmware_id",
            "fn_creation_ns",
        ),
        # "Find all entries named cmd.exe" — operator-UX forensic
        # search and ADS-hidden-content emit query.
        Index(
            "ix_windows_mft_records_firmware_filename",
            "firmware_id",
            "filename",
        ),
        # "Show me segment N of this volume" — the natural triage
        # navigation key.
        Index(
            "ix_windows_mft_records_firmware_segment",
            "firmware_id",
            "source_path",
            "segment_number",
        ),
    )
