"""add windows_mft_records table (Phase η.A.A)

Revision ID: 1f3a2b4c5d6e
Revises: a7b8c9d0e1f2
Create Date: 2026-05-11 00:30:00.000000

Phase η.A.A — adds the per-record landing zone for the Phase η.A NTFS
$MFT walker (η.A.C). Raw NTFS images extracted from firmware captures
(typically VHDX → raw via the α.2.7 qemu-img pipeline, or raw
partitions from β.7) are walked via dissect.ntfs ``NTFS(fh).mft.segments()``
to surface every MFT record (allocated + unallocated). Each record
becomes one row in this table.

Surfaces per-MFT-segment forensic-triage metadata:

- **$STANDARD_INFORMATION timestamps** (4 ns-precision columns:
  si_creation_ns / si_last_modification_ns / si_last_change_ns /
  si_last_access_ns) — the kernel writes these on every metadata
  change. ns precision is required because timestomp.exe / SetMACE
  truncate $FN to second-precision when rewriting, leaving the $SI
  ns tail at 0 — diff math at full precision is the detection key.
- **$FILE_NAME timestamps** (4 ns-precision columns:
  fn_creation_ns / fn_last_modification_ns / fn_last_change_ns /
  fn_last_access_ns) — the kernel writes these on create / rename
  only. NOT updated on every $SI write. Timestomp.exe / SetMACE
  rewrite $SI only, leaving $FN intact — η.A.D
  windows_mft_timestomping detection fires when $SI mtime < $FN
  mtime.
- **$DATA AttributeCollection summary** — file_size for the primary
  (unnamed) stream; ads_streams JSONB for the per-record named ADS
  roster (each entry ``{"name": str, "size": int}``). The
  ADS-hidden-content vector (η.A.D windows_mft_ads_hidden_content)
  fires on named ADS with non-trivial size; excludes Zone.Identifier
  ~100-byte MOTW tag.
- **Allocated/deleted state** (in_use bool) — fs.mft.segments() yields
  both; the FILE_RECORD_SEGMENT_IN_USE flag distinguishes them.
  Deleted-but-unreaped records carry recovered metadata for files an
  attacker tried to wipe.
- **Type flags** (is_directory bool) — distinguishes file from
  directory records. is_reparse_point lives in target_metadata JSONB.
- **Path columns** (full_path + filename) — full_path is the full
  in-volume path; filename is the basename for fast "find all
  cmd.exe" queries.
- **Segment context** (segment_number + image_segment_count +
  source_path) — the natural triage key for "show me segment N of
  this volume / this image".
- **target_metadata JSONB** — catchall for fields not worth a flat
  column (parent_segment_ref, reparse_point bool, attribute_flags,
  hard_link_count, sequence_number).

Per CLAUDE.md Rule #16: the η.A.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-archive / scatter-zip firmware extracts surface
every NTFS image candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker treats raw NTFS images as untrusted input via
dissect.ntfs (a pure-Python parser); nothing in wairz mounts the
volume, invokes ntfs-3g / mount / qemu-system, or executes any
binary from the parsed filesystem.

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns
(``ads_streams`` and ``target_metadata``) get dedicated normalizer +
schema_version stamp helpers in ``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``1f3a2b4c5d6e``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from η.C.D head ``a7b8c9d0e1f2``.

Indexes:

- ``ix_windows_mft_records_firmware_fn_creation`` —
  ``(firmware_id, fn_creation_ns)`` covers "all MFT records for
  firmware Y, oldest $FN creation first" forensic-timeline queries.
- ``ix_windows_mft_records_firmware_filename`` —
  ``(firmware_id, filename)`` covers "find all entries named X"
  operator-UX forensic search and the η.A.D ADS-hidden-content emit
  query shape.
- ``ix_windows_mft_records_firmware_segment`` —
  ``(firmware_id, source_path, segment_number)`` covers
  "show me segment N of image Z" triage navigation.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "1f3a2b4c5d6e"
down_revision: str | None = "a7b8c9d0e1f2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_mft_records",
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
        # Path to the raw NTFS image within the detection root
        # (Rule #16). Stored relative for stable cross-extraction
        # identifiers. E.g. ``images/disk0.raw``.
        sa.Column("source_path", sa.String(2048), nullable=False),
        # MFT segment number (0-indexed). BigInt for 64-bit volumes.
        sa.Column("segment_number", sa.BigInteger, nullable=False),
        # FILE_RECORD_SEGMENT_IN_USE flag.
        sa.Column(
            "in_use",
            sa.Boolean,
            nullable=False,
            server_default=sa.true(),
        ),
        # Type flag — True for directories, False for files.
        sa.Column(
            "is_directory",
            sa.Boolean,
            nullable=False,
            server_default=sa.false(),
        ),
        # Full path within the volume. NULL for orphans.
        sa.Column("full_path", sa.String(4096), nullable=True),
        # Basename — same as last path component of full_path. NULL
        # when full_path is NULL.
        sa.Column("filename", sa.String(512), nullable=True),
        # File size in bytes ($DATA primary). NULL for directories /
        # missing $DATA. BigInt for >2 GB files.
        sa.Column("file_size", sa.BigInteger, nullable=True),
        # $STANDARD_INFORMATION timestamps — ns-precision.
        sa.Column("si_creation_ns", sa.BigInteger, nullable=True),
        sa.Column("si_last_modification_ns", sa.BigInteger, nullable=True),
        sa.Column("si_last_change_ns", sa.BigInteger, nullable=True),
        sa.Column("si_last_access_ns", sa.BigInteger, nullable=True),
        # $FILE_NAME timestamps — ns-precision. Timestomp detection
        # compares these against $SI.
        sa.Column("fn_creation_ns", sa.BigInteger, nullable=True),
        sa.Column("fn_last_modification_ns", sa.BigInteger, nullable=True),
        sa.Column("fn_last_change_ns", sa.BigInteger, nullable=True),
        sa.Column("fn_last_access_ns", sa.BigInteger, nullable=True),
        # Named ADS roster. JSONB list-shape; rule #35c stamped via
        # _stamp_windows_mft_records_ads_streams. Empty list when no
        # ADS; absent (NULL) only on defensive parser failure.
        sa.Column("ads_streams", JSONB, nullable=True),
        # Catchall metadata dict. JSONB dict-shape; rule #35c stamped
        # via _stamp_windows_mft_records_target_metadata. NULL when
        # no extras surfaced.
        sa.Column("target_metadata", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        # Image-wide segment count for context. NULL during in-progress
        # walks.
        sa.Column("image_segment_count", sa.Integer, nullable=True),
    )
    op.create_index(
        "ix_windows_mft_records_firmware_fn_creation",
        "windows_mft_records",
        ["firmware_id", "fn_creation_ns"],
    )
    op.create_index(
        "ix_windows_mft_records_firmware_filename",
        "windows_mft_records",
        ["firmware_id", "filename"],
    )
    op.create_index(
        "ix_windows_mft_records_firmware_segment",
        "windows_mft_records",
        ["firmware_id", "source_path", "segment_number"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_mft_records_firmware_segment",
        table_name="windows_mft_records",
    )
    op.drop_index(
        "ix_windows_mft_records_firmware_filename",
        table_name="windows_mft_records",
    )
    op.drop_index(
        "ix_windows_mft_records_firmware_fn_creation",
        table_name="windows_mft_records",
    )
    op.drop_table("windows_mft_records")
