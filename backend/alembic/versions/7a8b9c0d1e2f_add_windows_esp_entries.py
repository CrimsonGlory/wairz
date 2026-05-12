"""add windows_esp_entries table (Phase θ.C.A)

Revision ID: 7a8b9c0d1e2f
Revises: 6e9f7a0b1c3d
Create Date: 2026-05-12 06:00:00.000000

Phase θ.C.A — adds the per-`.efi` landing zone for the Phase θ.C
EFI System Partition (ESP) PE chain correlation walker (θ.C.C).
`.efi` PE32+ files extracted from a firmware capture's EFI System
Partition (typically a FAT32 partition mounted on raw-image
extractions OR the ``EFI/`` directory at the root of an extracted
UEFI capsule) are walked by the θ.C.C runner, validated against the
β.4 signify Authenticode chain + β.10 DBX revocation list, and
persisted into this table.

Surfaces per-`.efi` forensic-triage metadata:

- **Source identifier** (file_path) — the relative path within the
  detection root (Rule #16) to the `.efi` file the walker parsed.
- **File-content identifiers** (file_sha256 + file_size) — SHA256 of
  the .efi contents is the canonical cross-firmware identifier
  (lookup_esp_chain MCP tool aggregates by sha256+fingerprint across
  the wairz corpus). file_size in bytes; tiny `.efi` < 4 KB is an
  early bootkit signal.
- **Authenticode state** (authenticode_state) — 5-state discriminator:
  signed_valid / signed_expired / signed_revoked / unsigned /
  parse_failed. DB CHECK constraint enforces the enum.
- **authenticode_chain JSONB** — chain summary from signify
  (β.4 verify_pe_file output). Surfaced for operator triage.
- **dbx_revocation_match JSONB** — DBX revocation match from
  β.10 match_dbx_revocation. NULL when no match.
- **anomaly_flags JSONB** — θ.C.D classifier inputs (is_unsigned,
  is_revoked, is_known_bootloader_path, is_suspiciously_small).
- **fingerprint_sha256** — SHA256 of (file_path_lower + file_sha256 +
  authenticode_state) for cross-firmware aggregation.

Per CLAUDE.md Rule #16: the θ.C.C walker uses
``get_detection_roots(firmware)`` — multi-archive ESP extractions
surface differently per unpacker; the multi-root discipline catches
FAT32 mounts, raw partition images, and direct ``EFI/`` directories.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only. The walker parses `.efi` files as PE32+ binaries via signify
(certificate-table reader) + pefile (COFF reader) + DBX matcher
(SHA256 / X.509 serial comparison) — all of which read the file as
DATA without transferring control to the executable. NO code path in
wairz invokes wine / mono / qemu-system / chainloader against the
persisted `.efi` files. The test gate
``tests/test_esp_walker.py::test_esp_no_efi_execution`` asserts this
discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: all three JSONB columns
(``authenticode_chain``, ``dbx_revocation_match``, ``anomaly_flags``)
get dedicated normaliser + schema_version stamp helpers in
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``7a8b9c0d1e2f``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from θ.B.E head ``6e9f7a0b1c3d``.

Indexes:

- ``ix_windows_esp_entries_firmware`` — ``(firmware_id,)`` covers
  "all ESP entries for firmware Y" canonical triage.
- ``ix_windows_esp_entries_firmware_sha256`` — ``(firmware_id,
  file_sha256)`` covers "show me the bootmgfw.efi hash" lookup.
- ``ix_windows_esp_entries_fingerprint`` — ``(fingerprint_sha256,)``
  covers the cross-firmware aggregation in ``lookup_esp_chain``
  MCP tool.
- ``ix_windows_esp_entries_firmware_state`` — ``(firmware_id,
  authenticode_state)`` covers the anomaly-focused MCP search filter.

CHECK constraint enforces the 5-state authenticode_state enum
(Rule #33 .c) — matches the Pydantic Literal mirror in
``app/schemas/windows_esp.py`` for boundary type-checking.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7a8b9c0d1e2f"
down_revision: str | None = "6e9f7a0b1c3d"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_esp_entries",
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
        # Relative path to the .efi file within the detection root.
        sa.Column("file_path", sa.String(2048), nullable=False),
        # SHA256 of the .efi file contents (64 hex chars).
        sa.Column("file_sha256", sa.String(64), nullable=False),
        # File size in bytes. BigInteger — legitimate winload.efi
        # can be 4-8 MB.
        sa.Column("file_size", sa.BigInteger, nullable=False),
        # Authenticode state discriminator (CHECK-enforced 5-state).
        sa.Column("authenticode_state", sa.String(32), nullable=False),
        # Chain summary from signify (β.4) — JSONB dict-shape.
        sa.Column("authenticode_chain", JSONB, nullable=True),
        # DBX revocation match from β.10 — JSONB dict-shape (NULL when
        # no match).
        sa.Column("dbx_revocation_match", JSONB, nullable=True),
        # Heuristic detection summary — JSONB dict-shape.
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # SHA256 of canonical entry tuple for cross-firmware
        # aggregation.
        sa.Column("fingerprint_sha256", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # CHECK constraint enforcing the 5-state authenticode_state enum
    # per Rule #33 .c. Mirrored by Pydantic Literal in
    # app/schemas/windows_esp.py.
    op.create_check_constraint(
        "ck_windows_esp_entries_authenticode_state",
        "windows_esp_entries",
        "authenticode_state IN "
        "('signed_valid', 'signed_expired', 'signed_revoked', "
        "'unsigned', 'parse_failed')",
    )
    op.create_index(
        "ix_windows_esp_entries_firmware",
        "windows_esp_entries",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_esp_entries_firmware_sha256",
        "windows_esp_entries",
        ["firmware_id", "file_sha256"],
    )
    op.create_index(
        "ix_windows_esp_entries_fingerprint",
        "windows_esp_entries",
        ["fingerprint_sha256"],
    )
    op.create_index(
        "ix_windows_esp_entries_firmware_state",
        "windows_esp_entries",
        ["firmware_id", "authenticode_state"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_esp_entries_firmware_state",
        table_name="windows_esp_entries",
    )
    op.drop_index(
        "ix_windows_esp_entries_fingerprint",
        table_name="windows_esp_entries",
    )
    op.drop_index(
        "ix_windows_esp_entries_firmware_sha256",
        table_name="windows_esp_entries",
    )
    op.drop_index(
        "ix_windows_esp_entries_firmware",
        table_name="windows_esp_entries",
    )
    op.drop_constraint(
        "ck_windows_esp_entries_authenticode_state",
        "windows_esp_entries",
        type_="check",
    )
    op.drop_table("windows_esp_entries")
