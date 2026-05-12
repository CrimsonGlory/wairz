"""add windows_efs_encrypted_files table (Phase ι.D.A — SECOND ι WINDOWS WALKER)

Revision ID: aabbccddee07
Revises: aabbccddee06
Create Date: 2026-05-12 19:30:00.000000

Phase ι.D.A — adds the per-file landing zone for the FOURTH ι walker in
wairz's portfolio (SECOND ι Windows-side after ι.C ETW; ι.A + ι.B were
Linux). The Phase ι.D.C walker identifies EFS-encrypted files via the
``FILE_ATTRIBUTE_ENCRYPTED`` (0x4000) bit on ``$STANDARD_INFORMATION``,
reads the file's ``LOGGED_UTILITY_STREAM`` attribute (type 0x100) which
carries the ``$EFS`` blob, and surfaces metadata about WHO CAN DECRYPT
(DDF user list) and WHO IS THE RECOVERY AGENT (DRF list).

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #36 EXTENSION (no decryption,
no DPAPI, no FEK handling).** The walker captures METADATA ONLY. It
NEVER decrypts the RSA-encrypted FEK, NEVER invokes Windows DPAPI
(``CryptUnprotectData``), NEVER attempts plaintext recovery, NEVER
imports cryptographic decryption modules. The "who can decrypt + who is
the recovery agent" surface is the forensic value (T1486 ransomware,
T1564.001 insider stealth, supply-chain fingerprint).

**Real-world Persona-E EFS relevance:**

- **SafeBreach 2020 PoC** — abused EFS for ransomware-like behaviour
  by encrypting victim files with attacker-controlled DDF.
- **Insider-threat patterns** — unauthorized SID in DDF = silent
  exfiltration vector; the file looks normal to the file owner.
- **Recovery agent supply-chain** — same DRF certificate thumbprint
  across multiple supposedly-independent firmwares = shared backdoor
  key (high) OR un-rekeyed vendor default (medium baseline review).

Per CLAUDE.md Rule #16: the ι.D.C walker uses ``get_detection_roots(firmware)``
(NOT ``firmware.extracted_path`` alone) so multi-rootfs Windows
firmware (VHDX / NTFS / FAT32 / system images) surfaces every NTFS
volume candidate. The walker reuses η.A's NTFS plumbing (``mft_walker.py``
``walk_raw_ntfs_images`` + ``looks_like_ntfs`` + ``_safe_attribute_value``).

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee07``
pre-validated FREE in the versions tree (grep returned 0 hits) before
authoring. Chains from ι.C.D head ``aabbccddee06``. The ``dissect.ntfs``
API surface (LOGGED_UTILITY_STREAM 0x100 + ``ATTRIBUTE_FLAG_ENCRYPTED``
0x4000) was confirmed via ``inspect.getsource`` on Attribute/AttributeMap
and ``dir(dissect.ntfs.c_ntfs)`` before authoring this migration:

- ``ATTRIBUTE_TYPE_CODE.LOGGED_UTILITY_STREAM = 0x100`` (the $EFS attr type)
- ``ATTRIBUTE_FLAG_ENCRYPTED = 0x4000`` (per-stream EFS flag at attr header)
- ``MftRecord.attributes`` returns ``AttributeMap`` (UserDict-like by type code)
- ``AttributeCollection[0].open()`` / ``.data()`` returns raw bytes of the attr

Per CLAUDE.md Rule #35c JSONB discipline: each JSONB column gets a
dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers`` (3 helpers for this table:
ddf_users / drf_recovery_agents / anomaly_flags).

Indexes:

- ``ix_windows_efs_encrypted_files_firmware_mft_record`` — ``(firmware_id,
  mft_record_number)`` covers cross-correlation with η.A's
  ``windows_mft_records`` table (operator can JOIN to fetch full MFT
  metadata for any EFS file).
- ``ix_windows_efs_encrypted_files_firmware_ddf_count`` — ``(firmware_id,
  ddf_user_count)`` covers shared-decryption candidate filtering.
- ``ix_windows_efs_encrypted_files_firmware_drf_count`` — ``(firmware_id,
  drf_recovery_agent_count)`` covers unusual-DRF-configuration filtering.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee07"
down_revision: str | None = "aabbccddee06"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_efs_encrypted_files",
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
        sa.Column("file_path", sa.String(1024), nullable=True),
        sa.Column("file_size", sa.BigInteger, nullable=True),
        sa.Column("mft_record_number", sa.BigInteger, nullable=False),
        sa.Column("efs_attribute_size", sa.Integer, nullable=False),
        sa.Column(
            "ddf_user_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column(
            "drf_recovery_agent_count",
            sa.Integer,
            nullable=False,
            server_default="0",
        ),
        sa.Column("ddf_users", JSONB, nullable=True),
        sa.Column("drf_recovery_agents", JSONB, nullable=True),
        sa.Column("anomaly_flags", JSONB, nullable=True),
        sa.Column("parse_error", sa.Text, nullable=True),
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
        "ix_windows_efs_encrypted_files_firmware_mft_record",
        "windows_efs_encrypted_files",
        ["firmware_id", "mft_record_number"],
    )
    op.create_index(
        "ix_windows_efs_encrypted_files_firmware_ddf_count",
        "windows_efs_encrypted_files",
        ["firmware_id", "ddf_user_count"],
    )
    op.create_index(
        "ix_windows_efs_encrypted_files_firmware_drf_count",
        "windows_efs_encrypted_files",
        ["firmware_id", "drf_recovery_agent_count"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_efs_encrypted_files_firmware_drf_count",
        table_name="windows_efs_encrypted_files",
    )
    op.drop_index(
        "ix_windows_efs_encrypted_files_firmware_ddf_count",
        table_name="windows_efs_encrypted_files",
    )
    op.drop_index(
        "ix_windows_efs_encrypted_files_firmware_mft_record",
        table_name="windows_efs_encrypted_files",
    )
    op.drop_table("windows_efs_encrypted_files")
