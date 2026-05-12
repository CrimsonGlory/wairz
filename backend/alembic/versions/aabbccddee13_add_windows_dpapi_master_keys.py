"""add windows_dpapi_master_keys table (Phase κ.D.A — NINTH κ-era walker)

Revision ID: aabbccddee13
Revises: aabbccddee12
Create Date: 2026-05-12 23:30:00.000000

Phase κ.D.A — adds the per-file landing zone for the Windows DPAPI
master-key PARSE-ONLY METADATA walker. Master-key files live under
``Users\\<user>\\AppData\\Roaming\\Microsoft\\Protect\\<sid>\\<guid>`` on
Windows installations and are the gateway to DPAPI-protected data
(Outlook credentials, browser passwords, certificate private keys,
WinSCP profile passwords, Wi-Fi credentials, ...).

**Real-world Persona-E DPAPI master-key relevance:**

- ``orphaned_masterkey``: creator_sid doesn't match any user SID found
  elsewhere in the firmware. Could be a backdoor key stash (attacker
  pre-staged keys for later credential decryption) or legacy artefact
  (user deleted, key files remained). Persona-E HIGH.

- ``admin_creator_sid``: creator_sid matches a Windows admin RID
  pattern (RID 500 / 512 / 519 / 18 — Built-in Administrator, Domain
  Admins, Enterprise Admins, Local System). Could be legitimate (admin
  service-account use) or compromise indicator. Persona-E MEDIUM.

- ``large_masterkey``: file_size_bytes > 2048. Typical master-key
  files are 740-1024 bytes; oversized files may indicate unusual DPAPI
  configuration or attacker-planted artefact. Persona-E LOW baseline.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #45 (parse-only-metadata
walker, Rule-of-Two — DURABLE BEYOND DEBATE).** The κ.D.C walker
parses the master-key file's HEADER + body PREAMBLE AS DATA via pure-
Python ``struct`` unpacking. The walker NEVER:

- Decrypts master keys.
- Invokes ``CryptUnprotectData`` or any DPAPI shim.
- Imports cryptographic decryption modules (no ``cryptography.fernet``,
  no ``impacket.dpapi.MasterKey().decrypt()`` calls).
- Records the salt bytes (only the SIZE — exposing the salt would aid
  offline cracking).

The walker's source is tokenized against forbidden invocation +
decryption tokens in ``test_dpapi_walker.py::test_walker_no_decrypt``,
plus a canary test confirms the gate ACTUALLY fires on synthetic
violations.

Per CLAUDE.md Rule #16: the κ.D.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Windows firmware (VHDX / NTFS / FAT32 / system
images) surfaces every Protect folder candidate.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee13``
pre-validated FREE in the versions tree (grep returned 0 hits) before
authoring. Chains from κ.C.D head ``aabbccddee12``.

Per CLAUDE.md Rule #35c JSONB discipline: the ``anomaly_flags`` JSONB
column gets a dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers``.

Indexes:

- ``ix_windows_dpapi_master_keys_firmware_guid`` — ``(firmware_id,
  master_key_guid)`` covers cross-firmware GUID joins for the
  ``lookup_dpapi_master_key_across_firmwares`` MCP tool.
- ``ix_windows_dpapi_master_keys_firmware_sid`` — ``(firmware_id,
  creator_sid)`` covers insider-threat queries ("which keys did user
  X create?").
- ``ix_windows_dpapi_master_keys_firmware_modified`` — ``(firmware_id,
  last_modified_ts)`` covers timeline correlation.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee13"
down_revision: str | None = "aabbccddee12"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_dpapi_master_keys",
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
        sa.Column("source_file_path", sa.String(1024), nullable=False),
        sa.Column("master_key_guid", sa.String(64), nullable=True),
        sa.Column("creator_sid", sa.String(256), nullable=True),
        sa.Column("flags", sa.Integer, nullable=True),
        sa.Column("hmac_iterations", sa.Integer, nullable=True),
        sa.Column("salt_size", sa.Integer, nullable=True),
        sa.Column("master_key_size", sa.Integer, nullable=True),
        sa.Column("backup_key_size", sa.Integer, nullable=True),
        sa.Column("cred_hist_size", sa.Integer, nullable=True),
        sa.Column("domain_key_size", sa.Integer, nullable=True),
        sa.Column("file_size_bytes", sa.BigInteger, nullable=True),
        sa.Column(
            "last_modified_ts",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column("anomaly_flags", JSONB, nullable=True),
        sa.Column(
            "schema_version",
            sa.Integer,
            nullable=False,
            server_default="1",
        ),
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
        "ix_windows_dpapi_master_keys_firmware_guid",
        "windows_dpapi_master_keys",
        ["firmware_id", "master_key_guid"],
    )
    op.create_index(
        "ix_windows_dpapi_master_keys_firmware_sid",
        "windows_dpapi_master_keys",
        ["firmware_id", "creator_sid"],
    )
    op.create_index(
        "ix_windows_dpapi_master_keys_firmware_modified",
        "windows_dpapi_master_keys",
        ["firmware_id", "last_modified_ts"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_dpapi_master_keys_firmware_modified",
        table_name="windows_dpapi_master_keys",
    )
    op.drop_index(
        "ix_windows_dpapi_master_keys_firmware_sid",
        table_name="windows_dpapi_master_keys",
    )
    op.drop_index(
        "ix_windows_dpapi_master_keys_firmware_guid",
        table_name="windows_dpapi_master_keys",
    )
    op.drop_table("windows_dpapi_master_keys")
