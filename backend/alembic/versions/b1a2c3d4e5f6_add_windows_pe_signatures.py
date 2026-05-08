"""add_windows_pe_signatures table for Phase β Authenticode

Revision ID: b1a2c3d4e5f6
Revises: 89007f64cfb0
Create Date: 2026-05-07 20:00:00.000000

Per-PE-binary Authenticode + RICH header + DBX revocation + ARM64EC/X
arch-view signature record. Phase β.2 of the Windows-coverage god-mode
campaign (.planning/intake/windows-coverage-godmode-2026-05-07.md).

Per Persona-D #3.b discussion + Persona-E #10 cross-reference workflow:
- New table (not JSONB on firmware.device_metadata) — efficient
  ``WHERE leaf_serial IN (dbx_set)`` SELECTs across firmware boundaries.
- ``CHECK (chain_status IN (...))`` durable gate per Rule #33 .c.
- ON DELETE CASCADE on the FK to hardware_firmware_blobs.id.
- 3 indexes: blob_id (cascade traversal), dbx_revoked (revocation
  rollup queries), chain_status (PE Hardening Dashboard filtering).
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB


# revision identifiers, used by Alembic.
revision = "b1a2c3d4e5f6"
down_revision = "89007f64cfb0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "windows_pe_signatures",
        sa.Column(
            "id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "blob_id",
            sa.dialects.postgresql.UUID(as_uuid=True),
            sa.ForeignKey("hardware_firmware_blobs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "signed",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("signer_subject", sa.Text),
        sa.Column("signer_issuer", sa.Text),
        sa.Column("leaf_serial", sa.String(128)),
        sa.Column("sig_hash_algo", sa.String(32)),
        sa.Column("tsa_authority", sa.Text),
        sa.Column(
            "signed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.Column(
            "chain_status",
            sa.String(32),
            nullable=False,
            server_default="unknown",
        ),
        sa.Column("chain_json", JSONB),
        sa.Column(
            "dbx_revoked",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("dbx_revocation_kb", sa.String(32)),
        sa.Column("rich_header_json", JSONB),
        sa.Column("arch_view", JSONB),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        # Persona-E #2 chain-status tri-state CHECK (Rule #33 .c).
        sa.CheckConstraint(
            "chain_status IN ('valid_at_signing', 'valid_now', 'revoked', "
            "'never_valid', 'unknown')",
            name="ck_windows_pe_signatures_chain_status",
        ),
    )
    # Persona-E #10 + PE Hardening Dashboard query patterns.
    op.create_index(
        "ix_windows_pe_signatures_blob_id",
        "windows_pe_signatures",
        ["blob_id"],
    )
    op.create_index(
        "ix_windows_pe_signatures_leaf_serial",
        "windows_pe_signatures",
        ["leaf_serial"],
    )
    op.create_index(
        "ix_windows_pe_signatures_dbx",
        "windows_pe_signatures",
        ["dbx_revoked"],
    )
    op.create_index(
        "ix_windows_pe_signatures_chain_status",
        "windows_pe_signatures",
        ["chain_status"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_pe_signatures_chain_status",
        table_name="windows_pe_signatures",
    )
    op.drop_index(
        "ix_windows_pe_signatures_dbx",
        table_name="windows_pe_signatures",
    )
    op.drop_index(
        "ix_windows_pe_signatures_leaf_serial",
        table_name="windows_pe_signatures",
    )
    op.drop_index(
        "ix_windows_pe_signatures_blob_id",
        table_name="windows_pe_signatures",
    )
    op.drop_table("windows_pe_signatures")
