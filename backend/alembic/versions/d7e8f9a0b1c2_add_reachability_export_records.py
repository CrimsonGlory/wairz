"""add reachability_export_records table (MOVE 2 Phase 1 — bridge durability)

Revision ID: d7e8f9a0b1c2
Revises: c4a17052e000
Create Date: 2026-06-09 21:30:00.000000

Per-blob ELF symbol-presence landing zone for the wairz reachability bridge (binary axis).
One row per ELF :class:`HardwareFirmwareBlob`, holding the DEFINED + IMPORTED symbol sets the
producer (``app.services.reachability_export``) extracts. PERSISTING per-blob keeps the
firmware-level ``reachability_export_walk_result`` aggregate small (an ELF symbol table is
3k-30k strings; a firmware carries hundreds of ELF blobs) AND lets the Rule #44
``lookup_reachable_symbol_across_firmwares`` MCP tool answer "which firmwares DEFINE symbol X"
with a GIN-indexed JSONB-containment query (``defined_symbols @> '["X"]'``) instead of a Python
scan of a giant aggregate. (Red-team correction to the v2 convergence, which proposed a giant
firmware-level JSONB — unbounded at RedactedProduct scale + un-queryable for the lookup.)

PARSE-ONLY (Rule #36/#45): rows hold symbol NAMES read from the ELF symbol table AS DATA. The
completeness flags (stripped / has_symtab / has_dynsym) travel WITH each row so a consumer
re-checks trustworthiness — the Iron Law (symbol absence valid ONLY on a non-stripped,
sha256-matched binary) is enforced at the producer/consumer, never inferred from a stripped row.

Per CLAUDE.md Rule #19 evidence-first: revision id ``d7e8f9a0b1c2`` pre-validated FREE in the
versions tree before authoring. Chains from the live single head ``c4a17052e000``.

Indexes:
- ``uq_reachexport_firmware_sha256`` (firmware_id, blob_sha256) — one symbol record per
  (firmware, blob content); the walker upserts on this key.
- ``ix_reachexport_firmware`` (firmware_id) — per-firmware clear + re-populate + aggregate read.
- ``ix_reachexport_defined_gin`` (defined_symbols, GIN) — backs the Rule #44 cross-firmware
  ``defined_symbols @> '["X"]'`` containment query.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d7e8f9a0b1c2"
down_revision: str | None = "c4a17052e000"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "reachability_export_records",
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
        sa.Column(
            "blob_id",
            UUID(as_uuid=True),
            sa.ForeignKey("hardware_firmware_blobs.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("blob_path", sa.String(1024), nullable=False),
        sa.Column("blob_sha256", sa.String(64), nullable=False),
        sa.Column("defined_symbols", JSONB, nullable=True),
        sa.Column("imported_symbols", JSONB, nullable=True),
        sa.Column(
            "stripped", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "has_symtab", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column(
            "has_dynsym", sa.Boolean, nullable=False, server_default=sa.text("false")
        ),
        sa.Column("arch", sa.String(32), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "firmware_id", "blob_sha256", name="uq_reachexport_firmware_sha256"
        ),
    )
    op.create_index(
        "ix_reachexport_firmware",
        "reachability_export_records",
        ["firmware_id"],
    )
    op.create_index(
        "ix_reachexport_defined_gin",
        "reachability_export_records",
        ["defined_symbols"],
        postgresql_using="gin",
    )


def downgrade() -> None:
    op.drop_index(
        "ix_reachexport_defined_gin", table_name="reachability_export_records"
    )
    op.drop_index(
        "ix_reachexport_firmware", table_name="reachability_export_records"
    )
    op.drop_table("reachability_export_records")
