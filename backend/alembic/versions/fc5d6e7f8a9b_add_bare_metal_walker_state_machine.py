r"""add bare-metal walker state machine + descriptor table (Rule #52 Phase 1)

Revision ID: fc5d6e7f8a9b
Revises: e1f2a3b4c5d6
Create Date: 2026-05-19 15:30:00.000000

DDL infrastructure for the schema-driven bare-metal MCU/DSP support per
CLAUDE.md Rule #52 — Eaton TMS320F28066 reference case. Three concerns:

1. **``firmware`` columns — bare_metal_audit walker state machine** per
   CLAUDE.md Rule #33 .a 5-state contract:
   - ``bare_metal_audit_status`` (Literal[idle|queued|running|completed|failed])
     + ``ck_firmware_bare_metal_audit_status`` CHECK
   - ``bare_metal_audit_started_at`` / ``bare_metal_audit_finished_at`` timestamps
   - ``bare_metal_audit_error`` text (failure trace)
   - ``bare_metal_audit_result`` JSONB (per-run policy audit aggregate;
     Rule #35c normaliser in ``services/jsonb_normalizers.py``)

2. **``hardware_firmware_blobs.chip_target``** — text FK shape
   ``vendor/family/domain`` matching the catalog's ``family_id + domain_name``
   triple. Nullable because most existing blobs predate the catalog;
   auto-detect or operator hint populates it post-walk.

3. **``bare_metal_descriptors`` table** — external-ingestor / operator
   chip hint store per Rule #33 .a idempotency + Scout CC §SC11
   provenance arbitration:
   - ``id`` UUID PK; ``firmware_id`` FK
   - ``descriptor_source`` text (Literal[operator|attested_external|
     unauthenticated_external|auto_detection])
   - ``ingestor_id`` text NULL (Velociraptor instance id / operator handle)
   - ``descriptor_hash`` text NULL (idempotency key — same hash from
     same ingestor within window = 200 idempotent ack)
   - ``payload`` JSONB NOT NULL (Rule #35c normaliser pair)
   - ``received_at`` timestamp NOT NULL DEFAULT now()
   - ``supersedes_id`` self-FK NULL (descriptor that supersedes prior)

Indices:
   - ``ix_bare_metal_descriptors_firmware_id_received_at`` covers the
     "most recent descriptor per firmware" lookup the walker runs.
   - ``ux_bare_metal_descriptors_idempotency`` UNIQUE on
     ``(firmware_id, ingestor_id, descriptor_hash)`` enforces Rule #33 .a
     — replay-protection at the storage layer, not just the application
     layer.

**Does NOT extend findings.source CHECK** — that lands in P1.9 as a
Rule #25 Shape-1 cross-stack alignment commit alongside the Pydantic
``BareMetalFindingSource`` Literal + frontend ``FINDING_SOURCE_CONFIG``
mirror + ``test_finding_source_alignment`` extension. Splitting that
to keep the migration focused on DDL infrastructure; finding-source
alignment is the operator-visible surface change and gets its own
attention.

Chains from ι.A.B head ``e1f2a3b4c5d6`` (the scheduled-task-name
composite index migration). No backfill needed — every existing
firmware row gets ``bare_metal_audit_status='idle'`` via the server
default.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "fc5d6e7f8a9b"
down_revision: str | None = "e1f2a3b4c5d6"
branch_labels: str | None = None
depends_on: str | None = None


_VALID_AUDIT_STATUSES = ("idle", "queued", "running", "completed", "failed")
_VALID_DESCRIPTOR_SOURCES = (
    "operator",
    "attested_external",
    "unauthenticated_external",
    "auto_detection",
)


def upgrade() -> None:
    # ── firmware.bare_metal_audit_* ──────────────────────────────────────
    op.add_column(
        "firmware",
        sa.Column(
            "bare_metal_audit_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.create_check_constraint(
        "ck_firmware_bare_metal_audit_status",
        "firmware",
        "bare_metal_audit_status IN ('idle', 'queued', 'running', 'completed', 'failed')",
    )
    op.add_column(
        "firmware",
        sa.Column(
            "bare_metal_audit_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "bare_metal_audit_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("bare_metal_audit_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "bare_metal_audit_result",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )

    # ── hardware_firmware_blobs.chip_target ──────────────────────────────
    op.add_column(
        "hardware_firmware_blobs",
        sa.Column("chip_target", sa.String(128), nullable=True),
    )
    op.create_index(
        "ix_hardware_firmware_blobs_chip_target",
        "hardware_firmware_blobs",
        ["chip_target"],
    )

    # ── bare_metal_descriptors ───────────────────────────────────────────
    op.create_table(
        "bare_metal_descriptors",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "firmware_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "descriptor_source",
            sa.String(32),
            nullable=False,
        ),
        sa.Column("ingestor_id", sa.String(128), nullable=True),
        sa.Column("descriptor_hash", sa.String(128), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "supersedes_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("bare_metal_descriptors.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_check_constraint(
        "ck_bare_metal_descriptors_source",
        "bare_metal_descriptors",
        "descriptor_source IN ("
        + ", ".join(f"'{v}'" for v in _VALID_DESCRIPTOR_SOURCES)
        + ")",
    )
    # Most-recent-descriptor-per-firmware lookup
    op.create_index(
        "ix_bare_metal_descriptors_firmware_received",
        "bare_metal_descriptors",
        ["firmware_id", sa.text("received_at DESC")],
    )
    # Rule #33 .a idempotency — replay-protection at the storage layer.
    # Partial unique index: only enforces when both ingestor_id AND
    # descriptor_hash are non-null (operator hand-submitted descriptors
    # may legitimately omit either field).
    op.create_index(
        "ux_bare_metal_descriptors_idempotency",
        "bare_metal_descriptors",
        ["firmware_id", "ingestor_id", "descriptor_hash"],
        unique=True,
        postgresql_where=sa.text(
            "ingestor_id IS NOT NULL AND descriptor_hash IS NOT NULL"
        ),
    )


def downgrade() -> None:
    op.drop_index(
        "ux_bare_metal_descriptors_idempotency",
        table_name="bare_metal_descriptors",
    )
    op.drop_index(
        "ix_bare_metal_descriptors_firmware_received",
        table_name="bare_metal_descriptors",
    )
    op.drop_constraint(
        "ck_bare_metal_descriptors_source",
        "bare_metal_descriptors",
        type_="check",
    )
    op.drop_table("bare_metal_descriptors")

    op.drop_index(
        "ix_hardware_firmware_blobs_chip_target",
        table_name="hardware_firmware_blobs",
    )
    op.drop_column("hardware_firmware_blobs", "chip_target")

    op.drop_column("firmware", "bare_metal_audit_result")
    op.drop_column("firmware", "bare_metal_audit_error")
    op.drop_column("firmware", "bare_metal_audit_finished_at")
    op.drop_column("firmware", "bare_metal_audit_started_at")
    op.drop_constraint(
        "ck_firmware_bare_metal_audit_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "bare_metal_audit_status")
