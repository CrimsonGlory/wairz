r"""add memory_dump_walk_* columns to firmware (Phase λ.α.B)

Revision ID: bdf2a3b4c5d6
Revises: bce1f2a3b4c5
Create Date: 2026-05-13 01:45:00.000000

Adds five columns to the ``firmware`` table for the Phase λ.α.B
memory-dump-image enumerator 202+polling refactor (Rule #33 .a
contract). Mirrors the prefetch_walk_status / evtx_walk_status / srum_walk_status /
scheduled_task_walk_status / lnk_walk_status / mft_walk_status / bcd_walk_status
pattern already on the table — same 5-column shape, same DB CHECK.

The Phase λ.α.B enumerator (``backend/app/services/memory_image_enumerator.py``)
walks every memory-image candidate found under each detection root
(``app.services.firmware_paths.get_detection_roots`` per Rule #16 —
NOT ``firmware.extracted_path`` alone), filters by extension
(``.raw|.dmp|.vmem|.lime|.mem|.crash``) + minimum size (100 MB),
probes the magic bytes, classifies OS family (windows / linux / mac /
unknown), and persists per-image rows into ``memory_dump_image`` (table
from λ.α.A). Stamps an aggregate JSONB result onto
``memory_dump_walk_result`` summarising image count + per-OS-family
breakdown + total bytes scanned.

The enumerator does NOT invoke Volatility 3. λ.α.D ships the Vol3
runner that actually parses image contents; λ.α.B's role is metadata
surfacing only — "which memory images exist in this firmware tree?"
The split lets the enumerator run independently of the
``INCLUDE_VOL3=1`` Dockerfile gate (λ.α.C) — even on a build without
Vol3, operators see which images are present and could be analysed
elsewhere.

Per Rule #33 .d (asyncio.create_task vs arq rubric): the enumerator
runs entirely in-process (pure-Python filesystem walk + magic-byte
probe; no subprocess, no Docker spawn). Per-row persistence is the
durable state. ``asyncio.create_task`` is the correct dispatch —
same shape as γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B.

Columns:

- ``memory_dump_walk_status``: idle / queued / running / completed / failed
- ``memory_dump_walk_started_at``: when the background task picked up
- ``memory_dump_walk_finished_at``: when the run terminated
- ``memory_dump_walk_error``: traceback summary on failure (Text)
- ``memory_dump_walk_result``: JSONB aggregate ``{schema_version: 1,
  image_count: int, total_bytes: int, by_os_family: {windows: int,
  linux: int, mac: int, unknown: int}, elapsed_s: float}``.

CHECK constraint matches the prefetch_walk_status / bcd_walk_status
pattern (Rule #33 .c).

Revision ID ``bdf2a3b4c5d6`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from λ.α.A head ``bce1f2a3b4c5``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "bdf2a3b4c5d6"
down_revision = "bce1f2a3b4c5"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "memory_dump_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "memory_dump_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "memory_dump_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("memory_dump_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("memory_dump_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_memory_dump_walk_status",
        "firmware",
        "memory_dump_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_memory_dump_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "memory_dump_walk_result")
    op.drop_column("firmware", "memory_dump_walk_error")
    op.drop_column("firmware", "memory_dump_walk_finished_at")
    op.drop_column("firmware", "memory_dump_walk_started_at")
    op.drop_column("firmware", "memory_dump_walk_status")
