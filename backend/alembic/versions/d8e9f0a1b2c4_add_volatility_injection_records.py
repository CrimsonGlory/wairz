r"""add volatility_injection_records + windows_injection_walk_* cols (Phase λ.γ.A)

Revision ID: d8e9f0a1b2c4
Revises: d6e7f8a9b0c2
Create Date: 2026-05-14 11:00:00.000000

Phase λ.γ walker — invokes Vol3's ``windows.malware.malfind`` /
``windows.malware.hollowprocesses`` / ``windows.malware.ldrmodules`` /
``windows.malware.processghosting`` / ``windows.malware.pebmasquerade``
plugin family against every ``memory_dump_image`` row whose
``os_family`` is ``windows`` OR ``unknown``. Surfaces five
high-fidelity injection / hollowing / hiding indicators as one row
per detection.

**Hard deadline 2026-06-07** for the top-level ``windows.malware.<X>``
relocation — Vol3 has flagged the deprecated top-level paths
(``hollowprocesses``, ``malfind``, ``ldrmodules``, ``processghosting``,
``psxview``) for removal at that date. The walker wires EXCLUSIVELY to
the canonical ``windows.malware.<X>`` paths (Rule #36 argv-discipline
gate at the walker boundary; commit-time grep enforces zero matches
for the deprecated top-level shapes).

Per Rule #44 cross-firmware aggregation: the per-row
``hexdump_sha256`` column (SHA256 of the first 64 bytes of an
``injected_code_region`` detection's hexdump) is the canonical
**"same injection across captures"** identity key. The MCP tool
``lookup_volatility_injection_across_firmwares`` (next commit)
joins on this column. ``supply_chain_signal=True`` when match_count
>= 2 — the strongest cross-firmware indicator any λ-stream walker
produces.

Per Rule #45 metadata-walker discipline: the walker surfaces hexdumps
+ paths + region metadata AS DATA. wairz NEVER tries to deobfuscate
injected code, NEVER invokes a region for execution, NEVER patches a
process via Vol3's read-write layer (the runner pins ``--offline``
and reads only).

Per Rule #33 .a state machine + .c CHECK constraint: new column
``windows_injection_walk_status`` constrained via
``ck_firmware_windows_injection_walk_status`` to the 5-state machine.

Revision ID ``d8e9f0a1b2c4`` was pre-validated FREE against the
versions tree (127 revs enumerated post-λ.β.A; the chosen ID does
not collide). Chains off ``d6e7f8a9b0c2`` (λ.β.A — single head after
λ.β ships).
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

revision = "d8e9f0a1b2c4"
down_revision = "d6e7f8a9b0c2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── volatility_injection_records table ────────────────────────────
    op.create_table(
        "volatility_injection_records",
        sa.Column(
            "id",
            UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "firmware_id",
            UUID(as_uuid=True),
            sa.ForeignKey("firmware.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "memory_image_id",
            UUID(as_uuid=True),
            sa.ForeignKey("memory_dump_image.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Five canonical kinds — pinned via the new CHECK constraint
        # below. Direct mapping to the future FindingSource values:
        # vol3_hollow_process / vol3_unlinked_process /
        # vol3_injected_code_region / vol3_peb_masquerade /
        # vol3_ghosted_process.
        sa.Column("detection_kind", sa.String(32), nullable=False),
        # Full Vol3 plugin name — `windows.malware.malfind` etc.
        # Stored as data so an operator can grep for "which plugin
        # emitted this row" without re-running the walker.
        sa.Column("detected_by_plugin", sa.String(64), nullable=False),
        sa.Column("pid", sa.Integer, nullable=False),
        sa.Column("image_filename", sa.String(256), nullable=False),
        # Memory region — present for malfind (injected code region
        # start VPN) and pebmasquerade (PEB ImageBaseAddress).
        sa.Column("region_address", sa.BigInteger, nullable=True),
        sa.Column("region_size", sa.BigInteger, nullable=True),
        # Page protection bits — "PAGE_EXECUTE_READWRITE", etc.
        # malfind's RWX detection is the canonical signal here.
        sa.Column("region_protection", sa.String(32), nullable=True),
        # First 64 bytes of malfind's hexdump emit, in canonical
        # "01 02 03 ..." spaced-hex form (NOT raw bytes — keeps the
        # column human-grep-able + indexable as a string).
        sa.Column("hexdump_first_64_bytes", sa.String(256), nullable=True),
        # SHA256 of the canonicalised hexdump_first_64_bytes (lower-case
        # hex pairs joined by single spaces — the canonicalisation
        # happens in the walker before hashing). This is the **Rule #44
        # cross-firmware identity key**.
        sa.Column("hexdump_sha256", sa.String(64), nullable=True),
        # Process-hollowing + PEB-masquerade fields.
        sa.Column("masquerade_path", sa.String(1024), nullable=True),
        sa.Column("actual_path", sa.String(1024), nullable=True),
        # ldrmodules emit — module-name + which lists it appeared in
        # / was missing from.
        sa.Column("module_name", sa.String(256), nullable=True),
        # processghosting emit — the image path that's been deleted
        # from disk.
        sa.Column("ghosted_path", sa.String(1024), nullable=True),
        # Schema-versioned evidence payload — per-detection extra
        # context (anomaly flags, derived properties).
        sa.Column("evidence", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
        ),
    )
    op.create_check_constraint(
        "ck_volatility_injection_records_detection_kind",
        "volatility_injection_records",
        "detection_kind IN "
        "('injected_code_region', 'hollow_process', 'unlinked_module', "
        "'peb_masquerade', 'ghosted_process')",
    )
    op.create_index(
        "ix_volatility_injection_records_firmware_kind",
        "volatility_injection_records",
        ["firmware_id", "detection_kind"],
    )
    op.create_index(
        "ix_volatility_injection_records_firmware_pid",
        "volatility_injection_records",
        ["firmware_id", "pid"],
    )
    op.create_index(
        "ix_volatility_injection_records_memory_image_id",
        "volatility_injection_records",
        ["memory_image_id"],
    )
    op.create_index(
        "ix_volatility_injection_records_hexdump_sha256",
        "volatility_injection_records",
        ["hexdump_sha256"],
    )

    # ── firmware.windows_injection_walk_* state-machine columns ────────
    op.add_column(
        "firmware",
        sa.Column(
            "windows_injection_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_injection_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_injection_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_injection_walk_error", sa.Text, nullable=True
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "windows_injection_walk_result", JSONB, nullable=True
        ),
    )
    op.create_check_constraint(
        "ck_firmware_windows_injection_walk_status",
        "firmware",
        "windows_injection_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_windows_injection_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "windows_injection_walk_result")
    op.drop_column("firmware", "windows_injection_walk_error")
    op.drop_column("firmware", "windows_injection_walk_finished_at")
    op.drop_column("firmware", "windows_injection_walk_started_at")
    op.drop_column("firmware", "windows_injection_walk_status")

    op.drop_index(
        "ix_volatility_injection_records_hexdump_sha256",
        table_name="volatility_injection_records",
    )
    op.drop_index(
        "ix_volatility_injection_records_memory_image_id",
        table_name="volatility_injection_records",
    )
    op.drop_index(
        "ix_volatility_injection_records_firmware_pid",
        table_name="volatility_injection_records",
    )
    op.drop_index(
        "ix_volatility_injection_records_firmware_kind",
        table_name="volatility_injection_records",
    )
    op.drop_constraint(
        "ck_volatility_injection_records_detection_kind",
        "volatility_injection_records",
        type_="check",
    )
    op.drop_table("volatility_injection_records")
