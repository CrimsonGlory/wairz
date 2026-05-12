"""add efs_walk_* columns to firmware (Phase ι.D.B — SECOND ι WINDOWS-SIDE)

Revision ID: aabbccddee08
Revises: aabbccddee07
Create Date: 2026-05-12 20:00:00.000000

Adds five columns to the ``firmware`` table for the Phase ι.D Windows
EFS DDF/DRF metadata walker 202+polling refactor (CLAUDE.md Rule #33
contract). SECOND ι Windows-side walker (ι.A + ι.B shipped Linux —
journald + systemd; ι.C shipped FIRST ι Windows — ETW). Mirrors the
etl_walk_status / systemd_walk_status / journald_walk_status patterns
already on the table.

Phase ι.D.C background runner ``run_efs_walk_background`` walks each
detection root per Rule #16 (NOT ``firmware.extracted_path`` alone),
locates raw NTFS image candidates (reuses η.A's ``walk_raw_ntfs_images``
plumbing), opens each via ``dissect.ntfs.NTFS``, iterates the MFT for
files with ``FILE_ATTRIBUTE_ENCRYPTED`` (0x4000) set on
$STANDARD_INFORMATION, reads the file's $EFS LOGGED_UTILITY_STREAM
attribute (type 0x100), parses the DDF (Data Decryption Field) + DRF
(Data Recovery Field) entries, persists per-file rows into
``windows_efs_encrypted_files`` (table from ι.D.A), and stamps an
aggregate JSONB result onto ``efs_walk_result``.

**PARSE-ONLY DISCIPLINE — Rule #36 + Rule #36 EXTENSION.** The walker
captures METADATA ONLY. It NEVER decrypts the RSA-encrypted FEK, NEVER
invokes Windows DPAPI (``CryptUnprotectData``), NEVER attempts plaintext
recovery, NEVER imports cryptographic decryption modules. The "who can
decrypt + who is the recovery agent" surface IS the forensic value
(T1486 ransomware variant, T1564.001 insider stealth, supply-chain
fingerprint).

Per Rule #33 .d (asyncio.create_task vs arq rubric): EFS walks run
entirely in-process (dissect.ntfs + asn1crypto pure-Python parsing; no
Docker spawn, no subprocess), and per-row persistence is the durable
state. ``asyncio.create_task`` is the correct dispatch — same shape as
γ.4 / ε.1.b.3 / ζ.2.B / ζ.3.B / η.B.C / η.C.C / η.A.B / θ.A.B /
θ.B.C / θ.C.B / θ.D.B / θ.E.B / ι.A.B / ι.B.B / ι.C.B.

Columns:

- ``efs_walk_status``: idle / queued / running / completed / failed
- ``efs_walk_started_at``: when the background task picked up
- ``efs_walk_finished_at``: when the run terminated
- ``efs_walk_error``: traceback summary on failure (Text)
- ``efs_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_efs_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the etl_walk_status / systemd_walk_status /
journald_walk_status / bcd_walk_status / wmi_walk_status pattern
(Rule #33 .c).

Revision ID ``aabbccddee08`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
ι.D.A head ``aabbccddee07``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee08"
down_revision = "aabbccddee07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "efs_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "efs_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "efs_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("efs_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("efs_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_efs_walk_status",
        "firmware",
        "efs_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_efs_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "efs_walk_result")
    op.drop_column("firmware", "efs_walk_error")
    op.drop_column("firmware", "efs_walk_finished_at")
    op.drop_column("firmware", "efs_walk_started_at")
    op.drop_column("firmware", "efs_walk_status")
