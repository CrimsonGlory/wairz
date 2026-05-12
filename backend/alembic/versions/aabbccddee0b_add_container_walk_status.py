"""add container_walk_* columns to firmware (Phase ι.E.B — THIRD LINUX, FIFTH ι)

Revision ID: aabbccddee0b
Revises: aabbccddee0a
Create Date: 2026-05-12 16:50:00.000000

Adds five columns to the ``firmware`` table for the Phase ι.E Linux
container-runtime artefact walker 202+polling refactor (CLAUDE.md Rule
#33 contract). THIRD LINUX walker (ι.A journald + ι.B systemd were
Linux; ι.C ETW + ι.D EFS were Windows). FIFTH ι walker overall. Mirrors
the etl_walk_status / systemd_walk_status / journald_walk_status /
efs_walk_status patterns already on the table.

Phase ι.E.C background runner ``run_container_walk_background`` walks
each detection root per Rule #16, scans canonical container runtime
locations (Docker / containerd / podman / OCI image-spec / daemon +
runtime configs), parses each JSON via Python's stdlib ``json``,
extracts container forensic METADATA (image_id / mounts / capabilities
/ seccomp profile / network mode / env keys / command / entrypoint),
persists per-artifact rows into ``linux_container_artifacts`` (table
from ι.E.A), and stamps an aggregate JSONB result onto
``container_walk_result``.

**Container forensics persona — T1610 / T1611 / T1612:**

- T1610 (Deploy Container) — adversary deploys a privileged container.
- T1611 (Escape to Host) — host-namespace shares + dangerous
  capabilities + ``/var/run/docker.sock`` mounts.
- T1612 (Build Image on Host) — surfaces via OCI manifest +
  image_repository fields.

**2025 CVE cluster:** 3 runc CVEs (CVE-2025-31133 unsafe symlink mount,
CVE-2025-52565 mishandling /dev/console, CVE-2025-52881 procfs write
redirect) + Docker CVE-2025-9074 (internal API exposure). All exploit
inspectable container-state artefacts wairz now surfaces.

Per Rule #33 .d (asyncio.create_task vs arq rubric): container walks
run entirely in-process (Python stdlib ``json`` parsing; no Docker
spawn, no subprocess), and per-row persistence is the durable state.
``asyncio.create_task`` is the correct dispatch — same shape as γ.4 /
ε.1.b.3 / ζ.2.B / ζ.3.B / η.* / θ.* / ι.A.B / ι.B.B / ι.C.B / ι.D.B.

Per Rule #36 no-execute: walker parses JSON state files only. Nothing
in wairz invokes any extracted container, exec's into one, or pulls
images. Test gate ``test_container_walker_no_execute_no_container_invocation``.

Columns:

- ``container_walk_status``: idle / queued / running / completed / failed
- ``container_walk_started_at``: when the background task picked up
- ``container_walk_finished_at``: when the run terminated
- ``container_walk_error``: traceback summary on failure (Text)
- ``container_walk_result``: JSONB aggregate. Canonical shape lives in
  ``app.services.jsonb_normalizers._normalize_firmware_container_walk_result``;
  schema_version stamped per Rule #35c.

CHECK constraint matches the etl_walk_status / systemd_walk_status /
journald_walk_status / efs_walk_status / bcd_walk_status / wmi_walk_status
pattern (Rule #33 .c).

Revision ID ``aabbccddee0b`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains from
ι.E.A head ``aabbccddee0a``.
"""
from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision = "aabbccddee0b"
down_revision = "aabbccddee0a"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "firmware",
        sa.Column(
            "container_walk_status",
            sa.String(20),
            nullable=False,
            server_default="idle",
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "container_walk_started_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column(
            "container_walk_finished_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "firmware",
        sa.Column("container_walk_error", sa.Text, nullable=True),
    )
    op.add_column(
        "firmware",
        sa.Column("container_walk_result", JSONB, nullable=True),
    )
    op.create_check_constraint(
        "ck_firmware_container_walk_status",
        "firmware",
        "container_walk_status IN "
        "('idle', 'queued', 'running', 'completed', 'failed')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_firmware_container_walk_status",
        "firmware",
        type_="check",
    )
    op.drop_column("firmware", "container_walk_result")
    op.drop_column("firmware", "container_walk_error")
    op.drop_column("firmware", "container_walk_finished_at")
    op.drop_column("firmware", "container_walk_started_at")
    op.drop_column("firmware", "container_walk_status")
