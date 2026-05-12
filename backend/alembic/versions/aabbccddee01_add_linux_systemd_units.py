"""add linux_systemd_units table (Phase ι.B.A — SECOND LINUX WALKER)

Revision ID: aabbccddee01
Revises: fb4c5d6e7f8a
Create Date: 2026-05-12 16:30:00.000000

Phase ι.B.A — adds the per-unit landing zone for the SECOND LINUX
walker in wairz's portfolio. The Phase ι.B.C walker parses systemd
unit-file (``.service`` / ``.timer`` / ``.socket`` / ``.target`` /
``.path`` / ``.mount`` / ``.swap``) INI text files extracted from
Linux firmware captures (typically under ``etc/systemd/system/*`` /
``usr/lib/systemd/system/*`` / ``lib/systemd/system/*`` /
``run/systemd/system/*`` / ``etc/systemd/user/*`` paths per Rule #16)
via Python's stdlib ``configparser`` (NO new dependency — Rule #19
evidence-first probe ran 2026-05-12T15:20Z: systemd unit files are
INI text, and stdlib configparser handles them with two small
defensive extensions for systemd's deliberate-non-strict-INI quirks).

Surfaces per-unit forensic-triage metadata:

- **Path identity** (unit_path + unit_type + unit_name) — absolute
  path inside the firmware extract, unit-type extension, and basename.
- **Operator label** (description) — [Unit] Description= value.
- **Execution surface** (exec_start + exec_start_pre + exec_stop +
  user + working_directory) — [Service] commands + UID context. The
  anomaly classifier flags T1543.002 systemd-service-from-writable
  (suspicious_path) and obfuscated/encoded ExecStart commands
  (obfuscated_exec).
- **Dependency graph** (wanted_by + required_by + requires + after +
  before, all JSONB list[str]) — [Install] + [Unit] graph linkage.
  The anomaly classifier flags root services with minimal Requires=
  (root_minimal_deps) and WantedBy targets outside the standard set
  (enabled_outside_standard).
- **Boot-time-active flag** (enabled) — true iff at least one
  enabled-symlink exists under a *.wants/ or *.requires/ directory
  pointing to this unit.
- **Trigger payload** (triggers JSONB dict) — [Timer] OnCalendar / etc.
- **Socket payload** (socket_listen JSONB dict) — [Socket] ListenStream
  / etc. The anomaly classifier flags unusual ports (socket_unusual_port).
- **anomaly_flags JSONB** — heuristic detection summary for the ι.B.D
  classifier. Canonical shape:
  ``{"suspicious_path": bool, "suspicious_unit_name": bool,
  "socket_unusual_port": bool, "root_minimal_deps": bool,
  "disabled_but_present": bool, "enabled_outside_standard": bool,
  "obfuscated_exec": bool, "schema_version": 1}``.
- **unit_raw Text** — full INI content truncated to ~8K at the walker
  boundary, for operator review.

Real-world adversaries using this exact tradecraft (Phase ι Scout 2
Persona-E refresh):

- APT36 Transparent Tribe (Aug 2025) — ``.service`` units staged in
  ``/etc/systemd/system/`` referencing payload binaries under
  ``/tmp/`` or ``/var/tmp/``.
- FIRESTARTER (CISA/NCSC 2026) — Russian APT toolkit with multi-stage
  systemd-unit + drop-in override persistence chain.
- Quasar Linux QLNX (May 2026) — 7-mechanism persistence kit
  including ``.service`` units, ``.timer`` units, drop-in overrides,
  and enabled-symlink hijacks.

Per CLAUDE.md Rule #16: the ι.B.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Linux firmware (squashfs / ext / cramfs /
erofs / tar.xz) surfaces every unit file candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses unit-file INI text via configparser as
untrusted input; nothing in wairz invokes any embedded
``ExecStart=``/``ExecStartPre=``/``ExecStop=`` command, mounts any
referenced path, or links any unit into a running systemd. The
exec_start / working_directory / user fields are surfaced for
operator review only.

Per CLAUDE.md Rule #35c JSONB discipline: each JSONB column gets a
dedicated normalizer + schema_version stamp helper in
``app.services.jsonb_normalizers`` (8 helpers for this table:
wanted_by / required_by / requires / after / before / triggers /
socket_listen / anomaly_flags).

Per CLAUDE.md Rule #19 evidence-first: revision ID ``aabbccddee01``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from ι.A.D head ``fb4c5d6e7f8a``.

Indexes:

- ``ix_linux_systemd_units_firmware_type`` — ``(firmware_id,
  unit_type)`` covers "all timer units for firmware Y" / "all service
  units for firmware Y" canonical service-vs-timer-split query.
- ``ix_linux_systemd_units_firmware_name`` — ``(firmware_id,
  unit_name)`` covers per-firmware basename lookup AND backs the ι.B.E
  ``lookup_systemd_unit_across_firmwares`` cross-firmware aggregation
  query.
- ``ix_linux_systemd_units_firmware_enabled`` — ``(firmware_id,
  enabled)`` covers "all boot-time-active units for firmware Y" —
  the primary persistence-investigation shape.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "aabbccddee01"
down_revision: str | None = "fb4c5d6e7f8a"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "linux_systemd_units",
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
        # Path identity.
        sa.Column("unit_path", sa.String(1024), nullable=False),
        sa.Column("unit_type", sa.String(32), nullable=False),
        sa.Column("unit_name", sa.String(255), nullable=False),
        # Operator label.
        sa.Column("description", sa.String(512), nullable=True),
        # Execution surface.
        sa.Column("exec_start", sa.String(2048), nullable=True),
        sa.Column("exec_start_pre", sa.String(2048), nullable=True),
        sa.Column("exec_stop", sa.String(2048), nullable=True),
        sa.Column("user", sa.String(64), nullable=True),
        sa.Column("working_directory", sa.String(1024), nullable=True),
        # Dependency graph (JSONB list[str]).
        sa.Column("wanted_by", JSONB, nullable=True),
        sa.Column("required_by", JSONB, nullable=True),
        sa.Column("requires", JSONB, nullable=True),
        sa.Column("after", JSONB, nullable=True),
        sa.Column("before", JSONB, nullable=True),
        # Boot-time-active flag.
        sa.Column(
            "enabled", sa.Boolean, nullable=False, server_default=sa.false()
        ),
        # Trigger / socket payloads (JSONB dict).
        sa.Column("triggers", JSONB, nullable=True),
        sa.Column("socket_listen", JSONB, nullable=True),
        # Anomaly aggregate.
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # Raw INI content.
        sa.Column("unit_raw", sa.Text, nullable=True),
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
        "ix_linux_systemd_units_firmware_type",
        "linux_systemd_units",
        ["firmware_id", "unit_type"],
    )
    op.create_index(
        "ix_linux_systemd_units_firmware_name",
        "linux_systemd_units",
        ["firmware_id", "unit_name"],
    )
    op.create_index(
        "ix_linux_systemd_units_firmware_enabled",
        "linux_systemd_units",
        ["firmware_id", "enabled"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_linux_systemd_units_firmware_enabled",
        table_name="linux_systemd_units",
    )
    op.drop_index(
        "ix_linux_systemd_units_firmware_name",
        table_name="linux_systemd_units",
    )
    op.drop_index(
        "ix_linux_systemd_units_firmware_type",
        table_name="linux_systemd_units",
    )
    op.drop_table("linux_systemd_units")
