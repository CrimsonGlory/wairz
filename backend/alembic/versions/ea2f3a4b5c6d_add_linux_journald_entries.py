"""add linux_journald_entries table (Phase ι.A.A — FIRST LINUX WALKER)

Revision ID: ea2f3a4b5c6d
Revises: cd1e2f3a4b5c
Create Date: 2026-05-12 15:00:00.000000

Phase ι.A.A — adds the per-entry landing zone for the FIRST LINUX
walker in wairz's portfolio (Phases η + θ shipped 10 Windows-only
walkers). The Phase ι.A.C walker parses ``.journal`` binary log files
extracted from Linux firmware captures (typically at
``var/log/journal/<machine-id>/system.journal`` and
``run/log/journal/<machine-id>/*.journal`` paths under detection
roots per Rule #16) via a clean-room parser implementing the upstream
systemd/sd-journal binary format (no third-party Python package
matches — Rule #19 evidence-first probe ran 2026-05-12T14:50Z:
``pip show dissect.journal`` returned package-not-found,
``curl pypi.org/pypi/dissect.journal/json`` returned 404,
``kaitaistruct`` is available but the Kaitai-generated parser is
~500 LOC of vendor-in code; clean-room over the public
``journal-def.h`` reference is the smaller and equally
maintainable path).

Surfaces per-journal-entry forensic-triage metadata:

- **Source identifiers** (machine_id + boot_id) — 32-char hex strings
  identifying the producing system + boot cycle. From the .journal
  header / entry fields.
- **Timing** (realtime_timestamp_us + monotonic_timestamp_us) —
  microseconds since epoch + microseconds since boot. Native journald
  precision.
- **Syslog classifiers** (priority + facility + transport) — priority
  0-7, facility 0-23, transport ``kernel`` / ``journal`` / ``audit``
  / ``stdout`` / etc.
- **Systemd context** (unit) — _SYSTEMD_UNIT field. NULL for bare
  kernel messages. Anomaly: unit paths under /tmp/, /dev/shm/,
  /var/tmp/ flag T1543.002 systemd-service-from-writable persistence.
- **Process identity** (pid + uid + gid + comm + exe_path + cmdline)
  — full process identification, NULL for kernel-transport entries.
  cmdline truncated to ~4096 chars at the walker boundary.
- **Host context** (hostname) — _HOSTNAME at emission time.
- **Message** — log body, truncated to ~8192 chars at the walker
  boundary so MCP tool outputs stay below 30 KB.
- **anomaly_flags JSONB** — heuristic detection summary for the
  ι.A.D classifier. Canonical shape:
  ``{"priority_critical": bool, "oom_killer": bool, "audit_failure":
  bool, "selinux_denied": bool, "segfault": bool, "suspicious_unit":
  bool, "log_clear_marker": bool, "schema_version": 1}``.

Per CLAUDE.md Rule #16: the ι.A.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-rootfs Linux firmware (squashfs / ext / cramfs /
erofs) surfaces every journal file candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker parses ``.journal`` binary content as untrusted
input via a clean-room pure-Python parser; nothing in wairz invokes
``journalctl`` / ``systemd-cat`` against the parsed entries or
replays embedded EXEC fields. The cmdline / exe_path / unit fields
are surfaced for operator review.

Per CLAUDE.md Rule #35c JSONB discipline: the JSONB column
(``anomaly_flags``) gets a dedicated normalizer + schema_version
stamp helper in ``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``ea2f3a4b5c6d``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from θ.D.E head ``cd1e2f3a4b5c``.

Indexes:

- ``ix_linux_journald_entries_firmware_time`` — ``(firmware_id,
  realtime_timestamp_us)`` covers "all journald entries for firmware
  Y, ordered by time" timeline query.
- ``ix_linux_journald_entries_firmware_unit`` — ``(firmware_id,
  unit)`` covers "all entries for firmware Y for a given systemd
  unit" T1543.002 persistence-investigation query.
- ``ix_linux_journald_entries_firmware_priority`` — ``(firmware_id,
  priority)`` covers "all high-priority entries for firmware Y"
  emergency-scan query.
- ``ix_linux_journald_entries_firmware_transport`` — ``(firmware_id,
  transport)`` covers "all audit-transport entries for firmware Y"
  T1562.012 audit-system-tampering query.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ea2f3a4b5c6d"
down_revision: str | None = "cd1e2f3a4b5c"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "linux_journald_entries",
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
        # Relative path to the .journal file within the detection root.
        sa.Column("journal_file_path", sa.String(2048), nullable=False),
        # Machine ID / boot ID (32-char hex strings).
        sa.Column("machine_id", sa.String(32), nullable=True),
        sa.Column("boot_id", sa.String(32), nullable=True),
        # Timing (usec since epoch / boot).
        sa.Column("realtime_timestamp_us", sa.BigInteger, nullable=False),
        sa.Column("monotonic_timestamp_us", sa.BigInteger, nullable=True),
        # Syslog classifiers.
        sa.Column("priority", sa.SmallInteger, nullable=False),
        sa.Column("facility", sa.SmallInteger, nullable=True),
        sa.Column("transport", sa.String(32), nullable=False),
        # Systemd context.
        sa.Column("unit", sa.String(255), nullable=True),
        # Process identity.
        sa.Column("pid", sa.Integer, nullable=True),
        sa.Column("uid", sa.Integer, nullable=True),
        sa.Column("gid", sa.Integer, nullable=True),
        sa.Column("comm", sa.String(255), nullable=True),
        sa.Column("exe_path", sa.String(1024), nullable=True),
        sa.Column("cmdline", sa.Text, nullable=True),
        # Host context.
        sa.Column("hostname", sa.String(255), nullable=True),
        # Message body (~8192 chars max at boundary).
        sa.Column("message", sa.Text, nullable=False),
        # Anomaly flag aggregate (JSONB dict-shape).
        sa.Column("anomaly_flags", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_linux_journald_entries_firmware_time",
        "linux_journald_entries",
        ["firmware_id", "realtime_timestamp_us"],
    )
    op.create_index(
        "ix_linux_journald_entries_firmware_unit",
        "linux_journald_entries",
        ["firmware_id", "unit"],
    )
    op.create_index(
        "ix_linux_journald_entries_firmware_priority",
        "linux_journald_entries",
        ["firmware_id", "priority"],
    )
    op.create_index(
        "ix_linux_journald_entries_firmware_transport",
        "linux_journald_entries",
        ["firmware_id", "transport"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_linux_journald_entries_firmware_transport",
        table_name="linux_journald_entries",
    )
    op.drop_index(
        "ix_linux_journald_entries_firmware_priority",
        table_name="linux_journald_entries",
    )
    op.drop_index(
        "ix_linux_journald_entries_firmware_unit",
        table_name="linux_journald_entries",
    )
    op.drop_index(
        "ix_linux_journald_entries_firmware_time",
        table_name="linux_journald_entries",
    )
    op.drop_table("linux_journald_entries")
