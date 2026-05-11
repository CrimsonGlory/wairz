"""add windows_scheduled_tasks table (Phase η.B.A)

Revision ID: f8a9b0c1d2e3
Revises: e7f8a9b0c1d2
Create Date: 2026-05-11 22:00:00.000000

Phase η.B.A — adds the per-task landing zone for the Scheduled Task
XML walker (η.B.C). Windows Scheduled Tasks live in ``\\Windows\\
System32\\Tasks\\`` as XML files (recursive subdirectory tree), one
file per task, stored ATOMICALLY with the schema namespaced by
``http://schemas.microsoft.com/windows/2004/02/mit/task``.

The Scheduled Tasks XML carries persistence-candidate metadata:

- ``<RegistrationInfo>`` — Author + Date + URI (canonical task path).
- ``<Triggers>`` — CalendarTrigger / LogonTrigger / BootTrigger /
  EventTrigger / TimeTrigger / RegistrationTrigger /
  SessionStateChangeTrigger / IdleTrigger.
- ``<Principals><Principal>`` — UserId/GroupId + RunLevel
  (LeastPrivilege | HighestAvailable — the privilege-escalation
  marker) + LogonType + RequiredPrivileges.
- ``<Actions>`` — Exec (Command + Arguments + WorkingDirectory) or
  ComHandler (ClassId).
- ``<Settings>`` — Enabled + Hidden + DisallowStartIfOnBatteries +
  AllowDemandStart + DisallowStartOnRemoteAppSession + 30+ other flags.

Persistence-finding emit (η.B.D) leverages the parsed data to flag:

- Encoded-PowerShell action shape — Action contains
  ``-EncodedCommand`` / ``FromBase64String`` / ``-enc`` patterns
  (Qakbot pattern) → HIGH confidence.
- RunLevel=HighestAvailable + non-system Author (Author NOT in
  {"Microsoft Corporation", "Microsoft", ""}) → MEDIUM confidence.
- Baseline rows → LOW confidence.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — the walker (``defusedxml.ElementTree.fromstring`` per Decision
D2 from intake) PARSES task XML; nothing in wairz invokes
``schtasks /create`` / ``Register-ScheduledTask`` / Start-Process on
the parsed Command. CustomAction-equivalent execution is forbidden.

Per CLAUDE.md Rule #35c JSONB discipline: ``triggers`` /
``actions`` / ``principal`` / ``settings`` each get a dedicated
normalizer + schema_version stamp in
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #16: the η.B.C walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so scatter-zip / multi-archive Windows extracts surface their
Tasks directories.

Per CLAUDE.md Rule #19 generalised: this migration extends
infrastructure (alembic chain). Pre-validated revision ID
``f8a9b0c1d2e3`` confirmed FREE in the versions tree of size 71
before authoring (grep returned 0 hits).

Indexes:

- ``ix_windows_scheduled_tasks_firmware_registration`` —
  ``(firmware_id, registration_date)`` covers "all tasks for
  firmware Y, newest first" forensic-timeline queries.
- ``ix_windows_scheduled_tasks_firmware_author`` —
  ``(firmware_id, author)`` covers Microsoft vs third-party
  partitioning.
- ``ix_windows_scheduled_tasks_firmware_uri`` —
  ``(firmware_id, task_uri)`` covers direct path lookup of known
  persistence-tasks.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f8a9b0c1d2e3"
down_revision: str | None = "e7f8a9b0c1d2"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_scheduled_tasks",
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
        # Path to the .xml within the detection root (Rule #16). Long
        # — Tasks tree can be 6+ levels deep under Microsoft\Windows\.
        sa.Column("source_path", sa.String(2048), nullable=False),
        # Canonical task path from <RegistrationInfo><URI>. Falls back
        # to source_path-derived value when missing.
        sa.Column("task_uri", sa.String(2048), nullable=True),
        # Task name (file basename, e.g. "WinSAT").
        sa.Column("task_name", sa.String(512), nullable=False),
        # Author from <RegistrationInfo><Author>. NULL when missing.
        # Classifier checks for "Microsoft Corporation" prefix to
        # decide system-vs-third-party MEDIUM confidence emit.
        sa.Column("author", sa.String(512), nullable=True),
        # Task registration date from <RegistrationInfo><Date>.
        # Indexed jointly with firmware_id for forensic-timeline
        # queries.
        sa.Column(
            "registration_date",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # RunLevel from <Principals><Principal><RunLevel>:
        # "LeastPrivilege" (default) or "HighestAvailable"
        # (privilege-escalation marker). NULL when absent.
        sa.Column("run_level", sa.String(64), nullable=True),
        # Resolved RunAs identifier. Common values: ``S-1-5-18``
        # (LocalSystem), ``S-1-5-19`` (LocalService),
        # ``S-1-5-20`` (NetworkService), or ``\\<HOSTNAME>\<USER>``.
        sa.Column("run_as_user", sa.String(512), nullable=True),
        # Per-task JSONB columns (each with its own normalizer +
        # schema_version stamp per Rule #35c).
        sa.Column("triggers", JSONB, nullable=True),
        sa.Column("actions", JSONB, nullable=True),
        sa.Column("principal", JSONB, nullable=True),
        sa.Column("settings", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_scheduled_tasks_firmware_registration",
        "windows_scheduled_tasks",
        ["firmware_id", "registration_date"],
    )
    op.create_index(
        "ix_windows_scheduled_tasks_firmware_author",
        "windows_scheduled_tasks",
        ["firmware_id", "author"],
    )
    op.create_index(
        "ix_windows_scheduled_tasks_firmware_uri",
        "windows_scheduled_tasks",
        ["firmware_id", "task_uri"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_scheduled_tasks_firmware_uri",
        table_name="windows_scheduled_tasks",
    )
    op.drop_index(
        "ix_windows_scheduled_tasks_firmware_author",
        table_name="windows_scheduled_tasks",
    )
    op.drop_index(
        "ix_windows_scheduled_tasks_firmware_registration",
        table_name="windows_scheduled_tasks",
    )
    op.drop_table("windows_scheduled_tasks")
