"""add windows_srum_records table (Phase ζ.3.A)

Revision ID: c5d6e7f8a9b0
Revises: b3c4d5e6f7a8
Create Date: 2026-05-10 16:00:00.000000

Phase ζ.3.A — adds the per-record landing zone for the SRUM
(System Resource Usage Monitor) walker (ζ.3.B). SRUM stores
~30-60 days of per-application + per-user resource usage in
``%SystemRoot%\\System32\\sru\\SRUDB.dat`` (an ESEDB file).

The SRUM database carries multiple tables identified by GUID:

- ``{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}`` — Application Resource
  Usage (per-app CPU + I/O bytes by user).
- ``{973F5D5C-1D90-4944-BE8E-24B94231A174}`` — Network Data Usage
  (per-app + per-user bytes sent/received per interface).
- ``{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}`` — Network Connectivity
  (per-app connection times per interface).
- ``{DD6636C4-8929-4683-974E-22C046A43763}`` — Push Notifications
  (per-app push counter).
- ``{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}`` — Energy Usage (per-app
  battery drain estimate).
- ``SruDbIdMapTable`` — string→ID map; the GUID-named tables store
  app/user identifiers as integers that must be resolved through
  this table.

Single-table strategy: all five GUID tables collapse to one
``windows_srum_records`` row per source-row, distinguished by a
``record_type`` discriminator column. Rationale:
- Schema simplicity — one DDL change per future ζ.X SRUM extension
  (the fields are largely fungible: app_id + user_id + timestamp +
  metric_value(s) + interface).
- Indexing efficiency — composite (firmware_id, record_type,
  recorded_at DESC) covers all common operator queries
  (forensic-timeline, "all network usage for app X", time-window
  filters across record types).
- Future per-record-type fields land in the ``extra_metadata`` JSONB
  (Rule #35c stamped) rather than forcing N table-extension
  migrations.

Common columns (always populated):
- record_type — discriminator (network_data_usage,
  network_connectivity, application_resource_usage, push_notification,
  energy_usage).
- app_identifier — resolved app_id → app name string (resolved via
  SruDbIdMapTable at walker time).
- user_identifier — resolved user_id → SID/username string.
- recorded_at — Windows FILETIME → datetime; the source row's
  TimeStamp field.

Per-record-type metric columns (nullable; only populated when the
discriminator matches):
- bytes_sent / bytes_received (network_data_usage).
- interface_luid (network_data_usage / network_connectivity).
- duration_seconds (network_connectivity).
- cpu_foreground_seconds / cpu_background_seconds
  (application_resource_usage).
- bytes_read / bytes_written (application_resource_usage).
- push_count (push_notification).
- energy_charge / energy_capacity (energy_usage).

Indexes:
- ``ix_windows_srum_records_firmware_type_time`` —
  ``(firmware_id, record_type, recorded_at DESC)`` covers "all rows of
  type X for firmware Y, newest first".
- ``ix_windows_srum_records_firmware_app`` —
  ``(firmware_id, app_identifier)`` covers "all rows for app
  chrome.exe across types".

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only — SRUM is parsed by libesedb-python (read-only mmap-style ESEDB
binding); nothing in wairz invokes esedbutil / Get-CimInstance
SRUMState / scriptable replay.

Per CLAUDE.md Rule #19 generalised: this migration extends infrastructure
(alembic chain). Rule #8 extended rebuild runs after the cut-over.
Pre-validated revision ID ``c5d6e7f8a9b0`` confirmed FREE in the
versions tree of size 68 (grep returned 0 hits).
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "c5d6e7f8a9b0"
down_revision: str | None = "b3c4d5e6f7a8"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_srum_records",
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
        # Discriminator — which SRUM table this row came from.
        # Tightened by a CHECK constraint to the canonical 5 values.
        sa.Column("record_type", sa.String(64), nullable=False),
        # Path to the SRUDB.dat within the detection root that
        # contained it (Rule #16 detection_roots discipline).
        sa.Column("source_path", sa.String(1024), nullable=False),
        # Resolved app identifier (SruDbIdMapTable lookup at walker time).
        # Falls back to "id:N" when the lookup fails. Indexed.
        sa.Column("app_identifier", sa.String(512), nullable=True),
        # Resolved user identifier (SID or username). Falls back to
        # "id:N" when the lookup fails.
        sa.Column("user_identifier", sa.String(256), nullable=True),
        # SRUM TimeStamp field. Authoritative timestamp for forensic-
        # timeline queries. Indexed jointly with firmware_id + type.
        sa.Column(
            "recorded_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        # Per-record-type metric columns (nullable; only populated when
        # the discriminator matches).
        sa.Column("bytes_sent", sa.BigInteger(), nullable=True),
        sa.Column("bytes_received", sa.BigInteger(), nullable=True),
        sa.Column("bytes_read", sa.BigInteger(), nullable=True),
        sa.Column("bytes_written", sa.BigInteger(), nullable=True),
        sa.Column("interface_luid", sa.BigInteger(), nullable=True),
        sa.Column("duration_seconds", sa.Integer(), nullable=True),
        sa.Column(
            "cpu_foreground_seconds", sa.Integer(), nullable=True
        ),
        sa.Column(
            "cpu_background_seconds", sa.Integer(), nullable=True
        ),
        sa.Column("push_count", sa.Integer(), nullable=True),
        sa.Column("energy_charge", sa.Integer(), nullable=True),
        sa.Column("energy_capacity", sa.Integer(), nullable=True),
        # Type-specific overflow + future-proofing — any field the
        # five GUID-tables carry that didn't fit a typed column lands
        # here. Rule #35c stamped envelope.
        sa.Column("extra_metadata", JSONB, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_windows_srum_records_record_type",
        "windows_srum_records",
        "record_type IN ("
        "'network_data_usage', "
        "'network_connectivity', "
        "'application_resource_usage', "
        "'push_notification', "
        "'energy_usage'"
        ")",
    )
    op.create_index(
        "ix_windows_srum_records_firmware_type_time",
        "windows_srum_records",
        ["firmware_id", "record_type", "recorded_at"],
    )
    op.create_index(
        "ix_windows_srum_records_firmware_app",
        "windows_srum_records",
        ["firmware_id", "app_identifier"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_srum_records_firmware_app",
        table_name="windows_srum_records",
    )
    op.drop_index(
        "ix_windows_srum_records_firmware_type_time",
        table_name="windows_srum_records",
    )
    op.drop_constraint(
        "ck_windows_srum_records_record_type",
        "windows_srum_records",
        type_="check",
    )
    op.drop_table("windows_srum_records")
