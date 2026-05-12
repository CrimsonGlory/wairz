"""add windows_wmi_events table (Phase θ.B.B)

Revision ID: 4c7d5e6f8b1a
Revises: 3b6c4d5e6f7a
Create Date: 2026-05-12 04:00:00.000000

Phase θ.B.B — adds the per-binding landing zone for the Phase θ.B
Windows Management Instrumentation (WMI) persistence walker (θ.B.D).
WMI repository OBJECTS.DATA files extracted from firmware captures
(typically under ``Windows/System32/wbem/Repository/``) are walked
via the vendored PyWMIPersistenceFinder (Phase θ.B.A — keyword-search
regex parser, MIT-licensed fork) to surface every
``__FilterToConsumerBinding`` triple. Each binding becomes one row in
this table.

Surfaces per-WMI-binding forensic-triage metadata:

- **Source identifiers** (source_path + namespace) — source_path is
  the relative path within the detection root (Rule #16) to the
  OBJECTS.DATA file the binding was parsed from. namespace is
  typically NULL on vendor-derived rows (the keyword-search parser
  doesn't reliably extract namespace from raw bytes; future work:
  cross-reference INDEX.BTR for the binding's namespace mapping).
- **Binding triple** (binding_id + filter_name + filter_query +
  consumer_name + consumer_type) — the FilterToConsumerBinding's
  canonical fields. binding_id = "<consumer_name>-<filter_name>"
  matches the vendored PyWMIPersistenceFinder's identifier shape.
- **consumer_payload JSONB** — the attacker-controlled
  CommandLineTemplate / ScriptText / FileName + WriteString payload,
  surfaced verbatim as DATA for operator review. Canonical shape:
  ``[{"consumer_type": str, "arguments": str, "other": str,
      "schema_version": 1}]``.
- **anomaly_flags JSONB** — heuristic detection summary for the
  θ.B.E classifier. Canonical shape ``{"encoded_powershell": bool,
  "script_host_invocation": bool, "active_script_consumer": bool,
  "non_benign_binding": bool, "high_severity": bool,
  "schema_version": 1}``.
- **fingerprint_sha256** — SHA256 of the canonical
  (binding_id, filter_query, first consumer arguments) tuple for
  cross-firmware aggregation via the ``lookup_wmi_persistence`` MCP
  tool.
- **probably_benign** — vendored well-known-binding annotation
  (BVTConsumer-BVTFilter, SCM Event Log Consumer-SCM Event Log
  Filter). The MCP layer surfaces these but with reduced priority;
  the finding emit hook skips benign bindings entirely.

Per CLAUDE.md Rule #16: the θ.B.D walker uses
``get_detection_roots(firmware)`` (NOT ``firmware.extracted_path``
alone) so multi-archive / scatter-zip firmware extracts surface
every OBJECTS.DATA candidate.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only. The walker treats OBJECTS.DATA as untrusted text input via
the vendored PyWMIPersistenceFinder (regex-only parser; zero
process-spawn primitives). The consumer_payload JSONB carries
attacker-controlled CommandLineTemplate / ScriptText / FileName /
WriteString verbatim from the repository for operator review; NO
code path in wairz invokes wscript / cscript / powershell / mshta /
WmiPrvSE / wmiexec against the persisted payloads. The test gate
``tests/test_wmi_walker.py::test_wmi_no_script_execution`` asserts
this discipline programmatically (negative test: the spawn-grep
across the walker module yields zero matches).

Per CLAUDE.md Rule #35c JSONB discipline: both JSONB columns
(``consumer_payload`` and ``anomaly_flags``) get dedicated normaliser
+ schema_version stamp helpers in
``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``4c7d5e6f8b1a``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from θ.A.D head ``3b6c4d5e6f7a``.

Indexes:

- ``ix_windows_wmi_events_firmware`` — ``(firmware_id,)`` covers
  "all WMI bindings for firmware Y" canonical triage.
- ``ix_windows_wmi_events_firmware_binding`` — ``(firmware_id,
  binding_id)`` covers "show me the FooConsumer-BarFilter binding"
  natural lookup.
- ``ix_windows_wmi_events_fingerprint`` — ``(fingerprint_sha256,)``
  covers the cross-firmware aggregation in lookup_wmi_persistence
  MCP tool.
- ``ix_windows_wmi_events_firmware_benign`` — ``(firmware_id,
  probably_benign)`` covers the anomaly-focused MCP search filter.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "4c7d5e6f8b1a"
down_revision: str | None = "3b6c4d5e6f7a"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_wmi_events",
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
        # Relative path to the OBJECTS.DATA file within the
        # detection root.
        sa.Column("source_path", sa.String(2048), nullable=False),
        # WMI namespace (typically NULL on vendor-derived rows).
        sa.Column("namespace", sa.String(256), nullable=True),
        # Synthesized "consumer_name-filter_name" identifier.
        sa.Column("binding_id", sa.String(512), nullable=False),
        # __EventFilter.Name field.
        sa.Column("filter_name", sa.String(512), nullable=False),
        # WQL SELECT statement (filter trigger condition).
        sa.Column("filter_query", sa.String(4096), nullable=True),
        # EventConsumer.Name field.
        sa.Column("consumer_name", sa.String(512), nullable=False),
        # EventConsumer type discriminator (CommandLine / ActiveScript
        # / LogFile / NTEventLog / SMTP / Other).
        sa.Column("consumer_type", sa.String(64), nullable=False),
        # Attacker-controlled payload roster (DATA only; never
        # executed per Rule #36).
        sa.Column("consumer_payload", JSONB, nullable=True),
        # Heuristic detection summary (JSONB dict-shape).
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # SHA256 of (binding_id, filter_query, first consumer args)
        # for cross-firmware aggregation.
        sa.Column("fingerprint_sha256", sa.String(64), nullable=True),
        # Well-known-binding annotation from vendored
        # PyWMIPersistenceFinder.
        sa.Column(
            "probably_benign",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_windows_wmi_events_firmware",
        "windows_wmi_events",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_wmi_events_firmware_binding",
        "windows_wmi_events",
        ["firmware_id", "binding_id"],
    )
    op.create_index(
        "ix_windows_wmi_events_fingerprint",
        "windows_wmi_events",
        ["fingerprint_sha256"],
    )
    op.create_index(
        "ix_windows_wmi_events_firmware_benign",
        "windows_wmi_events",
        ["firmware_id", "probably_benign"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_wmi_events_firmware_benign",
        table_name="windows_wmi_events",
    )
    op.drop_index(
        "ix_windows_wmi_events_fingerprint",
        table_name="windows_wmi_events",
    )
    op.drop_index(
        "ix_windows_wmi_events_firmware_binding",
        table_name="windows_wmi_events",
    )
    op.drop_index(
        "ix_windows_wmi_events_firmware",
        table_name="windows_wmi_events",
    )
    op.drop_table("windows_wmi_events")
