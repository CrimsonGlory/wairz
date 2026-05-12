"""add windows_sdb_entries table (Phase θ.D.B)

Revision ID: ab1c2d3e4f5a
Revises: cd0e1f2a3b4c
Create Date: 2026-05-12 11:00:00.000000

Phase θ.D.B — adds the per-shim-entry landing zone for the Phase θ.D
Windows Application Compatibility Shim Database (`.sdb`) walker
(θ.D.D). Each shim entry parsed from a `.sdb` file (TAG_SHIM under
a TAG_APP, OR TAG_PATCH) becomes one ``WindowsSdbEntry`` row,
classified by shim_class (RedirectEXE / InjectDll / GetCommandLineW /
RedirectShortcut / Custom / Patch / Other) and the SDB-kind discriminator
(microsoft / custom / unknown).

Closes the θ campaign at 5-of-5 walker streams (θ.A BCD + θ.B WMI +
θ.C ESP + θ.E MBR/VBR + θ.D SDB shim) matching η's precedent.

T1546.011 Application Shimming — adversaries (APT41, FIN7, Carbanak,
various ransomware affiliates) plant custom `.sdb` shims under
``Windows/AppPatch/Custom/<exe>.sdb``. Windows loads the shim on
every launch of the target executable, executing attacker code in
the application's context. Typical attacker primitives surfaced by
this table:

- ``InjectDll`` — DLL injection into target process address space.
- ``RedirectEXE`` — replace executed binary entirely.
- ``GetCommandLineW`` — argument-injection / spoofing.
- ``RedirectShortcut`` — shortcut-target hijack.

Surfaces per-entry forensic-triage metadata:

- **Source identifier** (file_path + file_sha256) — the relative
  path within the detection root (Rule #16) to the `.sdb` file
  plus its SHA256 (cross-firmware identifier).
- **SDB kind** (sdb_kind) — 3-state discriminator: microsoft, custom,
  unknown. DB CHECK constraint enforces the enum. The Literal mirror
  in ``app/schemas/firmware.py`` type-checks at the API boundary.
- **App identifiers** (app_name + app_exe) — TAG_APP_NAME and the
  first TAG_EXE's TAG_NAME of the parent TAG_APP for human-readable
  triage.
- **shim_class** — 7-state discriminator (RedirectEXE / InjectDll /
  GetCommandLineW / RedirectShortcut / Custom / Patch / Other). DB
  CHECK constraint enforces the enum.
- **shim_payload JSONB** — raw shim/patch instructions verbatim (name,
  module, command_line, description, OR for PATCH-class entries the
  TAG_PATCH_BITS hex blob).
- **anomaly_flags JSONB** — θ.D.E classifier inputs (is_custom_path,
  has_inject_dll, has_redirect_exe, has_get_command_line,
  has_redirect_shortcut, has_dll_outside_appdir, has_command_line).
- **fingerprint_sha256** — SHA256 of (file_path_lower + file_sha256
  + shim_class + shim_name) for cross-firmware aggregation in the
  θ.D.F ``lookup_sdb_shim`` MCP tool.

Per CLAUDE.md Rule #16: the θ.D.D walker uses
``get_detection_roots(firmware)`` — multi-archive Windows extractions
surface `.sdb` differently per unpacker (full partition image vs
partial AppPatch directory extract); the multi-root discipline
catches all forms.

Per CLAUDE.md Rule #36 no-execute discipline: this table holds DATA
only. `.sdb` files describe shim instructions Windows loads + executes
via AppHelp / sdbinst infrastructure. The walker parses bytes via the
vendored python_sdb clean-room parser (no execution); wairz NEVER
invokes sdbinst / AppHelp / Mscoree against parsed entries. The test
gate ``tests/test_sdb_walker.py::test_sdb_no_shim_execution`` asserts
this discipline programmatically.

Per CLAUDE.md Rule #35c JSONB discipline: the ``shim_payload`` +
``anomaly_flags`` JSONB columns get dedicated normaliser + schema_version
stamp helpers in ``app.services.jsonb_normalizers``.

Per CLAUDE.md Rule #19 evidence-first: revision ID ``ab1c2d3e4f5a``
pre-validated FREE in the versions tree (grep returned 0 hits)
before authoring. Chains from θ.E.D head ``cd0e1f2a3b4c``.

Indexes:

- ``ix_windows_sdb_entries_firmware`` — ``(firmware_id,)`` covers
  "all SDB entries for firmware Y" canonical triage.
- ``ix_windows_sdb_entries_firmware_sha`` — ``(firmware_id, file_sha256)``
  covers "show me this exact .sdb file's entries" lookup.
- ``ix_windows_sdb_entries_fingerprint`` — ``(fingerprint_sha256,)``
  covers the cross-firmware aggregation in ``lookup_sdb_shim`` MCP tool.
- ``ix_windows_sdb_entries_firmware_kind`` — ``(firmware_id, sdb_kind)``
  covers the anomaly-focused MCP search filter (custom-path shims).

CHECK constraints enforce the 3-state sdb_kind enum AND the 7-state
shim_class enum (Rule #33 .c) — matches the Pydantic Literal mirrors
in ``app/schemas/firmware.py`` for boundary type-checking.
"""
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "ab1c2d3e4f5a"
down_revision: str | None = "cd0e1f2a3b4c"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "windows_sdb_entries",
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
        # Relative path to the `.sdb` file within the detection root.
        sa.Column("file_path", sa.String(2048), nullable=False),
        # SHA256 of the `.sdb` file contents (64 hex chars).
        sa.Column("file_sha256", sa.String(64), nullable=False),
        # SDB kind discriminator (CHECK-enforced 3-state).
        sa.Column("sdb_kind", sa.String(32), nullable=False),
        # App name (TAG_APP_NAME of parent TAG_APP).
        sa.Column("app_name", sa.String(512), nullable=True),
        # App EXE filename (TAG_NAME of first TAG_EXE under TAG_APP).
        sa.Column("app_exe", sa.String(512), nullable=True),
        # Shim class discriminator (CHECK-enforced 7-state).
        sa.Column("shim_class", sa.String(64), nullable=False),
        # Shim payload — JSONB dict-shape.
        sa.Column("shim_payload", JSONB, nullable=True),
        # Anomaly flags — JSONB dict-shape.
        sa.Column("anomaly_flags", JSONB, nullable=True),
        # SHA256 fingerprint of canonical entry tuple for
        # cross-firmware aggregation.
        sa.Column("fingerprint_sha256", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    # CHECK constraint enforcing the 3-state sdb_kind enum per
    # Rule #33 .c. Mirrored by Pydantic Literal in
    # app/schemas/firmware.py.
    op.create_check_constraint(
        "ck_windows_sdb_entries_sdb_kind",
        "windows_sdb_entries",
        "sdb_kind IN ('microsoft', 'custom', 'unknown')",
    )
    # CHECK constraint enforcing the 7-state shim_class enum per
    # Rule #33 .c. Mirrored by Pydantic Literal in
    # app/schemas/firmware.py.
    op.create_check_constraint(
        "ck_windows_sdb_entries_shim_class",
        "windows_sdb_entries",
        "shim_class IN "
        "('RedirectEXE', 'InjectDll', 'GetCommandLineW', "
        "'RedirectShortcut', 'Custom', 'Patch', 'Other')",
    )
    op.create_index(
        "ix_windows_sdb_entries_firmware",
        "windows_sdb_entries",
        ["firmware_id"],
    )
    op.create_index(
        "ix_windows_sdb_entries_firmware_sha",
        "windows_sdb_entries",
        ["firmware_id", "file_sha256"],
    )
    op.create_index(
        "ix_windows_sdb_entries_fingerprint",
        "windows_sdb_entries",
        ["fingerprint_sha256"],
    )
    op.create_index(
        "ix_windows_sdb_entries_firmware_kind",
        "windows_sdb_entries",
        ["firmware_id", "sdb_kind"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_windows_sdb_entries_firmware_kind",
        table_name="windows_sdb_entries",
    )
    op.drop_index(
        "ix_windows_sdb_entries_fingerprint",
        table_name="windows_sdb_entries",
    )
    op.drop_index(
        "ix_windows_sdb_entries_firmware_sha",
        table_name="windows_sdb_entries",
    )
    op.drop_index(
        "ix_windows_sdb_entries_firmware",
        table_name="windows_sdb_entries",
    )
    op.drop_constraint(
        "ck_windows_sdb_entries_shim_class",
        "windows_sdb_entries",
        type_="check",
    )
    op.drop_constraint(
        "ck_windows_sdb_entries_sdb_kind",
        "windows_sdb_entries",
        type_="check",
    )
    op.drop_table("windows_sdb_entries")
