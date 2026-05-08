"""extend findings.source CHECK with windows_registry_persistence + windows_inf + windows_driver_imports

Revision ID: c9d0e1f2a3b4
Revises: c8d9e0f1a2b3
Create Date: 2026-05-09

Phase γ.7 — extends ``ck_findings_source`` with three new source values
so Phase γ.4 (registry hive walks) and Phase γ.5 (driver INF / CAT
extraction) can emit ``Finding`` rows the operator can triage alongside
the existing CVE / SBOM / kernel / authenticode findings:

- ``windows_registry_persistence`` — emitted by Phase γ.8 classifier
  when the registry walker surfaces a persistence-relevant subkey
  (Run / RunOnce / RunServices, AppInit_DLLs, Image File Execution
  Options, Winlogon ShellExecuteHooks, Session Manager BootExecute,
  Active Setup Installed Components, CurrentControlSet\\Services).
  Severity tier varies by subkey (Run / RunOnce → medium; IFEO image
  file execution options → high; Session Manager BootExecute →
  critical) per Persona-E #13.
- ``windows_inf`` — emitted when the driver INF parser surfaces a
  notable-but-not-imports-related signal (unsigned CAT, no CAT,
  attestation-with-no-MS-anchor, multi-mfg INFs that may need
  manual verification).
- ``windows_driver_imports`` — emitted when scan_inf_imports surfaces
  an unusual PnP hardware ID set (kernel-mode drivers for unfamiliar
  hardware that warrant manual review). Persona-E #13 driver-matrix
  workflow.

Live audit at migration-authoring time (2026-05-09, before this
migration applies):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_registry_persistence / windows_inf /
    -- windows_driver_imports (the γ.8 classifier doesn't exist yet)

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill
needed. The Pydantic ``WindowsFindingSource`` Literal extension lands
in the same Phase γ.7 commit (cross-stack alignment per Rule #25
single-slice exception #2). γ.8 emit-from-walk service method follows
the β.12c precedent shape.

Mirrors ``c5b6a7d8e9f0_extend_findings_source_windows_verdicts.py``
(the most recent recreator of ``ck_findings_source``) — same
drop-and-recreate shape with the extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via ``importlib`` and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 exception #2:
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains the
  three values.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets matching entries per CLAUDE.md Rule #9 exhaustivity.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "c8d9e0f1a2b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Allowlist tuple — exposed under ``_NEW_SOURCE_VALUES`` so the
# cross-stack alignment test can importlib-load the latest recreator
# and assert agreement with the frontend FindingSource union.
_NEW_SOURCE_VALUES: tuple[str, ...] = (
    "manual",
    "security_audit",
    "yara_scan",
    "attack_surface",
    "sbom_scan",
    "hardware_firmware_graph",
    "apk-manifest-scan",
    "apk-bytecode-scan",
    "apk-mobsfscan",
    "cwe_checker",
    "uefi_scan",
    "clamav_scan",
    "vt_scan",
    "abusech_scan",
    "fuzzing",
    "unpack_audit",
    "security_review",
    "ai_discovered",
    # Phase β.12a additions:
    "windows_authenticode",
    "windows_dbx_revoked",
    # Phase γ.7 additions:
    "windows_registry_persistence",
    "windows_inf",
    "windows_driver_imports",
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", _NEW_SOURCE_VALUES),
    )


def downgrade() -> None:
    # Defensive: if any rows were tagged with the new sources between
    # upgrade and downgrade (γ.8 classifier emitted findings), remap
    # them to 'manual' so the prior CHECK accepts the row. Same shape
    # as c5b6a7d8e9f0's downgrade.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ("
        "'windows_registry_persistence', "
        "'windows_inf', "
        "'windows_driver_imports')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES
        if v not in (
            "windows_registry_persistence",
            "windows_inf",
            "windows_driver_imports",
        )
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
