"""extend findings.source CHECK with windows_r2r_stomp + windows_il_capa

Revision ID: d5a6b7c8d9e0
Revises: d4a5b6c7d8e9
Create Date: 2026-05-09 19:00:00.000000

Phase δ.8 — extends ``ck_findings_source`` with two new source values
so Phase δ.6 (R2R-stomping detection) and the future capa-on-IL emitter
can persist ``Finding`` rows the operator can triage alongside the
existing CVE / SBOM / kernel / authenticode / registry / driver findings:

- ``windows_r2r_stomp`` — emitted by the δ.6 R2R-stomping classifier
  when a .NET PE has a ReadyToRun native code section + IL/native
  divergence (Tier 1 LOW for review-candidate; Tier 2 MEDIUM for
  capa/IL divergence; Tier 3/4 reserved for deeper detection).
  Persona-E #5 — single highest-impact differentiator.
- ``windows_il_capa`` — capa-on-IL capability hits (e.g. "encrypted
  with AES" / "creates network socket" / "anti-debug technique") that
  surface as Findings when the IL prologue carries a high-confidence
  capa rule match. Used by R2R-stomp Tier 2 + as a standalone
  capability badge for .NET assemblies.

Live audit at migration-authoring time (2026-05-09, before this
migration applies):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_r2r_stomp / windows_il_capa (the δ.6
    -- classifier is service-only at present; emit hook lands in δ.8
    -- alongside this CHECK extension)

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``c9d0e1f2a3b4_extend_findings_source_windows_registry_drivers.py``
(γ.7's recreator) — same drop-and-recreate shape with the extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Four now: 7079b4d +
ee2abd9 β.12a + f70c2e1 γ.7 + this δ.8 commit):
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains the
  two values.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets matching entries per CLAUDE.md Rule #9 exhaustivity.

Backend ``WindowsFindingSource`` Literal in
``app/schemas/finding.py`` is also extended in this same commit so the
typed source constants in ``finding_service.py`` (`_SOURCE_R2R_STOMP`
+ `_SOURCE_IL_CAPA`) compile-check against the new values.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "d5a6b7c8d9e0"
down_revision: Union[str, None] = "d4a5b6c7d8e9"
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
    # Phase δ.8 additions:
    "windows_r2r_stomp",
    "windows_il_capa",
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
    # upgrade and downgrade (δ.6/δ.7 emitted findings), remap them to
    # 'manual' so the prior CHECK accepts the row. Same shape as
    # c9d0e1f2a3b4's downgrade.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ('windows_r2r_stomp', 'windows_il_capa')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES
        if v not in ("windows_r2r_stomp", "windows_il_capa")
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
