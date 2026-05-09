"""extend findings.source CHECK with windows EVTX sources

Revision ID: e1a2b3c4d5e6
Revises: e0a1b2c3d4e5
Create Date: 2026-05-10 10:00:00.000000

Phase ε.1.b.4 — extends ``ck_findings_source`` with three new source
values so the EVTX walk emit hook can persist forensic-timeline
``Finding`` rows the operator can triage alongside the existing CVE /
SBOM / kernel / authenticode / registry / driver / R2R-stomp findings:

- ``windows_sysmon_proc_create`` — emitted by the ε.1.b.4 emit hook
  for Sysmon Event ID 1 (process create). Persona-E #4 forensic-
  timeline trio: surfaces every detected process-create event where
  the parent / child / commandline triple matches a wairz heuristic
  (LOLBin abuse, suspicious cmdline patterns, zero-prevalence binaries).
  Confidence tier mapping:
  - LOW review candidate → Confidence.low
  - MEDIUM heuristic match → Confidence.medium
  - HIGH (deferred to future ζ.X tier) → Confidence.high

- ``windows_logon_success`` — emitted for Security Event ID 4624
  (logon success). Surfaces interactive / network / RDP / service
  logons matching wairz heuristics (golden-ticket / pass-the-hash
  patterns, anomalous logon-type / user / source-IP combos).

- ``windows_logon_failure`` — emitted for Security Event ID 4625
  (logon failure). Surfaces failed-logon bursts + uncommon failure
  reasons that can indicate brute-force probing or credential
  spraying.

Live audit at migration-authoring time (2026-05-10, before this
migration applies):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_sysmon_proc_create / windows_logon_success /
    -- windows_logon_failure (the ε.1.b.4 emit hook is the first
    -- consumer of these source tags; service ships with this CHECK
    -- extension)

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill
needed.

Mirrors ``d5a6b7c8d9e0_extend_findings_source_windows_dotnet.py``
(δ.8's recreator) — same drop-and-recreate shape with the extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Five now: 7079b4d +
ee2abd9 β.12a + f70c2e1 γ.7 + 20ea228 δ.8 + this ε.1.b.4 commit):
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains the
  three values.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets matching entries per CLAUDE.md Rule #9 exhaustivity.

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants
in ``finding_service.py`` (``_SOURCE_SYSMON_1`` + ``_SOURCE_LOGON_SUCCESS``
+ ``_SOURCE_LOGON_FAILURE``) compile-check against the new values.

Revision ID `e1a2b3c4d5e6` was pre-validated FREE against the 60-revision
versions tree before authoring per `.mex/patterns/add-alembic-migration.md`.
"""
from typing import Sequence, Union

from alembic import op


revision: str = "e1a2b3c4d5e6"
down_revision: Union[str, None] = "e0a1b2c3d4e5"
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
    # Phase ε.1.b.4 additions:
    "windows_sysmon_proc_create",
    "windows_logon_success",
    "windows_logon_failure",
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
    # upgrade and downgrade (ε.1.b.4 emit hook persisted findings), remap
    # them to 'manual' so the prior CHECK accepts the row. Same shape
    # as d5a6b7c8d9e0's downgrade.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ('windows_sysmon_proc_create', "
        "'windows_logon_success', 'windows_logon_failure')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES
        if v not in (
            "windows_sysmon_proc_create",
            "windows_logon_success",
            "windows_logon_failure",
        )
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
