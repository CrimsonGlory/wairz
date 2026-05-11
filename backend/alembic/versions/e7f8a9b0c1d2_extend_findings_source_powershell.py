"""extend findings.source CHECK with PowerShell event-log source (Phase η.E)

Revision ID: e7f8a9b0c1d2
Revises: c5f6e7d8a9b0
Create Date: 2026-05-11 21:30:00.000000

Phase η.E — extends ``ck_findings_source`` with ONE new source value
so the PowerShell event-log finding-emit hook (η.E extension of ε's
existing ``emit_evtx_findings_from_walk``) can persist forensic-triage
rows for PowerShell EIDs 4103 (Module/Pipeline) and 4104 (ScriptBlock):

- ``windows_powershell_script_block`` — emitted for PowerShell EIDs
  4103 and 4104. Confidence tier mapping is heuristic-driven:

  - LOW (Confidence.low) — EID 4103 module-load events.
  - MEDIUM (Confidence.medium) — EID 4104 plain ScriptBlock events.
  - HIGH (Confidence.high) — EID 4104 with obfuscation indicators
    (base64 / EncodedCommand / -enc / Invoke-Expression /
    FromBase64String / `[char]` arrays).

Per intake D5, ONE Literal value covers the 4103/4104 EID pair (the
EID-specific metadata goes into the finding's evidence/details rather
than into separate Literal values per EID).

Live audit at migration-authoring time (2026-05-11):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_powershell_script_block (η.E ships first
    -- consumer; emit-hook extension ships in this same commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``c5f6e7d8a9b0_extend_findings_source_srum.py`` (ζ.3.C
recreator) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Eight → Rule-of-Nine):

- 7079b4d (2026-05-06 base)
- ee2abd9 β.12a (windows_authenticode + windows_dbx_revoked)
- f70c2e1 γ.7 (windows_registry_persistence + windows_inf +
                windows_driver_imports)
- 20ea228 δ.8 (windows_r2r_stomp + windows_il_capa)
- 5466644 ε.1.b.4 (windows_sysmon_proc_create + windows_logon_success +
                   windows_logon_failure)
- da71afa ζ.1 (windows_amcache_install)
- a6be708 ζ.2.C (windows_prefetch_execution)
- 04a3c55 ζ.3.C (windows_srum_network_activity +
                 windows_srum_application_runtime) → Rule-of-Eight
- THIS η.E (windows_powershell_script_block) → Rule-of-Nine

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_POWERSHELL_SCRIPT_BLOCK``)
compile-checks.

Revision ID ``e7f8a9b0c1d2`` was pre-validated FREE against the
72-revision versions tree before authoring (Rule #19 evidence-first).
"""

from alembic import op


revision: str = "e7f8a9b0c1d2"
down_revision: str | None = "c5f6e7d8a9b0"
branch_labels: str | None = None
depends_on: str | None = None


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
    "windows_authenticode",
    "windows_dbx_revoked",
    "windows_registry_persistence",
    "windows_inf",
    "windows_driver_imports",
    "windows_r2r_stomp",
    "windows_il_capa",
    "windows_sysmon_proc_create",
    "windows_logon_success",
    "windows_logon_failure",
    "windows_amcache_install",
    "windows_prefetch_execution",
    "windows_srum_network_activity",
    "windows_srum_application_runtime",
    # Phase η.E addition — PowerShell event-log source (EIDs 4103/4104):
    "windows_powershell_script_block",
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
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source = 'windows_powershell_script_block'"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v != "windows_powershell_script_block"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
