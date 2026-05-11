"""extend findings.source CHECK with windows_lnk_abnormal_target (Phase η.C.D)

Revision ID: a7b8c9d0e1f2
Revises: c2e3f4a5b6d7
Create Date: 2026-05-11 23:50:00.000000

Phase η.C.D — extends ``ck_findings_source`` with ONE new source value
so the LNK walker (η.C.C) can persist persistence-candidate findings
as ``windows_lnk_abnormal_target`` Finding rows:

- ``windows_lnk_abnormal_target`` — emitted by
  ``emit_lnk_findings_from_walk`` for every ``WindowsLnkRecord``
  row produced by the η.C.C walker whose target / arguments shape
  matches T1547.009 Shortcut Modification persistence indicators.
  Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — target_path resolves to a known
    script-host binary (cmd.exe / cscript.exe / wscript.exe /
    powershell.exe / pwsh.exe / mshta.exe / regsvr32.exe /
    rundll32.exe) AND arguments contain encoded-PowerShell
    pattern (``-EncodedCommand`` / ``-enc`` / ``FromBase64String`` /
    ``Invoke-Expression`` / ``[char[]]`` / ``DownloadString`` /
    ``IEX``). Qakbot / cobalt-strike pattern.
  - MEDIUM (Confidence.medium) — target_path is non-Microsoft
    (NOT under \\Windows\\, %SystemRoot%, %windir%, C:\\Program Files\\
    Microsoft *, C:\\ProgramData\\Microsoft\\, etc.). LNKs targeting
    user-writable directories are atypical for legitimate Start Menu
    / Recent docs entries.
  - LOW (Confidence.low) — baseline review-candidate row.

Per intake D5-style discipline: ONE Literal value covers all 3 tiers
(the tier metadata goes into the finding's confidence + evidence
fields, not into separate Literal values per tier).

Live audit at migration-authoring time (2026-05-11):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_lnk_abnormal_target (η.C.D ships first
    -- consumer; emit-hook extension ships in this same commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``a0b1c2d3e4f5_extend_findings_source_scheduled_task.py``
(η.B.D) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Ten → Rule-of-Eleven):

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
                 windows_srum_application_runtime)
- ac98e55 η.E (windows_powershell_script_block) → Rule-of-Nine
- e149dcf η.B.D (windows_scheduled_task_persistence) → Rule-of-Ten
- THIS η.C.D (windows_lnk_abnormal_target) → Rule-of-Eleven

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_LNK_ABNORMAL_TARGET``) compile-checks.

Revision ID ``a7b8c9d0e1f2`` was pre-validated FREE against the
75-revision versions tree before authoring (Rule #19 evidence-first).
"""

from alembic import op


revision: str = "a7b8c9d0e1f2"
down_revision: str | None = "c2e3f4a5b6d7"
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
    "windows_powershell_script_block",
    "windows_scheduled_task_persistence",
    # Phase η.C.D addition — LNK abnormal-target source:
    "windows_lnk_abnormal_target",
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
        "WHERE source = 'windows_lnk_abnormal_target'"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v != "windows_lnk_abnormal_target"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
