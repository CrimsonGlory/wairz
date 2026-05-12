"""extend findings.source CHECK with windows_wmi_persistence (Phase θ.B.E)

Revision ID: 6e9f7a0b1c3d
Revises: 5d8e6f9c0a2b
Create Date: 2026-05-12 05:00:00.000000

Phase θ.B.E — extends ``ck_findings_source`` with ONE new source value
so the WMI walker (θ.B.D) can persist FilterToConsumerBinding
findings as Finding rows:

- ``windows_wmi_persistence`` — emitted by
  ``emit_wmi_findings_from_walk`` for every non-benign
  ``WindowsWmiEvent`` row whose anomaly_flags shape matches
  T1546.003 Event-Triggered Execution: WMI Event Subscription
  indicators. Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — consumer_type=ActiveScriptEventConsumer
    (in-process VBScript/JScript — the highest-impact WMI
    consumer type), OR consumer_payload carries the encoded-
    PowerShell pattern (Qakbot signature: -EncodedCommand / -enc
    / FromBase64String / Invoke-Expression / [char[]] /
    DownloadString / IEX). T1546.003 strong signal.
  - MEDIUM (Confidence.medium) — consumer_type=CommandLine
    EventConsumer AND consumer_payload references a known script-
    host binary (wscript/cscript/powershell/pwsh/mshta/rundll32/
    regsvr32). LOLBin-via-WMI shape.
  - LOW (Confidence.low) — baseline review-candidate row (any
    non-benign FilterToConsumerBinding deserves operator attention).

Per intake style: ONE Literal value covers all 3 tiers (tier metadata
into the finding's confidence + evidence rather than separate Literal
values per tier). Same shape as windows_scheduled_task_persistence /
windows_lnk_abnormal_target.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_wmi_persistence (θ.B.E ships first consumer;
    -- emit-hook extension ships in θ.B.F).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``3b6c4d5e6f7a_extend_findings_source_bcd.py`` (θ.A.D) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Fourteen → Rule-of-Fifteen):

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
- fd7cd23 η.C.D (windows_lnk_abnormal_target) → Rule-of-Eleven
- 66bd8d6 η.A.D (windows_mft_ads_hidden_content + windows_mft_timestomping)
  → Rule-of-Twelve
- η.D.D (windows_byovd_driver) → Rule-of-Thirteen
- a4d5f45 θ.A.D (windows_bcd_suspicious_path +
                 windows_bcd_testsigning_enabled) → Rule-of-Fourteen
- THIS θ.B.E (windows_wmi_persistence) → Rule-of-Fifteen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_WMI_PERSISTENCE``) compile-checks.

Revision ID ``6e9f7a0b1c3d`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.B.C head ``5d8e6f9c0a2b``.
"""

from alembic import op


revision: str = "6e9f7a0b1c3d"
down_revision: str | None = "5d8e6f9c0a2b"
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
    "windows_lnk_abnormal_target",
    "windows_mft_ads_hidden_content",
    "windows_mft_timestomping",
    "windows_byovd_driver",
    "windows_bcd_suspicious_path",
    "windows_bcd_testsigning_enabled",
    # Phase θ.B.E addition — WMI walker emit source:
    "windows_wmi_persistence",
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
        "WHERE source = 'windows_wmi_persistence'"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v != "windows_wmi_persistence"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
