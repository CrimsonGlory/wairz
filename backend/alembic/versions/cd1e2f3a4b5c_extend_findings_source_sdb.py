"""extend findings.source CHECK with windows_sdb_* (Phase θ.D.E)

Revision ID: cd1e2f3a4b5c
Revises: bc1d2e3f4a5b
Create Date: 2026-05-12 12:00:00.000000

Phase θ.D.E — extends ``ck_findings_source`` with THREE new source
values so the SDB shim walker (θ.D.D) can persist application-
compatibility-shim correlation findings as Finding rows:

- ``windows_sdb_inject_dll`` — emitted for every WindowsSdbEntry
  row with shim_class=InjectDll AND sdb_kind=custom (attacker-
  controllable directory). Confidence tier mapping:

  - HIGH (Confidence.high) — direct DLL-injection primitive in
    a custom-path .sdb. Strong T1546.011 Application Shimming
    signal — attacker can load arbitrary DLL into the target
    process address space on every application launch.

- ``windows_sdb_redirect_exe`` — emitted for every WindowsSdbEntry
  row with shim_class=RedirectEXE AND sdb_kind=custom.
  Confidence tier mapping:

  - HIGH (Confidence.high) — replaces the executed binary
    entirely. Adversary deploys a custom .sdb under
    Windows/AppPatch/Custom/<exe>.sdb pointing to attacker-
    controlled replacement binary.

- ``windows_sdb_custom_shim`` — emitted for every WindowsSdbEntry
  row with sdb_kind=custom that doesn't match the two HIGH classes
  above. Confidence tier mapping:

  - MEDIUM (Confidence.medium) — Custom-path with
    GetCommandLineW OR RedirectShortcut OR has_command_line
    (argument-injection / shortcut-hijack / hot-edge tradecraft).
  - LOW (Confidence.low) — Custom-path baseline (operator review;
    not all custom shims are malicious, but the path is suspicious).

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_sdb_inject_dll / windows_sdb_redirect_exe /
    -- windows_sdb_custom_shim (θ.D.E ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``cd0e1f2a3b4c_extend_findings_source_mbr_vbr.py`` (θ.E.D) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Eighteen):

- 7079b4d (2026-05-06 base) → Rule-of-One
- ee2abd9 β.12a → Rule-of-Two
- f70c2e1 γ.7 → Rule-of-Three
- 20ea228 δ.8 → Rule-of-Four
- 5466644 ε.1.b.4 → Rule-of-Five
- da71afa ζ.1 → Rule-of-Six
- a6be708 ζ.2.C → Rule-of-Seven
- 04a3c55 ζ.3.C → Rule-of-Eight
- ac98e55 η.E → Rule-of-Nine
- e149dcf η.B.D → Rule-of-Ten
- fd7cd23 η.C.D → Rule-of-Eleven
- 66bd8d6 η.A.D → Rule-of-Twelve
- η.D.D → Rule-of-Thirteen
- a4d5f45 θ.A.D → Rule-of-Fourteen
- 383ffe9 θ.B.E → Rule-of-Fifteen
- c0d5795 θ.C.D → Rule-of-Sixteen
- f0544f2 θ.E.D → Rule-of-Seventeen
- THIS θ.D.E (windows_sdb_inject_dll + windows_sdb_redirect_exe +
  windows_sdb_custom_shim) → Rule-of-Eighteen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants
in ``finding_service.py`` (``_SOURCE_SDB_INJECT_DLL`` /
``_SOURCE_SDB_REDIRECT_EXE`` / ``_SOURCE_SDB_CUSTOM``) compile-check.

Revision ID ``cd1e2f3a4b5c`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.D.C head ``bc1d2e3f4a5b``.
"""

from alembic import op


revision: str = "cd1e2f3a4b5c"
down_revision: str | None = "bc1d2e3f4a5b"
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
    "windows_wmi_persistence",
    "windows_esp_unsigned",
    "windows_esp_dbx_revoked",
    "windows_mbr_bootkit",
    "windows_vbr_anomaly",
    # Phase θ.D.E additions — SDB shim walker emit sources:
    "windows_sdb_inject_dll",
    "windows_sdb_redirect_exe",
    "windows_sdb_custom_shim",
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
        "WHERE source IN ('windows_sdb_inject_dll', "
        "'windows_sdb_redirect_exe', 'windows_sdb_custom_shim')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v not in (
            "windows_sdb_inject_dll",
            "windows_sdb_redirect_exe",
            "windows_sdb_custom_shim",
        )
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
