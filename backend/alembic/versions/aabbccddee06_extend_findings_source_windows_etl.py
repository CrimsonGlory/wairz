"""extend findings.source CHECK with windows_etl_* (Phase ι.C.D — FIRST ι WINDOWS)

Revision ID: aabbccddee06
Revises: aabbccddee05
Create Date: 2026-05-12 19:00:00.000000

Phase ι.C.D — extends ``ck_findings_source`` with FOUR new source
values so the FIRST ι Windows-side walker (ι.C.C ETW .etl trace-log)
can persist operator-actionable findings as Finding rows. THIRD ι
cross-stack alignment commit AND the FIRST ι Windows extension (ι.A.D
+ ι.B.D both extended LinuxFindingSource for Linux journald + systemd).

Rule #25 single-slice exception #2, Rule-of-Twenty → Rule-of-Twenty-
One.

NEW SOURCES:

- ``windows_etl_kernel_proc_after_clear`` — emitted when kernel process
  events (NT Kernel Logger / Microsoft-Windows-Kernel-Process) are
  retained in ETL after a Security.evtx clear marker (correlated via
  ``firmware.evtx_walk_result.log_clear_count``). T1070.001 (Clear
  Windows Event Logs) — FortiGuard 2024 IR canonical tradecraft;
  adversaries who clear EVTX frequently forget to clear ETL.
  Persona-E HIGH.

- ``windows_etl_provider_disabled`` — emitted for logger-session-end
  events (opcode 0x02 / 0x06) from session-control providers (EventLog
  / Logger / Trace-Control / EventTrace). T1562.002 (Disable Windows
  Event Logging). Persona-E HIGH.

- ``windows_etl_unusual_provider`` — emitted for events from a provider
  whose GUID is not in the known Microsoft set AND whose name doesn't
  match the Microsoft-* / Windows-* vendor prefix. T1574 (Hijack
  Execution Flow — providers) candidate. Baseline review — third-
  party ETW providers do exist legitimately. Persona-E MEDIUM.

- ``windows_etl_non_microsoft_in_diagtrack`` — emitted when a third-
  party provider appears inside the AutoLogger-Diagtrack-Listener
  session (Microsoft-only by design). Strong T1574 indicator.
  Persona-E HIGH.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any windows_etl_* (ι.C.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``aabbccddee03_extend_findings_source_linux_systemd.py``
(ι.B.D) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twenty → Rule-of-Twenty-
One):

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
- cd1e2f3a4b5c θ.D.E → Rule-of-Eighteen
- fb4c5d6e7f8a ι.A.D (linux_journald_*) → Rule-of-Nineteen
- aabbccddee03 ι.B.D (linux_systemd_*) → Rule-of-Twenty
- THIS ι.C.D (windows_etl_*) → Rule-of-Twenty-One — FIRST ι Windows
  extension (FIRST Windows-side cross-stack since θ.D.E SDB)

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
gets EXTENDED in this same commit with the 4 new values; typed
module-level constants ``_SOURCE_ETL_*`` in ``finding_service.py``
ensure compile-check coverage.

Revision ID ``aabbccddee06`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.C.B head ``aabbccddee05``.
"""

from alembic import op


revision: str = "aabbccddee06"
down_revision: str | None = "aabbccddee05"
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
    "windows_sdb_inject_dll",
    "windows_sdb_redirect_exe",
    "windows_sdb_custom_shim",
    # Phase ι.A.D additions — FIRST LINUX source family. Journald
    # walker emit sources:
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    # Phase ι.B.D additions — SECOND LINUX source family. Systemd
    # unit-file walker emit sources:
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    # Phase ι.C.D additions — FIRST ι Windows extension. ETW .etl
    # trace-log walker emit sources:
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
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
        "WHERE source IN ("
        "'windows_etl_kernel_proc_after_clear', "
        "'windows_etl_provider_disabled', "
        "'windows_etl_unusual_provider', "
        "'windows_etl_non_microsoft_in_diagtrack'"
        ")"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES if v not in _REMOVED_IN_THIS_REVISION
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
