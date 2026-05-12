"""extend findings.source CHECK with linux_journald_* (Phase ι.A.D — FIRST LINUX)

Revision ID: fb4c5d6e7f8a
Revises: fb3a4b5c6d7e
Create Date: 2026-05-12 16:00:00.000000

Phase ι.A.D — extends ``ck_findings_source`` with FIVE new source
values so the FIRST LINUX walker (ι.A.C journald) can persist
operator-actionable findings as Finding rows. This is the first
NON-WINDOWS cross-stack alignment commit in wairz — sibling to the
WindowsFindingSource family established by β.12a → θ.D.E (18
Rule-of-N applications).

NEW SOURCES:

- ``linux_journald_priority_critical`` — emitted for entries with
  priority <= 2 (emerg / alert / crit). Persona-E LOW baseline;
  review-candidate row. NOT a confirmed-compromise signal but a
  triage starting point — operator may filter for sustained patterns.

- ``linux_journald_oom_killer`` — emitted for entries whose MESSAGE
  matches the kernel OOM-killer pattern. T1499 (Endpoint DoS)
  collateral signal. Sustained OOM-kill activity correlates with
  resource-exhaustion exploit attempts (memory-bomb DOS, fork-bomb,
  zip-bomb residue). Persona-E MEDIUM.

- ``linux_journald_suspicious_unit`` — emitted for entries whose
  _SYSTEMD_UNIT path is under a writable directory (/tmp, /var/tmp,
  /dev/shm, /run/shm, /home). T1543.002 (Create or Modify System
  Process: Systemd Service) — APT36 (Aug 2025), FIRESTARTER (CISA
  2026), Quasar Linux QLNX (May 2026) canonical TTP. Persona-E HIGH.

- ``linux_journald_log_clear`` — emitted for entries whose MESSAGE
  matches journalctl --vacuum / --rotate / cleared-archived-journal
  residue. T1070.002 (Indicator Removal: Clear Linux or Mac System
  Logs). Persona-E MEDIUM — could be legitimate rotation, operator
  triages.

- ``linux_journald_selinux_denied`` — emitted for entries with SELinux
  AVC denials. T1562.001 (Disable or Modify Tools — SELinux policy
  bypass attempt). The denial itself is the *defense success* signal,
  but a sustained pattern indicates intentional bypass attempts.
  Persona-E MEDIUM.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any linux_journald_* (ι.A.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``cd1e2f3a4b5c_extend_findings_source_sdb.py`` (θ.D.E) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Eighteen → Rule-of-
Nineteen):

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
- THIS ι.A.D (linux_journald_*) → Rule-of-Nineteen — FIRST non-
  Windows source family

Backend ``LinuxFindingSource`` Literal in ``app/schemas/finding.py``
is introduced as a sibling of ``WindowsFindingSource`` in this same
commit so the typed source constants in ``finding_service.py``
(``_SOURCE_JOURNALD_*``) compile-check.

Revision ID ``fb4c5d6e7f8a`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.A.B head ``fb3a4b5c6d7e``.
"""

from alembic import op


revision: str = "fb4c5d6e7f8a"
down_revision: str | None = "fb3a4b5c6d7e"
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
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
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
        "'linux_journald_priority_critical', "
        "'linux_journald_oom_killer', "
        "'linux_journald_suspicious_unit', "
        "'linux_journald_log_clear', "
        "'linux_journald_selinux_denied'"
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
