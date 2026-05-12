r"""extend findings.source CHECK with windows_dpapi_* (Phase κ.D.D)

Revision ID: aabbccddee15
Revises: aabbccddee14
Create Date: 2026-05-13 00:00:00.000000

Phase κ.D.D — extends ``ck_findings_source`` with THREE new source
values so the κ.D.C DPAPI master-key PARSE-ONLY METADATA walker can
persist operator-actionable findings as Finding rows. NINTH κ-era
cross-stack alignment commit. Rule #25 single-slice exception #2
(DB CHECK + frontend mirror + backend Literal extension all in one
atomic commit — ``test_finding_source_alignment.py`` enforces pairwise
agreement).

NEW SOURCES:

- ``windows_dpapi_orphaned_masterkey`` HIGH — creator_sid extracted
  from the master-key file's path doesn't match any user SID
  discovered elsewhere in the firmware. Backdoor key stash indicator
  (attacker pre-staged keys for later credential decryption) OR
  legacy artefact (user deleted, key files remained). Persona-E HIGH.

- ``windows_dpapi_admin_creator_sid`` MEDIUM — creator_sid matches a
  Windows admin RID pattern (RID 500 / 512 / 519 — Built-in
  Administrator, Domain Admins, Enterprise Admins) OR the Local
  System SID (S-1-5-18). Could be legitimate (admin service-account
  use) or compromise indicator (attacker created keys under admin
  identity). Persona-E MEDIUM.

- ``windows_dpapi_large_masterkey`` LOW — file_size_bytes > 2048.
  Typical master-key files are 740-1024 bytes; oversized files may
  indicate unusual DPAPI configuration or attacker-planted artefact.
  Persona-E LOW baseline.

**PARSE-ONLY DISCIPLINE REMINDER (Rule #36 + Rule #45 —
Rule-of-Two DURABLE BEYOND DEBATE).** These findings are emitted from
the κ.D.C walker's pure-Python ``struct`` parser over DPAPI master-key
files' headers + body preambles. The walker NEVER decrypts master
keys, NEVER invokes ``CryptUnprotectData``, NEVER records the salt
bytes (only the salt SIZE constant). Findings flag METADATA only.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any windows_dpapi_* (κ.D.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``aabbccddee12_extend_findings_source_linux_persistence.py``
(κ.C.D) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twenty-Five with this
extension). Files updated atomically:

- ``frontend/src/types/index.ts`` — ``FindingSource`` union extended.
- ``frontend/src/constants/statusConfig.ts`` — ``FINDING_SOURCE_CONFIG``
  entries for each new source (icon + label + className).
- ``backend/app/schemas/finding.py`` — ``WindowsFindingSource`` Literal
  extended with the same 3 values.
- ``backend/app/services/finding_service.py`` — typed module-level
  ``_SOURCE_DPAPI_*`` constants + emit hook
  ``emit_dpapi_findings_from_walk``.

Revision ID ``aabbccddee15`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from κ.D.B head ``aabbccddee14``.
"""

from alembic import op


revision: str = "aabbccddee15"
down_revision: str | None = "aabbccddee14"
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
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
    "windows_efs_orphaned_drf",
    "windows_efs_unusual_recovery_agent",
    "windows_efs_domain_admin_in_ddf",
    "windows_efs_large_drf",
    "linux_container_privileged_mode",
    "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount",
    "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
    "windows_appcompat_suspicious_path",
    "windows_appcompat_temp_execution",
    "windows_appcompat_recent_baseline",
    "linux_bash_history_clear",
    "linux_cron_suspicious_command",
    "linux_ld_preload_hijack",
    # Phase κ.D.D additions — Windows DPAPI master-key PARSE-ONLY
    # METADATA (Rule #45 — walker NEVER decrypts master keys; surfaces
    # creator_sid + per-file metadata anomalies only).
    "windows_dpapi_orphaned_masterkey",
    "windows_dpapi_admin_creator_sid",
    "windows_dpapi_large_masterkey",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "windows_dpapi_orphaned_masterkey",
    "windows_dpapi_admin_creator_sid",
    "windows_dpapi_large_masterkey",
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
        "'windows_dpapi_orphaned_masterkey', "
        "'windows_dpapi_admin_creator_sid', "
        "'windows_dpapi_large_masterkey'"
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
