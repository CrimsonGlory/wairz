r"""extend findings.source CHECK with Linux kernel-config hardening sources

Revision ID: 3dcb4e5f6a7b
Revises: 3dba4e5f6a7b
Create Date: 2026-05-22 21:30:00.000000

Rule #25 Shape-1 cross-stack alignment commit (Rule-of-Twenty-One pattern —
extends Rule-of-Twenty from ``2cba3d4e5f6a`` ICS protocol):

  - DB CHECK: this migration extends ``ck_findings_source``
  - Pydantic Literal: ``KernelConfigFindingSource`` in app/schemas/finding.py
  - Frontend mirror: ``FindingSource`` union in types/index.ts +
    ``FINDING_SOURCE_CONFIG`` keys in statusConfig.ts
  - Alignment test: test_finding_source_alignment auto-discovers the
    new values from THIS migration's ``_NEW_SOURCE_VALUES`` tuple

Lands the source vocabulary for the ``linux_kernel_hardening_walker``
(separate PR) — the walker reads ``HardwareFirmwareBlob.metadata.kernel_config``
populated by ``parsers/kernel_image.py`` (commits f947b59 + 108102b) and
emits Findings against blobs that ship Linux kernels with insecure /
missing hardening configs.  Initial 10 sources mirror the KSPP catalogue
+ the pre-existing security.py:1585 ``checks`` list (the MCP-tool's
ad-hoc audit surface).  Severity + CWE assignments documented per-source
in the Literal docstring at schemas/finding.py.

NEW SOURCES (10):

* ``kernel_config_no_kaslr`` — KASLR (CONFIG_RANDOMIZE_BASE) off. CWE-330.
* ``kernel_config_devmem_enabled`` — /dev/mem (CONFIG_DEVMEM=y) on. CWE-732.
* ``kernel_config_devkmem_enabled`` — /dev/kmem (CONFIG_DEVKMEM=y) on. CWE-732.
* ``kernel_config_no_module_sig`` — module signing off. CWE-345.
* ``kernel_config_no_lsm`` — no major LSM (SELinux/AppArmor/SMACK/TOMOYO). CWE-272.
* ``kernel_config_no_stackprotector`` — CONFIG_STACKPROTECTOR_STRONG off. CWE-121.
* ``kernel_config_no_hardened_usercopy`` — CONFIG_HARDENED_USERCOPY off. CWE-120.
* ``kernel_config_no_fortify_source`` — CONFIG_FORTIFY_SOURCE off. CWE-120.
* ``kernel_config_io_uring_enabled`` — CONFIG_IO_URING=y risk surface. CWE-1188.
* ``kernel_config_no_dm_verity`` — CONFIG_DM_VERITY off. CWE-353.

Live audit at migration-authoring time (2026-05-22):

    SELECT source, COUNT(*) FROM findings
      WHERE source LIKE 'kernel_config_%' GROUP BY source;
    -- 0 rows (Phase 2 first consumer ships in a follow-up PR).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``fd6e7f8a9b0c_extend_findings_source_bare_metal.py`` (the
Rule #52 Phase 1 cross-stack alignment commit shape). Same
drop-and-recreate with extended ``_NEW_SOURCE_VALUES`` tuple. Tuple is
exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import +
assert agreement.

Wave-2 attack B mitigation: every new source name is ≤34 chars; the
``findings.source`` column is VARCHAR(50) → comfortable headroom + no
truncation risk on persisted rows.

Chains from ``3dba4e5f6a7b`` (Rule #15 string-column widen — does not
touch ``ck_findings_source``; preserved tuple).  The prior source-CHECK
migration is ``2cba3d4e5f6a`` (ICS Phase 4 closer).
"""
from __future__ import annotations

from alembic import op


revision: str = "3dcb4e5f6a7b"
down_revision: str | None = "3dba4e5f6a7b"
branch_labels: str | None = None
depends_on: str | None = None


_NEW_SOURCE_VALUES: tuple[str, ...] = (
    # ── canonical core ─────────────────────────────────────────────────
    "manual", "security_audit", "yara_scan", "attack_surface", "sbom_scan",
    "hardware_firmware_graph", "apk-manifest-scan", "apk-bytecode-scan",
    "apk-mobsfscan", "cwe_checker", "uefi_scan", "clamav_scan", "vt_scan",
    "abusech_scan", "fuzzing", "unpack_audit", "security_review", "ai_discovered",
    # ── windows family ────────────────────────────────────────────────
    "windows_authenticode", "windows_dbx_revoked",
    "windows_registry_persistence", "windows_inf", "windows_driver_imports",
    "windows_r2r_stomp", "windows_il_capa",
    "windows_sysmon_proc_create", "windows_logon_success", "windows_logon_failure",
    "windows_amcache_install", "windows_prefetch_execution",
    "windows_srum_network_activity", "windows_srum_application_runtime",
    "windows_powershell_script_block", "windows_scheduled_task_persistence",
    "windows_lnk_abnormal_target",
    "windows_mft_ads_hidden_content", "windows_mft_timestomping",
    "windows_byovd_driver",
    "windows_bcd_suspicious_path", "windows_bcd_testsigning_enabled",
    "windows_wmi_persistence",
    "windows_esp_unsigned", "windows_esp_dbx_revoked",
    "windows_mbr_bootkit", "windows_vbr_anomaly",
    "windows_sdb_inject_dll", "windows_sdb_redirect_exe", "windows_sdb_custom_shim",
    "windows_etl_kernel_proc_after_clear", "windows_etl_provider_disabled",
    "windows_etl_unusual_provider", "windows_etl_non_microsoft_in_diagtrack",
    "windows_efs_orphaned_drf", "windows_efs_unusual_recovery_agent",
    "windows_efs_domain_admin_in_ddf", "windows_efs_large_drf",
    "windows_appcompat_suspicious_path", "windows_appcompat_temp_execution",
    "windows_appcompat_recent_baseline",
    "windows_dpapi_orphaned_masterkey", "windows_dpapi_admin_creator_sid",
    "windows_dpapi_large_masterkey",
    "windows_usnjrnl_file_deletion", "windows_usnjrnl_temp_create_delete_pair",
    "windows_usnjrnl_renamed_executable",
    # ── linux family ──────────────────────────────────────────────────
    "linux_journald_priority_critical", "linux_journald_oom_killer",
    "linux_journald_suspicious_unit", "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    "linux_systemd_suspicious_path", "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port", "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    "linux_container_privileged_mode", "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount", "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
    "linux_bash_history_clear", "linux_cron_suspicious_command",
    "linux_ld_preload_hijack",
    # ── Rule #52 Phase 1 bare-metal MCU/DSP family ─────────────────────
    "c28x_unsecure_csm",
    "c28x_csm_perma_lock",
    "bare_metal_chip_unknown_with_hints",
    "bare_metal_encrypted_region_skipped",
    # ── Rule #52 ICS protocol catalog family ────────────────────────────
    "ics_modbus_tcp_detected",
    "ics_modbus_rtu_detected",
    "ics_dnp3_detected",
    "ics_s7comm_detected",
    "ics_unknown_ics_detected",
    # ── kernel-image hardening family (this migration) ────────────────
    "kernel_config_no_kaslr",
    "kernel_config_devmem_enabled",
    "kernel_config_devkmem_enabled",
    "kernel_config_no_module_sig",
    "kernel_config_no_lsm",
    "kernel_config_no_stackprotector",
    "kernel_config_no_hardened_usercopy",
    "kernel_config_no_fortify_source",
    "kernel_config_io_uring_enabled",
    "kernel_config_no_dm_verity",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "kernel_config_no_kaslr",
    "kernel_config_devmem_enabled",
    "kernel_config_devkmem_enabled",
    "kernel_config_no_module_sig",
    "kernel_config_no_lsm",
    "kernel_config_no_stackprotector",
    "kernel_config_no_hardened_usercopy",
    "kernel_config_no_fortify_source",
    "kernel_config_io_uring_enabled",
    "kernel_config_no_dm_verity",
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
        + ", ".join(f"'{v}'" for v in _REMOVED_IN_THIS_REVISION)
        + ")"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(v for v in _NEW_SOURCE_VALUES if v not in _REMOVED_IN_THIS_REVISION)
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
