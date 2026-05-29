r"""extend findings.source CHECK with kernel_config_extraction_blocked

Revision ID: f4a5b6c7d8e9
Revises: e3f4a5b6c7d8
Create Date: 2026-05-29 14:30:00.000000

Rule #25 Shape-1 cross-stack alignment commit. Lands the ONE structural
finding source the C1 generic kernel-config EXTRACTION walker emits — the
HONEST BLOCKED verdict for the Elo-tablet-style ``ff12d941`` proprietary
A/B OTA ``payload.bin`` boot-partition op (the
``R47.1b``-undeterminable-not-proven-absent case).

  - DB CHECK: this migration extends ``ck_findings_source``
  - Pydantic Literal: ``KernelConfigFindingSource`` in app/schemas/finding.py
  - Frontend mirror: ``FindingSource`` union in types/index.ts +
    ``FINDING_SOURCE_CONFIG`` keys in statusConfig.ts
  - Alignment test: test_finding_source_alignment auto-discovers the new
    value from THIS migration's ``_NEW_SOURCE_VALUES`` tuple

The KSPP per-rule ``kernel_config_*`` hardening sources stay the
DOWNSTREAM ``linux_kernel_hardening_walker``'s job — C1 emits exactly ONE
structural source so operators see the ``ff12d941`` block honestly rather
than as a silent no-op.

NEW SOURCES (1):

* ``kernel_config_extraction_blocked`` — INFO-severity. C1 could not
  recover the kernel ``.config`` because the kernel's packaging is not
  standard-decodable (the ff12d941 proprietary block class). Recommendation
  (live_adb_or_vendor_tool) carried in the Finding evidence text. CWE-1059
  (insufficient technical documentation / vendor-opaque format envelope).
  Kernel CVEs for the firmware fall through to version_not_affected /
  unresolved rather than config_disabled (Axiom 1 guilty-until-proven).

Source name is 33 chars; ``findings.source`` column is VARCHAR(50) →
comfortable headroom + no truncation risk (Wave-2 attack B analog).

Live audit at migration-authoring time (2026-05-29):

    SELECT source, COUNT(*) FROM findings
      WHERE source = 'kernel_config_extraction_blocked';
    -- 0 rows (walker emit ships in the same commit). Zero existing rows
    -- ⇒ "extend CHECK" path; no defensive backfill needed (Rule #19).

Mirrors ``5e6f7a8b9c0d_extend_findings_source_kernel_config_kspp_extended.py``
shape. Chains from ``e3f4a5b6c7d8`` (add_kernel_config_walk_to_firmware).
"""
from __future__ import annotations

from alembic import op


revision: str = "f4a5b6c7d8e9"
down_revision: str | None = "e3f4a5b6c7d8"
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
    # ── kernel-image hardening family ────────────────────────────────
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
    # ── KSPP extended family ──────────────────────────────────────────
    "kernel_config_kspp_extended",
    # ── C1 EXTRACTION walker structural source (this migration) ────────
    "kernel_config_extraction_blocked",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "kernel_config_extraction_blocked",
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
