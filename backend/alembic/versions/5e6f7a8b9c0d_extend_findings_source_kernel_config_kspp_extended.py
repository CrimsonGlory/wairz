r"""extend findings.source CHECK with kernel_config_kspp_extended

Revision ID: 5e6f7a8b9c0d
Revises: 4ecdef506a7c
Create Date: 2026-05-22 23:30:00.000000

Rule #25 Shape-1 cross-stack alignment commit (Rule-of-Twenty-Two
extension — chains from ``3dcb4e5f6a7b`` which landed the initial 10
``kernel_config_*`` sources and ``4ecdef506a7c`` which added the
``kernel_config_audit_*`` walker state-machine columns).

  - DB CHECK: this migration extends ``ck_findings_source``
  - Pydantic Literal: ``KernelConfigFindingSource`` in app/schemas/finding.py
  - Frontend mirror: ``FindingSource`` union in types/index.ts +
    ``FINDING_SOURCE_CONFIG`` keys in statusConfig.ts
  - Alignment test: test_finding_source_alignment auto-discovers the
    new value from THIS migration's ``_NEW_SOURCE_VALUES`` tuple

Lands the source vocabulary for the upstream
``kernel-hardening-checker`` catalogue expansion (Phase
kernel-image-followup-T3 Phase 2, chains from Phase 1 dep pin at
``4b05af2``). The walker (separate commit in this chain) will emit:

  * The 10 existing ``kernel_config_*`` per-rule sources, preserved
    unchanged (each rule kept under its operator-visible name); AND
  * One new generic ``kernel_config_kspp_extended`` source for ALL
    upstream rules NOT in the wairz-curated 10 (~250 additional
    checks per arch — too many for per-source alignment given the
    cross-stack discipline cost). Evidence payload carries the
    upstream rule name + decision + reason in the Finding's
    ``evidence`` text so operators can filter via evidence-text search.

The tier-based strategy keeps existing per-source filterability on the
high-signal items operators already pick by name (KASLR, /dev/mem,
module signing, LSM, etc — 10 sources currently in
``statusConfig.ts:178-187``) while accepting "extended" as the catch-
all for the rest of the upstream catalogue. Operator UX preserved;
342 frontend ``Record<FindingSource, Config>`` entries avoided.

NEW SOURCES (1):

* ``kernel_config_kspp_extended`` — KSPP-aligned kernel hardening
  check from upstream ``kernel-hardening-checker`` (any rule beyond
  the wairz-curated 10). Severity derived from upstream
  ``KconfigCheck.decision`` (kspp→high, defconfig→medium, grsec/
  clipos/maintainer/grapheneos→low, lockdown→medium). CWE inferred
  from upstream ``KconfigCheck.reason`` (self_protection→CWE-693,
  cut_attack_surface→CWE-1188, harden_userspace→CWE-119,
  security_policy→CWE-272, network_security→CWE-693). Evidence
  text includes ``opt.name`` + ``opt.expected`` + ``opt.check_result``.

Live audit at migration-authoring time (2026-05-22):

    SELECT source, COUNT(*) FROM findings
      WHERE source = 'kernel_config_kspp_extended';
    -- 0 rows (walker swap ships in the next commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``3dcb4e5f6a7b_extend_findings_source_kernel_config.py``
shape (Rule #25 Shape-1 alignment commit precedent). Same
drop-and-recreate with extended ``_NEW_SOURCE_VALUES`` tuple. Tuple is
exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import +
assert agreement.

Wave-2 attack B mitigation: source name ``kernel_config_kspp_extended``
is 27 chars; ``findings.source`` column is VARCHAR(50) → comfortable
headroom + no truncation risk on persisted rows.

Chains from ``4ecdef506a7c`` (add_kernel_config_audit_walker_state).
"""
from __future__ import annotations

from alembic import op


revision: str = "5e6f7a8b9c0d"
down_revision: str | None = "4ecdef506a7c"
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
    # ── KSPP extended family (this migration) ─────────────────────────
    "kernel_config_kspp_extended",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "kernel_config_kspp_extended",
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
