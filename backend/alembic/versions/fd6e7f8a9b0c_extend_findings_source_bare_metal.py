r"""extend findings.source CHECK with bare-metal MCU/DSP sources (Rule #52 Phase 1)

Revision ID: fd6e7f8a9b0c
Revises: fc5d6e7f8a9b
Create Date: 2026-05-19 15:45:00.000000

Rule #25 Shape-1 cross-stack alignment commit (Rule-of-Twenty pattern —
extends Rule-of-Nineteen from ``fb4c5d6e7f8a`` linux_journald):

  - DB CHECK: this migration extends ``ck_findings_source``
  - Pydantic Literal: ``BareMetalFindingSource`` in app/schemas/finding.py
  - Frontend mirror: ``FindingSource`` union in types/index.ts +
    ``FINDING_SOURCE_CONFIG`` keys in statusConfig.ts
  - Alignment test: test_finding_source_alignment auto-discovers the
    new values from THIS migration's ``_NEW_SOURCE_VALUES`` tuple

NEW SOURCES:

- ``c28x_unsecure_csm`` — emitted by the bare_metal_audit walker when the
  TI C28x Code Security Module password locations (0x3F7FF8-0x3F7FFF) are
  all 0xFFFF (factory-unprogrammed). JTAG dummy-read unlocks the chip;
  CWE-1273 (Device Unlock Credential Sharing) + CWE-1191 (On-Chip Debug
  Defaults). Severity HIGH. Eaton UPS firmware 2026-05-19 is the
  reference case.

- ``c28x_csm_perma_lock`` — emitted when CSM PWL is all 0x0000 (the
  perma-lock value — chip cannot be re-flashed without erasing PWL).
  Surfaces as a manufacturing-quality / RMA finding. CWE-1191. Severity
  MEDIUM.

- ``bare_metal_chip_unknown_with_hints`` — emitted when zero chip families
  match auto-detect AND no operator descriptor is available. Carries the
  heuristic findings (entropy / strings / vector-table candidates) so
  operators see SOMETHING actionable. Severity INFO.

- ``bare_metal_encrypted_region_skipped`` — informational emit when the
  walker skips a region declared ``semantic: encrypted_region`` per Rule
  #45 parse-only contract. Operators see WHY the region wasn't audited.
  Severity INFO.

Live audit at migration-authoring time (2026-05-19):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any bare_metal_* / c28x_* source (Phase 1 first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``fb4c5d6e7f8a_extend_findings_source_linux_journald.py``
(ι.A.D — first non-Windows family). Same drop-and-recreate shape with
extended ``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact
name so ``test_finding_source_alignment._load_db_source_values`` can
import + assert agreement.

Chains from Rule #52 Phase 1 DDL ``fc5d6e7f8a9b``.
"""
from __future__ import annotations

from alembic import op


revision: str = "fd6e7f8a9b0c"
down_revision: str | None = "fc5d6e7f8a9b"
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
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "c28x_unsecure_csm",
    "c28x_csm_perma_lock",
    "bare_metal_chip_unknown_with_hints",
    "bare_metal_encrypted_region_skipped",
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
