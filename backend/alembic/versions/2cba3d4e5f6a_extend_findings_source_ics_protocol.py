r"""extend findings.source CHECK with ICS protocol catalog sources (Rule #52 instance #3 Phase 2)

Revision ID: 2cba3d4e5f6a
Revises: 1c52a4b5c6d7
Create Date: 2026-05-22 10:00:00.000000

Rule #25 Shape-1 cross-stack alignment commit. Mirrors the bare_metal
``fd6e7f8a9b0c`` precedent — extends ``ck_findings_source`` with 5 NEW
finding sources matching the closed ``IcsProtocolFamily`` Literal in
``app/schemas/ics_protocol.py``. Per W2-β §SC5-NEW-ICS-S2-η mitigation,
ALL family values get a corresponding finding source — adding a new
protocol YAML (Phase 5: DNP3, S7Comm; future: opc_ua, ethercat) without
a matching source value would silently reject finding emits at runtime.

Cross-stack contract surfaces (Rule #48 5-part):
  - DB CHECK: this migration extends ``ck_findings_source``
  - Pydantic Literal: ``IcsProtocolFindingSource`` in app/schemas/finding.py
  - Frontend mirror: ``FindingSource`` union in types/index.ts +
    ``FINDING_SOURCE_CONFIG`` keys in statusConfig.ts
  - Alignment test: ``test_finding_source_alignment`` auto-discovers
    this migration via ``_latest_source_check_migration_path()`` walking
    the alembic chain from HEAD; pulls ``_NEW_SOURCE_VALUES`` tuple as
    the authoritative DB-side allowlist

NEW SOURCES:

- ``ics_modbus_tcp_detected`` — emitted when the walker matches at
  least one binary against a Modbus/TCP manifest (Session 1's
  ``_system/modbus_tcp.yaml`` is the production reference; Phase 5
  will not extend with sibling Modbus/RTU YAMLs).
- ``ics_modbus_rtu_detected`` — Modbus RTU over serial (RS-485);
  forward-prepared for future serial-protocol YAML extensions.
- ``ics_dnp3_detected`` — emitted when the walker matches at least one
  binary against a DNP3 manifest (Phase 5 ``_system/dnp3.yaml`` will
  exercise this source).
- ``ics_s7comm_detected`` — emitted when the walker matches at least
  one binary against a Siemens S7Comm/S7Comm-Plus manifest (Phase 5
  ``_system/s7comm.yaml`` will exercise this source).
- ``ics_unknown_ics_detected`` — emitted when a plugin (Phase 4) flags
  an ICS-like stack the closed-grammar catalog cannot identify;
  forward-prepared for the W2-β §SC5-NEW-ICS-7 hot-reload mitigation
  envelope (plugin escape hatch).

Live audit at migration-authoring time (2026-05-22):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any ics_* source (Phase 2 first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``fd6e7f8a9b0c_extend_findings_source_bare_metal.py``. Same
drop-and-recreate shape with extended ``_NEW_SOURCE_VALUES`` tuple.
Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import +
assert agreement.

Chains from ICS Phase 1.A DDL ``1c52a4b5c6d7``.
"""
from __future__ import annotations

from alembic import op


revision: str = "2cba3d4e5f6a"
down_revision: str | None = "1c52a4b5c6d7"
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
    # ── Rule #52 instance #1 — bare-metal MCU/DSP family ─────────────
    "c28x_unsecure_csm",
    "c28x_csm_perma_lock",
    "bare_metal_chip_unknown_with_hints",
    "bare_metal_encrypted_region_skipped",
    # ── Rule #52 instance #3 — ICS protocol catalog family (THIS) ────
    # All 5 IcsProtocolFamily Literal values get an ics_*_detected
    # source per W2-β §SC5-NEW-ICS-S2-η mitigation — forward-prepares
    # future protocol YAMLs (opc_ua, ethercat) without requiring a
    # second cross-stack alignment commit each time.
    "ics_modbus_tcp_detected",
    "ics_modbus_rtu_detected",
    "ics_dnp3_detected",
    "ics_s7comm_detected",
    "ics_unknown_ics_detected",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "ics_modbus_tcp_detected",
    "ics_modbus_rtu_detected",
    "ics_dnp3_detected",
    "ics_s7comm_detected",
    "ics_unknown_ics_detected",
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
