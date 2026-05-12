r"""extend findings.source CHECK with linux_persistence_* (Phase κ.C.D)

Revision ID: aabbccddee12
Revises: aabbccddee11
Create Date: 2026-05-12 23:59:00.000000

Phase κ.C.D — extends ``ck_findings_source`` with THREE new source
values so the κ.C.C Linux persistence-triplet walker can persist
operator-actionable findings as Finding rows. EIGHTH κ-era cross-stack
alignment commit. Rule #25 single-slice exception #2 (DB CHECK +
frontend mirror + backend Literal extension all in one atomic commit
— ``test_finding_source_alignment.py`` enforces pairwise agreement).

NEW SOURCES:

- ``linux_bash_history_clear`` HIGH — T1070.003 Indicator Removal:
  Clear Command History. The act of trying to clear bash_history
  ironically leaves cleanup commands in the historical entries below.
  ``history -c`` / ``> ~/.bash_history`` / ``rm -f ~/.bash_history`` /
  ``unset HISTFILE``.

- ``linux_cron_suspicious_command`` MEDIUM — T1053.003 Scheduled Task /
  Cron + persistence. Fires when a crontab line combines suspicious
  flags (temp_path_command OR reboot_persistence + network_egress).
  Persona-E MEDIUM baseline; operator triages by reading the
  ``schedule_spec`` and ``command`` columns.

- ``linux_ld_preload_hijack`` HIGH — T1574.006 Hijack Execution Flow:
  Dynamic Linker Hijacking. ANY ``/etc/ld.so.preload`` entry warrants
  operator review — the file is inherently sensitive (every dynamically-
  linked process loads listed libraries before its own deps). When the
  library path lives under ``/tmp/`` / ``/dev/shm/`` or has an unusual
  extension, the case is open-and-shut compromise.

**PARSE-ONLY DISCIPLINE REMINDER (Rule #36).** These findings are
emitted from the κ.C.C walker's pure-Python text-line parser. The
walker NEVER invokes ``bash`` / ``crontab`` / ``ldconfig`` against
the parsed lines. Findings flag METADATA only.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any linux_bash_history_clear / linux_cron_suspicious_command
    -- / linux_ld_preload_hijack (κ.C.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``aabbccddee0c_extend_findings_source_linux_container.py``
(ι.E.D) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend ``FindingSource``
union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twenty-Four with this
extension). Files updated atomically:

- ``frontend/src/types/index.ts`` — ``FindingSource`` union extended.
- ``frontend/src/constants/statusConfig.ts`` — ``FINDING_SOURCE_CONFIG``
  entries for each new source (icon + label + className).
- ``backend/app/schemas/finding.py`` — ``LinuxFindingSource`` Literal
  extended with the same 3 values.
- ``backend/app/services/finding_service.py`` — typed module-level
  ``_SOURCE_LINUX_PERSISTENCE_*`` constants + emit hook
  ``emit_linux_persistence_findings_from_walk``.

Revision ID ``aabbccddee12`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from κ.C.B head ``aabbccddee11``.
"""

from alembic import op


revision: str = "aabbccddee12"
down_revision: str | None = "aabbccddee11"
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
    # Phase κ.C.D additions — Linux persistence-triplet (bash_history +
    # crontab + ld.so.preload). PARSE-ONLY walker surfaces persistence
    # METADATA only — file paths + commands + library paths.
    "linux_bash_history_clear",
    "linux_cron_suspicious_command",
    "linux_ld_preload_hijack",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "linux_bash_history_clear",
    "linux_cron_suspicious_command",
    "linux_ld_preload_hijack",
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
        "'linux_bash_history_clear', "
        "'linux_cron_suspicious_command', "
        "'linux_ld_preload_hijack'"
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
