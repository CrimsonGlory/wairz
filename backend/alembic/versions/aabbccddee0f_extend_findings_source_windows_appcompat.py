r"""extend findings.source CHECK with windows_appcompat_* (Phase κ.B.D)

Revision ID: aabbccddee0f
Revises: aabbccddee0e
Create Date: 2026-05-12 22:00:00.000000

Phase κ.B.D — extends ``ck_findings_source`` with THREE new source
values so the κ.B.C AppCompat / Shimcache walker can persist operator-
actionable findings as Finding rows. SEVENTH κ-era cross-stack
alignment commit. Rule #25 single-slice exception #2 (DB CHECK +
frontend mirror + backend Literal extension all in one atomic commit —
``test_finding_source_alignment.py`` enforces pairwise agreement).

NEW SOURCES:

- ``windows_appcompat_suspicious_path`` — emitted when an AppCompat
  entry's file_path matches a canonical adversary-staging directory
  (``\Users\Public\``, ``\Windows\Temp\``, ``\AppData\Local\Temp\``,
  ``\ProgramData\Microsoft\Windows\Caches\``, ``C:\Temp\``).
  T1106 / T1059 — Persona-E HIGH.

- ``windows_appcompat_temp_execution`` — emitted when an AppCompat
  entry's file_path ends in ``.tmp`` or ``.dat``. T1036 Masquerading
  (extension hiding) — Persona-E MEDIUM.

- ``windows_appcompat_recent_baseline`` — emitted when the entry is
  near the MRU end of AppCompat (insertion_position low) AND has a
  recent last_modified_ts (within ~30 days of the firmware capture).
  Baseline-anomaly review per Persona-E LOW — useful for "new binary
  appeared near the time of compromise" investigations.

**PARSE-ONLY DISCIPLINE REMINDER (Rule #36).** These findings are
emitted from the κ.B.C walker's pure-Python ``struct`` parser over the
SYSTEM hive's AppCompatCache REG_BINARY value. The walker NEVER
invokes any extracted binary, NEVER spawns subprocesses, NEVER calls
Windows APIs. Findings flag METADATA anomalies only; operators triage
file paths as DATA.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any windows_appcompat_* (κ.B.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``aabbccddee09_extend_findings_source_windows_efs.py`` (ι.D.D)
— same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import it
via importlib and assert agreement with the frontend ``FindingSource``
union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twenty-Three with this
extension). Files updated atomically:

- ``frontend/src/types/index.ts`` — ``FindingSource`` union extended.
- ``frontend/src/constants/statusConfig.ts`` — ``FINDING_SOURCE_CONFIG``
  entries for each new source (icon + label + className).
- ``backend/app/schemas/finding.py`` — ``WindowsFindingSource`` Literal
  extended with the same 3 values.
- ``backend/app/services/finding_service.py`` — typed module-level
  ``_SOURCE_APPCOMPAT_*`` constants + ``emit_appcompat_findings_from_walk``
  hook.

Revision ID ``aabbccddee0f`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from κ.B.B head ``aabbccddee0e``.
"""

from alembic import op


revision: str = "aabbccddee0f"
down_revision: str | None = "aabbccddee0e"
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
    # Phase ι.A.D additions — FIRST LINUX source family.
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    # Phase ι.B.D additions — Linux systemd.
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    # Phase ι.C.D additions — Windows ETL.
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
    # Phase ι.D.D additions — Windows EFS (PARSE-ONLY — METADATA only).
    "windows_efs_orphaned_drf",
    "windows_efs_unusual_recovery_agent",
    "windows_efs_domain_admin_in_ddf",
    "windows_efs_large_drf",
    # Phase ι.E.D additions — Linux container artefacts.
    "linux_container_privileged_mode",
    "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount",
    "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
    # Phase κ.B.D additions — Windows AppCompat / Shimcache (PARSE-ONLY
    # — walker pure-Python struct parser surfaces execution-evidence
    # METADATA only).
    "windows_appcompat_suspicious_path",
    "windows_appcompat_temp_execution",
    "windows_appcompat_recent_baseline",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "windows_appcompat_suspicious_path",
    "windows_appcompat_temp_execution",
    "windows_appcompat_recent_baseline",
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
        "'windows_appcompat_suspicious_path', "
        "'windows_appcompat_temp_execution', "
        "'windows_appcompat_recent_baseline'"
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
