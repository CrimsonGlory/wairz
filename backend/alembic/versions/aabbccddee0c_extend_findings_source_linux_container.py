"""extend findings.source CHECK with linux_container_* (Phase ι.E.D — THIRD LINUX)

Revision ID: aabbccddee0c
Revises: aabbccddee0b
Create Date: 2026-05-12 17:00:00.000000

Phase ι.E.D — extends ``ck_findings_source`` with FIVE new source
values so the FIFTH ι walker (THIRD LINUX — ι.E.C container-runtime
artefact metadata) can persist operator-actionable findings as Finding
rows. FIFTH ι cross-stack alignment commit AND the THIRD LINUX source
family extension (ι.A.D journald + ι.B.D systemd were Linux; ι.C.D ETW
+ ι.D.D EFS were Windows).

Rule #25 single-slice exception #2, Rule-of-Twenty-Two → Rule-of-
Twenty-Three.

NEW SOURCES:

- ``linux_container_privileged_mode`` — emitted when HostConfig.Privileged
  is true OR OCI-runtime equivalent. T1610 Deploy Container — privileged
  is the canonical foothold + escalation primitive. Persona-E HIGH.

- ``linux_container_dangerous_capability`` — emitted when CapAdd contains
  one of: SYS_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, DAC_READ_SEARCH,
  DAC_OVERRIDE, NET_ADMIN, NET_RAW, SETUID, SETGID, MKNOD, AUDIT_WRITE.
  T1611 Escape to Host. Persona-E HIGH.

- ``linux_container_unsafe_host_mount`` — emitted when a bind mount source
  is under one of: /, /etc, /proc, /sys, /dev, /var/run/docker.sock,
  /var/run/containerd, /run/docker.sock, /home, /root. T1611 escape
  pathway. The 2025 runc CVE cluster (CVE-2025-31133 / -52565 / -52881)
  all exploit shapes that this catches. Persona-E HIGH.

- ``linux_container_unconfined_security`` — emitted when seccomp=unconfined
  AND/OR AppArmorProfile=unconfined. Removes the kernel-syscall filter
  that blocks container-escape primitives. Persona-E MEDIUM.

- ``linux_container_unknown_registry_image`` — emitted when image_repository
  is NOT in the major-known allowlist (docker.io, gcr.io,
  mcr.microsoft.com, quay.io, public.ecr.aws, registry.access.redhat.com,
  registry.redhat.io, ghcr.io, registry.k8s.io, k8s.gcr.io, nvcr.io).
  Could be private/legitimate or attacker-controlled. Persona-E MEDIUM
  baseline review.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any linux_container_* (ι.E.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``aabbccddee09_extend_findings_source_windows_efs.py`` (ι.D.D)
— same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import it
via importlib and assert agreement with the frontend ``FindingSource``
union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twenty-Two → Rule-of-
Twenty-Three):

- ι.A.D linux_journald_* → Rule-of-Nineteen (FIRST non-Windows family)
- ι.B.D linux_systemd_* → Rule-of-Twenty (SECOND non-Windows)
- ι.C.D windows_etl_* → Rule-of-Twenty-One (FIRST ι Windows)
- ι.D.D windows_efs_* → Rule-of-Twenty-Two (SECOND ι Windows)
- THIS ι.E.D linux_container_* → Rule-of-Twenty-Three (THIRD LINUX,
  FIFTH ι overall)

Backend ``LinuxFindingSource`` Literal in ``app/schemas/finding.py``
gets EXTENDED in this same commit with the 5 new values; typed
module-level constants ``_SOURCE_CONTAINER_*`` in ``finding_service.py``
ensure compile-check coverage.

Revision ID ``aabbccddee0c`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.E.B head ``aabbccddee0b``.
"""

from alembic import op

revision: str = "aabbccddee0c"
down_revision: str | None = "aabbccddee0b"
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
    # Phase ι.A.D — FIRST LINUX source family. Journald walker emit sources:
    "linux_journald_priority_critical",
    "linux_journald_oom_killer",
    "linux_journald_suspicious_unit",
    "linux_journald_log_clear",
    "linux_journald_selinux_denied",
    # Phase ι.B.D — SECOND LINUX source family. Systemd walker emit sources:
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
    # Phase ι.C.D — FIRST ι Windows extension. ETW .etl trace-log walker:
    "windows_etl_kernel_proc_after_clear",
    "windows_etl_provider_disabled",
    "windows_etl_unusual_provider",
    "windows_etl_non_microsoft_in_diagtrack",
    # Phase ι.D.D — SECOND ι Windows extension. EFS DDF/DRF metadata
    # (PARSE-ONLY — wairz NEVER decrypts the FEK, NEVER invokes DPAPI):
    "windows_efs_orphaned_drf",
    "windows_efs_unusual_recovery_agent",
    "windows_efs_domain_admin_in_ddf",
    "windows_efs_large_drf",
    # Phase ι.E.D additions — THIRD LINUX source family (FIFTH ι walker
    # overall). Container runtime artefact metadata walker emit sources
    # — T1610 Deploy Container / T1611 Escape to Host / T1612 Build
    # Image on Host coverage.
    "linux_container_privileged_mode",
    "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount",
    "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "linux_container_privileged_mode",
    "linux_container_dangerous_capability",
    "linux_container_unsafe_host_mount",
    "linux_container_unconfined_security",
    "linux_container_unknown_registry_image",
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
        "'linux_container_privileged_mode', "
        "'linux_container_dangerous_capability', "
        "'linux_container_unsafe_host_mount', "
        "'linux_container_unconfined_security', "
        "'linux_container_unknown_registry_image'"
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
