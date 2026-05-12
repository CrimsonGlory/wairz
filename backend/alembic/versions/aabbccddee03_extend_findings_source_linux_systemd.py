"""extend findings.source CHECK with linux_systemd_* (Phase ι.B.D — SECOND LINUX)

Revision ID: aabbccddee03
Revises: aabbccddee02
Create Date: 2026-05-12 17:30:00.000000

Phase ι.B.D — extends ``ck_findings_source`` with FIVE new source
values so the SECOND LINUX walker (ι.B.C systemd unit-file) can
persist operator-actionable findings as Finding rows. SECOND non-
Windows cross-stack alignment commit (Rule #25 single-slice exception
#2, Rule-of-Twenty — ι.A.D was Rule-of-Nineteen, the first Linux
source family).

NEW SOURCES:

- ``linux_systemd_suspicious_path`` — emitted for units whose
  ExecStart= or WorkingDirectory= references a writable directory
  (/tmp, /var/tmp, /dev/shm, /run/shm, /home). T1543.002 (Create or
  Modify System Process: Systemd Service) — APT36 (Aug 2025),
  FIRESTARTER (CISA 2026), Quasar Linux QLNX (May 2026) canonical
  TTP. Persona-E HIGH.

- ``linux_systemd_obfuscated_exec`` — emitted for units whose
  ExecStart= contains a long /bin/sh -c invocation (>120 chars), an
  eval-like pattern, a curl|sh / wget|sh pipeline, or an embedded
  base64-decoded blob. T1027 (Obfuscated Files or Information).
  Persona-E HIGH.

- ``linux_systemd_socket_unusual_port`` — emitted for [Socket] units
  whose ListenStream= or ListenDatagram= binds a numeric port
  outside the well-known set. T1571 (Non-Standard Port). Persona-E
  MEDIUM.

- ``linux_systemd_root_minimal_deps`` — emitted for service units
  that run as User=root (or unset) AND declare an empty Requires=.
  Common rootkit pattern. Persona-E MEDIUM (ambiguous — many
  legitimate baseline services match).

- ``linux_systemd_enabled_outside_standard`` — emitted for units
  whose [Install] WantedBy= or RequiredBy= references a target
  outside the standard 17-target set. Adversary frequently defines
  custom targets for staging. T1543.002 supporting indicator.
  Persona-E MEDIUM.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for any linux_systemd_* (ι.B.D ships first consumer).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``fb4c5d6e7f8a_extend_findings_source_linux_journald.py``
(ι.A.D) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Nineteen → Rule-of-
Twenty):

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
- fb4c5d6e7f8a ι.A.D (linux_journald_*) → Rule-of-Nineteen
- THIS ι.B.D (linux_systemd_*) → Rule-of-Twenty — SECOND non-
  Windows source family (and second Rule-of-N application to a
  Linux walker)

Backend ``LinuxFindingSource`` Literal in ``app/schemas/finding.py``
gets EXTENDED in this same commit with the 5 new values (sibling
sources to the journald block introduced in ι.A.D); typed module-
level constants ``_SOURCE_SYSTEMD_*`` in ``finding_service.py``
ensure compile-check coverage.

Revision ID ``aabbccddee03`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from ι.B.B head ``aabbccddee02``.
"""

from alembic import op


revision: str = "aabbccddee03"
down_revision: str | None = "aabbccddee02"
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
    # Phase ι.B.D additions — SECOND LINUX source family. Systemd
    # unit-file walker emit sources:
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
)


_REMOVED_IN_THIS_REVISION: tuple[str, ...] = (
    "linux_systemd_suspicious_path",
    "linux_systemd_obfuscated_exec",
    "linux_systemd_socket_unusual_port",
    "linux_systemd_root_minimal_deps",
    "linux_systemd_enabled_outside_standard",
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
        "'linux_systemd_suspicious_path', "
        "'linux_systemd_obfuscated_exec', "
        "'linux_systemd_socket_unusual_port', "
        "'linux_systemd_root_minimal_deps', "
        "'linux_systemd_enabled_outside_standard'"
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
