"""extend findings.source CHECK with windows_bcd_suspicious_path + windows_bcd_testsigning_enabled (Phase θ.A.D)

Revision ID: 3b6c4d5e6f7a
Revises: 2a5b3c4d5e6f
Create Date: 2026-05-12 03:00:00.000000

Phase θ.A.D — extends ``ck_findings_source`` with TWO new source values
so the BCD walker (θ.A.C) can persist suspicious-bootloader-path +
testsigning-enabled findings as Finding rows:

- ``windows_bcd_suspicious_path`` — emitted by
  ``emit_bcd_findings_from_walk`` for every ``WindowsBcdEntry`` row
  whose anomaly_flags.suspicious_path is True (image_path NOT under
  any Microsoft-vetted prefix like Windows\\, Boot\\, EFI\\Microsoft\\).
  Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — suspicious_path AND
    (non_microsoft_description OR testsigning_enabled). The
    combination is a strong bootkit signal — BlackLotus, Bootkitty,
    CosmicStrand pattern of replacing the bootloader path with a
    non-Microsoft binary that won't validate against Authenticode.
  - MEDIUM (Confidence.medium) — suspicious_path alone. Could be a
    legitimate non-Microsoft OS (Ubuntu, FreeBSD); operator
    triages by cross-referencing the description.

- ``windows_bcd_testsigning_enabled`` — emitted by
  ``emit_bcd_findings_from_walk`` for every ``WindowsBcdEntry`` row
  whose anomaly_flags.testsigning_enabled is True (BCD element
  0x16000010 set). Confidence tier mapping:

  - HIGH (Confidence.high) — testsigning_enabled AND
    (no_integrity_checks OR nx_disabled). Multiple security-relevant
    policy bits flipped at once is the canonical BYOVD-precursor
    shape.
  - MEDIUM (Confidence.medium) — testsigning_enabled alone. Could be
    a developer / driver-debug system; operator triages by
    cross-referencing the host context.

Per intake style: ONE Literal value per detection pattern (the tier
metadata goes into the finding's confidence + evidence fields).

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_bcd_suspicious_path and 0 for
    -- windows_bcd_testsigning_enabled (θ.A.D ships first consumer; emit-hook
    -- extension ships in θ.A.E).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``3b5c4d6e7f8a_extend_findings_source_mft.py`` (η.A.D) and
``8da9b0c1d2e3_extend_findings_source_byovd.py`` (η.D.D) — same
drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Thirteen → Rule-of-Fourteen):

- 7079b4d (2026-05-06 base)
- ee2abd9 β.12a (windows_authenticode + windows_dbx_revoked)
- f70c2e1 γ.7 (windows_registry_persistence + windows_inf +
                windows_driver_imports)
- 20ea228 δ.8 (windows_r2r_stomp + windows_il_capa)
- 5466644 ε.1.b.4 (windows_sysmon_proc_create + windows_logon_success +
                   windows_logon_failure)
- da71afa ζ.1 (windows_amcache_install)
- a6be708 ζ.2.C (windows_prefetch_execution)
- 04a3c55 ζ.3.C (windows_srum_network_activity +
                 windows_srum_application_runtime)
- ac98e55 η.E (windows_powershell_script_block) → Rule-of-Nine
- e149dcf η.B.D (windows_scheduled_task_persistence) → Rule-of-Ten
- fd7cd23 η.C.D (windows_lnk_abnormal_target) → Rule-of-Eleven
- 66bd8d6 η.A.D (windows_mft_ads_hidden_content + windows_mft_timestomping)
  → Rule-of-Twelve
- ?? η.D.D (windows_byovd_driver) → Rule-of-Thirteen
- THIS θ.A.D (windows_bcd_suspicious_path +
              windows_bcd_testsigning_enabled) → Rule-of-Fourteen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants in
``finding_service.py`` (``_SOURCE_BCD_SUSPICIOUS_PATH`` +
``_SOURCE_BCD_TESTSIGNING_ENABLED``) compile-check.

Revision ID ``3b6c4d5e6f7a`` was pre-validated FREE against the
82-revision versions tree before authoring (Rule #19 evidence-first).
Chains from θ.A.B head ``2a5b3c4d5e6f``.
"""

from alembic import op


revision: str = "3b6c4d5e6f7a"
down_revision: str | None = "2a5b3c4d5e6f"
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
    # Phase θ.A.D additions — BCD walker emit sources:
    "windows_bcd_suspicious_path",
    "windows_bcd_testsigning_enabled",
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
        "WHERE source IN "
        "('windows_bcd_suspicious_path', 'windows_bcd_testsigning_enabled')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v not in (
            "windows_bcd_suspicious_path",
            "windows_bcd_testsigning_enabled",
        )
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
