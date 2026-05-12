"""extend findings.source CHECK with windows_byovd_driver (Phase η.D.D)

Revision ID: a8b9c0d1e2f3
Revises: 3b5c4d6e7f8a
Create Date: 2026-05-11 11:00:00.000000

Phase η.D.D — extends ``ck_findings_source`` with ONE new source value
so the LOLDrivers BYOVD lookup (η.D.C) can persist driver fingerprint
matches as Finding rows:

- ``windows_byovd_driver`` — emitted by
  ``emit_byovd_findings_from_driver`` for every Windows driver blob
  whose SHA256 (or Authenticode hash) matches a LOLDrivers record.
  Confidence tier mapping is heuristic-driven by category + CVE:

  - HIGH (Confidence.high) — category=``malicious``, OR category=
    ``vulnerable driver`` AND ≥1 CVE associated. The malicious-driver
    case is unambiguous compromise; the CVE-associated case carries
    public-known-exploit weight beyond a stale-driver flag.
  - MEDIUM (Confidence.medium) — category=``vulnerable driver`` with
    no CVE association. Surfaces stale-driver BYOVD risk without
    over-triaging legitimate-but-stale embedded firmware.

  Per intake style: ONE Literal value covers all tiers (tier metadata
  goes into the finding's confidence + evidence fields, not into
  separate Literal values per tier).

Live audit at migration-authoring time (2026-05-11):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_byovd_driver (η.D.D ships first consumer; emit-
    -- hook extension ships in this same commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``a7b8c9d0e1f2_extend_findings_source_lnk.py`` (η.C.D) and
``3b5c4d6e7f8a_extend_findings_source_mft.py`` (η.A.D) — same
drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES`` tuple.
Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import it
via importlib and assert agreement with the frontend ``FindingSource``
union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Twelve → Rule-of-Thirteen):

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
- 66bd8d6 η.A.D (windows_mft_ads_hidden_content +
                windows_mft_timestomping) → Rule-of-Twelve
- THIS η.D.D (windows_byovd_driver) → Rule-of-Thirteen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_BYOVD_DRIVER``) compile-checks.

Revision ID ``a8b9c0d1e2f3`` was pre-validated FREE against the
78-revision versions tree before authoring (Rule #19 evidence-first).
Chains from η.A.D head ``3b5c4d6e7f8a``.
"""

from alembic import op


revision: str = "a8b9c0d1e2f3"
down_revision: str | None = "3b5c4d6e7f8a"
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
    # Phase η.D.D addition — LOLDrivers BYOVD fingerprint emit source:
    "windows_byovd_driver",
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
        "WHERE source = 'windows_byovd_driver'"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v != "windows_byovd_driver"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
