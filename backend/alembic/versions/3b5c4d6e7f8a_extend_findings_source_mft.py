"""extend findings.source CHECK with windows_mft_ads_hidden_content + windows_mft_timestomping (Phase η.A.D)

Revision ID: 3b5c4d6e7f8a
Revises: 2a4b3c5d6e7f
Create Date: 2026-05-11 01:30:00.000000

Phase η.A.D — extends ``ck_findings_source`` with TWO new source values
so the MFT walker (η.A.C) can persist hidden-content + anti-forensics
candidate findings as Finding rows:

- ``windows_mft_ads_hidden_content`` — emitted by
  ``emit_mft_findings_from_walk`` for every ``WindowsMftRecord`` row
  whose ads_streams JSONB carries one or more named ADS streams with
  non-trivial size (>1 KB excluding Zone.Identifier ~100-byte MOTW
  tag). Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — ADS size > 16 KB. ProcessHollower /
    Pegasus / generic AV-evasion drop pattern; the hidden stream
    is large enough to carry payload code.
  - MEDIUM (Confidence.medium) — ADS size 1 KB – 16 KB. Suspicious
    metadata or small payload; benign Zone.Identifier is excluded
    by the >1 KB threshold.

- ``windows_mft_timestomping`` — emitted by
  ``emit_mft_findings_from_walk`` for every ``WindowsMftRecord`` row
  whose $SI mtime < $FN mtime. timestomp.exe / SetMACE / SetMACE.ps1
  / PowerShell SetCreation pattern. Confidence tier mapping:

  - MEDIUM (Confidence.medium) — single timestomp pair detected
    ($SI mtime < $FN mtime).
  - HIGH (Confidence.high) — ALL FOUR $SI timestamps older than
    ALL FOUR $FN timestamps. timestomp.exe rewrites the full $SI
    tuple; matching all four pairs is the strongest signal.

Per intake style: ONE Literal value per detection pattern (the tier
metadata goes into the finding's confidence + evidence fields, not
into separate Literal values per tier).

Live audit at migration-authoring time (2026-05-11):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_mft_ads_hidden_content and 0 for
    -- windows_mft_timestomping (η.A.D ships first consumer; emit-hook
    -- extension ships in this same commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``a7b8c9d0e1f2_extend_findings_source_lnk.py`` (η.C.D) and
``a0b1c2d3e4f5_extend_findings_source_scheduled_task.py`` (η.B.D) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Eleven → Rule-of-Twelve):

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
- THIS η.A.D (windows_mft_ads_hidden_content +
              windows_mft_timestomping) → Rule-of-Twelve

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants in
``finding_service.py`` (``_SOURCE_MFT_ADS_HIDDEN_CONTENT`` +
``_SOURCE_MFT_TIMESTOMPING``) compile-check.

Revision ID ``3b5c4d6e7f8a`` was pre-validated FREE against the
77-revision versions tree before authoring (Rule #19 evidence-first).
Chains from η.A.B head ``2a4b3c5d6e7f``.
"""

from alembic import op


revision: str = "3b5c4d6e7f8a"
down_revision: str | None = "2a4b3c5d6e7f"
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
    # Phase η.A.D additions — MFT walker emit sources:
    "windows_mft_ads_hidden_content",
    "windows_mft_timestomping",
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
        "('windows_mft_ads_hidden_content', 'windows_mft_timestomping')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v not in (
            "windows_mft_ads_hidden_content",
            "windows_mft_timestomping",
        )
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
