"""extend findings.source CHECK with windows_mbr_* / windows_vbr_* (Phase θ.E.D)

Revision ID: cd0e1f2a3b4c
Revises: bc0d1e2f3a4b
Create Date: 2026-05-12 10:00:00.000000

Phase θ.E.D — extends ``ck_findings_source`` with TWO new source
values so the MBR/VBR walker (θ.E.C) can persist boot-sector
correlation findings as Finding rows:

- ``windows_mbr_bootkit`` — emitted by
  ``emit_mbr_vbr_findings_from_walk`` for every ``WindowsMbrVbrSector``
  row with sector_kind=mbr AND known_bootkit_match populated
  (TDL4 / Olmasco / Mebroot / Petya / BlackEnergy). Confidence tier
  mapping:

  - HIGH (Confidence.high) — known_bootkit_match populated.
    Direct named-bootkit fingerprint hit; T1542.003 Pre-OS Boot:
    Bootkit signal at the BIOS / legacy boot layer.

- ``windows_vbr_anomaly`` — emitted for every ``WindowsMbrVbrSector``
  row with sector_kind=vbr_* AND (known_bootkit_match populated OR
  bootcode_signature_match is NULL AND anomaly_count >= 2).
  Confidence tier mapping:

  - HIGH (Confidence.high) — known_bootkit_match populated (named
    VBR bootkit — Mebroot VBR variant, Olmasco VBR variant).
  - MEDIUM (Confidence.medium) — bootcode_signature_match is NULL
    AND >=2 anomaly flags raised (modified VBR without a named
    bootkit match — supply-chain compromise candidate).

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_mbr_bootkit / windows_vbr_anomaly
    -- (θ.E.D ships first consumer; emit-hook extension ships in θ.E.E).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``9c0d1e2f3a4b_extend_findings_source_esp.py`` (θ.C.D) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Seventeen):

- 7079b4d (2026-05-06 base)
- ee2abd9 β.12a (windows_authenticode + windows_dbx_revoked)
- f70c2e1 γ.7 (windows_registry_persistence + windows_inf +
                windows_driver_imports)
- 20ea228 δ.8 (windows_r2r_stomp + windows_il_capa)
- 5466644 ε.1.b.4 (3 EVTX-related)
- da71afa ζ.1 (windows_amcache_install)
- a6be708 ζ.2.C (windows_prefetch_execution)
- 04a3c55 ζ.3.C (2 SRUM-related) → Rule-of-Eight
- ac98e55 η.E (windows_powershell_script_block) → Rule-of-Nine
- e149dcf η.B.D (windows_scheduled_task_persistence) → Rule-of-Ten
- fd7cd23 η.C.D (windows_lnk_abnormal_target) → Rule-of-Eleven
- 66bd8d6 η.A.D (windows_mft_*) → Rule-of-Twelve
- η.D.D (windows_byovd_driver) → Rule-of-Thirteen
- a4d5f45 θ.A.D (windows_bcd_*) → Rule-of-Fourteen
- 383ffe9 θ.B.E (windows_wmi_persistence) → Rule-of-Fifteen
- c0d5795 θ.C.D (windows_esp_*) → Rule-of-Sixteen
- THIS θ.E.D (windows_mbr_bootkit + windows_vbr_anomaly)
  → Rule-of-Seventeen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants
in ``finding_service.py`` (``_SOURCE_MBR_BOOTKIT`` /
``_SOURCE_VBR_ANOMALY``) compile-check.

Revision ID ``cd0e1f2a3b4c`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.E.B head ``bc0d1e2f3a4b``.
"""

from alembic import op


revision: str = "cd0e1f2a3b4c"
down_revision: str | None = "bc0d1e2f3a4b"
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
    # Phase θ.E.D additions — MBR/VBR walker emit sources:
    "windows_mbr_bootkit",
    "windows_vbr_anomaly",
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
        "WHERE source IN ('windows_mbr_bootkit', 'windows_vbr_anomaly')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v not in ("windows_mbr_bootkit", "windows_vbr_anomaly")
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
