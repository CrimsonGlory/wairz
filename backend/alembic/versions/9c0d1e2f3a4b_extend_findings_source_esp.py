"""extend findings.source CHECK with windows_esp_* (Phase θ.C.D)

Revision ID: 9c0d1e2f3a4b
Revises: 8b9c0d1e2f3a
Create Date: 2026-05-12 07:00:00.000000

Phase θ.C.D — extends ``ck_findings_source`` with TWO new source
values so the ESP walker (θ.C.C) can persist `.efi` chain-correlation
findings as Finding rows:

- ``windows_esp_unsigned`` — emitted by
  ``emit_esp_findings_from_walk`` for every ``WindowsEspEntry`` row
  whose authenticode_state=unsigned AND file_path matches a
  canonical OS-bootloader path (BlackLotus / Bootkitty canonical
  bootkit shape). Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — unsigned `.efi` AND
    is_known_bootloader_path (EFI/Boot/bootx64.efi,
    EFI/Microsoft/Boot/bootmgfw.efi, etc.). Strong T1542.003
    Pre-OS Boot: Bootkit signal.
  - MEDIUM (Confidence.medium) — unsigned `.efi` AND is_vendor_path
    (EFI/<vendor>/...). Could be a non-standard signed-via-shim
    layout OR a legitimate vendor utility; operator triages.

- ``windows_esp_dbx_revoked`` — emitted for every
  ``WindowsEspEntry`` row whose authenticode_state=signed_revoked
  (Authenticode chain validates BUT the leaf certificate appears in
  the β.10 DBX revocation list). Confidence tier mapping:

  - HIGH (Confidence.high) — DBX-revoked. Microsoft has explicitly
    revoked this bootloader; on a current-patch Secure Boot
    enforcement the binary would fail at load time. The revocation
    is the authoritative signal regardless of path.

Live audit at migration-authoring time (2026-05-12):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_esp_unsigned / windows_esp_dbx_revoked
    -- (θ.C.D ships first consumer; emit-hook extension ships in θ.C.E).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``6e9f7a0b1c3d_extend_findings_source_wmi.py`` (θ.B.E) —
same drop-and-recreate shape with an extended ``_NEW_SOURCE_VALUES``
tuple. Tuple is exposed under that exact name so
``test_finding_source_alignment._load_db_source_values`` can import
it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Sixteen):

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
- THIS θ.C.D (windows_esp_unsigned + windows_esp_dbx_revoked)
  → Rule-of-Sixteen

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants
in ``finding_service.py`` (``_SOURCE_ESP_UNSIGNED`` /
``_SOURCE_ESP_DBX_REVOKED``) compile-check.

Revision ID ``9c0d1e2f3a4b`` was pre-validated FREE against the
versions tree before authoring (Rule #19 evidence-first). Chains
from θ.C.B head ``8b9c0d1e2f3a``.
"""

from alembic import op


revision: str = "9c0d1e2f3a4b"
down_revision: str | None = "8b9c0d1e2f3a"
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
    # Phase θ.C.D additions — ESP walker emit sources:
    "windows_esp_unsigned",
    "windows_esp_dbx_revoked",
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
        "WHERE source IN ('windows_esp_unsigned', 'windows_esp_dbx_revoked')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v not in ("windows_esp_unsigned", "windows_esp_dbx_revoked")
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
