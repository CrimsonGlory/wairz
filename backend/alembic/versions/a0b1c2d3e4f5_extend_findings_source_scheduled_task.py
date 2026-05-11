"""extend findings.source CHECK with windows_scheduled_task_persistence (Phase η.B.D)

Revision ID: a0b1c2d3e4f5
Revises: f9a0b1c2d3e4
Create Date: 2026-05-11 23:00:00.000000

Phase η.B.D — extends ``ck_findings_source`` with ONE new source value
so the Scheduled Task XML walker (η.B.C) can persist persistence-
candidate findings as ``windows_scheduled_task_persistence`` Finding
rows:

- ``windows_scheduled_task_persistence`` — emitted by
  ``emit_scheduled_task_findings_from_walk`` for every
  ``WindowsScheduledTask`` row produced by the η.B.C walker.
  Confidence tier mapping is heuristic-driven:

  - HIGH (Confidence.high) — Action contains encoded-PowerShell
    pattern (``-EncodedCommand`` / ``-enc`` / ``FromBase64String`` /
    ``Invoke-Expression`` / ``[char[]]`` / ``DownloadString`` /
    ``IEX``). Qakbot pattern.
  - MEDIUM (Confidence.medium) — RunLevel=HighestAvailable AND
    non-system Author (Author NOT prefixed by "Microsoft").
  - LOW (Confidence.low) — baseline review-candidate row for every
    persistent task.

Per intake D5-style discipline: ONE Literal value covers all 3 tiers
(the tier metadata goes into the finding's confidence + evidence
fields, not into separate Literal values per tier).

Live audit at migration-authoring time (2026-05-11):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_scheduled_task_persistence (η.B.D ships first
    -- consumer; emit-hook extension ships in this same commit).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``e7f8a9b0c1d2_extend_findings_source_powershell.py`` (η.E
recreator) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Nine → Rule-of-Ten):

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
- THIS η.B.D (windows_scheduled_task_persistence) → Rule-of-Ten

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_SCHEDULED_TASK_PERSISTENCE``)
compile-checks.

Revision ID ``a0b1c2d3e4f5`` was pre-validated FREE against the
73-revision versions tree before authoring (Rule #19 evidence-first).
"""

from alembic import op


revision: str = "a0b1c2d3e4f5"
down_revision: str | None = "f9a0b1c2d3e4"
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
    # Phase η.B.D addition — Scheduled Task persistence source:
    "windows_scheduled_task_persistence",
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
        "WHERE source = 'windows_scheduled_task_persistence'"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v != "windows_scheduled_task_persistence"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
