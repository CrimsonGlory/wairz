"""extend findings.source CHECK with SRUM sources (Phase ζ.3.C)

Revision ID: c5f6e7d8a9b0
Revises: d6e7f8a9b0c1
Create Date: 2026-05-10 17:00:00.000000

Phase ζ.3.C — extends ``ck_findings_source`` with TWO new source values
so the SRUM finding-emit hook (ζ.3.D) can persist forensic-triage rows
the operator can review:

- ``windows_srum_network_activity`` — emitted for SRUM network_data_usage
  / network_connectivity records. Surfaces "this app made network
  connections in the last 30 days" — top-tier IR signal for after-the-
  fact compromise investigation.
- ``windows_srum_application_runtime`` — emitted for SRUM
  application_resource_usage records. Surfaces "this app actually ran
  in the last 30 days" + how much CPU/IO it consumed.

Confidence tier mapping for both:
- LOW review candidate (baseline) → Confidence.low — usage history is
  not malicious by itself; threat-feed correlation is deferred to a
  future ζ.X phase. Same shape as ζ.1's windows_amcache_install +
  ζ.2.C's windows_prefetch_execution (all program-history baselines
  at LOW).

Live audit at migration-authoring time (2026-05-10):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_srum_* (the ζ.3.D emit hook is the first
    -- consumer; service ships with this CHECK extension).

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``b3c4d5e6f7a8_extend_findings_source_prefetch.py`` (ζ.2.C
recreator) — same drop-and-recreate shape with an extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Seven → Rule-of-Eight):
- 7079b4d (2026-05-06 base)
- ee2abd9 β.12a (windows_authenticode + windows_dbx_revoked)
- f70c2e1 γ.7 (windows_registry_persistence + windows_inf + windows_driver_imports)
- 20ea228 δ.8 (windows_r2r_stomp + windows_il_capa)
- 5466644 ε.1.b.4 (windows_sysmon_proc_create + windows_logon_success +
                   windows_logon_failure)
- da71afa ζ.1 (windows_amcache_install)
- a6be708 ζ.2.C (windows_prefetch_execution)
- THIS ζ.3.C (windows_srum_network_activity +
               windows_srum_application_runtime) → Rule-of-Eight

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constants in
``finding_service.py`` (``_SOURCE_SRUM_NETWORK_ACTIVITY`` +
``_SOURCE_SRUM_APPLICATION_RUNTIME``) compile-check.

Revision ID ``c5f6e7d8a9b0`` was pre-validated FREE against the
69-revision versions tree before authoring.
"""

from alembic import op


revision: str = "c5f6e7d8a9b0"
down_revision: str | None = "d6e7f8a9b0c1"
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
    # Phase ζ.3.C additions — two SRUM sources:
    "windows_srum_network_activity",
    "windows_srum_application_runtime",
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
        "'windows_srum_network_activity', "
        "'windows_srum_application_runtime'"
        ")"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v
        for v in _NEW_SOURCE_VALUES
        if v
        not in {
            "windows_srum_network_activity",
            "windows_srum_application_runtime",
        }
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
