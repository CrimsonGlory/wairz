"""extend findings.source CHECK with windows_prefetch_execution (Phase ζ.2.C)

Revision ID: b3c4d5e6f7a8
Revises: b4c5d6e7f8a9
Create Date: 2026-05-10 15:00:00.000000

Phase ζ.2.C — extends ``ck_findings_source`` with one new source value
so the Prefetch finding-emit hook (ζ.2.D) can persist application-execution
history rows the operator can triage:

- ``windows_prefetch_execution`` — emitted by
  ``finding_service.emit_prefetch_findings_from_walk`` for every
  ``WindowsPrefetchRecord`` row produced by the ζ.2.B walker. Persona-E
  application-execution-history surfacing.

  Confidence tier mapping:
  - LOW review candidate (baseline) → Confidence.low — execution history
    is not malicious by itself; threat-feed correlation (file path / hash
    against a known-malicious-binary database) is deferred to a future
    ζ.X phase. Same shape as ζ.1's windows_amcache_install (also
    installation-history baseline; deferred threat correlation).
  - MEDIUM (heuristic match against curated suspicious-binary list) —
    deferred.
  - HIGH (threat-feed match) — deferred.

Live audit at migration-authoring time (2026-05-10):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_prefetch_execution (the ζ.2.D emit hook is
    -- the first consumer of this source tag; service ships with this
    -- CHECK extension)

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``f2b3c4d5e6f7_extend_findings_source_amcache.py`` (ζ.1
recreator) — same drop-and-recreate shape with the extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Six → Rule-of-Seven now:
7079b4d + ee2abd9 β.12a + f70c2e1 γ.7 + 20ea228 δ.8 + 5466644 ε.1.b.4 +
da71afa ζ.1 + this ζ.2.C commit):
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains the
  one value.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets a matching entry per CLAUDE.md Rule #9 exhaustivity.

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_PREFETCH_EXECUTION``) compile-checks
against the new value.

Revision ID ``b3c4d5e6f7a8`` was pre-validated FREE against the
67-revision versions tree before authoring per
``.mex/patterns/add-alembic-migration.md``.
"""

from alembic import op


revision: str = "b3c4d5e6f7a8"
down_revision: str | None = "b4c5d6e7f8a9"
branch_labels: str | None = None
depends_on: str | None = None


# Allowlist tuple — exposed under ``_NEW_SOURCE_VALUES`` so the
# cross-stack alignment test can importlib-load the latest recreator
# and assert agreement with the frontend FindingSource union.
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
    # Phase δ.8 additions:
    "windows_r2r_stomp",
    "windows_il_capa",
    # Phase ε.1.b.4 additions:
    "windows_sysmon_proc_create",
    "windows_logon_success",
    "windows_logon_failure",
    # Phase ζ.1 additions:
    "windows_amcache_install",
    # Phase ζ.2.C additions:
    "windows_prefetch_execution",
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
    # Defensive: if any rows were tagged with the new source between
    # upgrade and downgrade (ζ.2.D emit hook persisted findings), remap
    # them to 'manual' so the prior CHECK accepts the row. Same shape
    # as f2b3c4d5e6f7's downgrade.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ('windows_prefetch_execution')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES if v != "windows_prefetch_execution"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
