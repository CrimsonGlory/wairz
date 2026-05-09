"""extend findings.source CHECK with windows_amcache_install (Phase ζ.1)

Revision ID: f2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-05-09 18:30:00.000000

Phase ζ.1 — extends ``ck_findings_source`` with one new source value
so the Amcache finding-emit hook can persist program-installation
history rows the operator can triage:

- ``windows_amcache_install`` — emitted by ``finding_service.emit_amcache_findings_from_walk``
  for ``InventoryApplicationFile`` entries on parsed AmCache.hve
  registry extracts. Persona-E program-installation history surfacing.
  γ.4 already walks AmCache.hve as part of the registry hive walker;
  ζ.1 layers Finding emission on top WITHOUT introducing a new walker
  service (no Rule #39 inner/outer/safe triplet needed at this layer
  — the emit hook reads from existing ``windows_registry_extracts``
  rows where ``hive_type == 'AmCache'``).

  Confidence tier mapping:
  - LOW review candidate (baseline) → Confidence.low — installation
    history is not malicious by itself; threat-feed correlation
    (e.g. SHA1 against a known-malicious-binary database) is deferred
    to a future ζ.X phase.
  - MEDIUM (heuristic match against curated suspicious-product list)
    — deferred.
  - HIGH (threat-feed match) — deferred.

Live audit at migration-authoring time (2026-05-09, before this
migration applies):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_amcache_install (the ζ.1 emit hook is the
    -- first consumer of this source tag; service ships with this
    -- CHECK extension)

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.

Mirrors ``e1a2b3c4d5e6_extend_findings_source_windows_event_log.py``
(ε.1.b.4 recreator) — same drop-and-recreate shape with the extended
``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed under that exact name
so ``test_finding_source_alignment._load_db_source_values`` can
import it via importlib and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror lands in this same commit per Rule #25 single-slice
exception #2 (cross-stack alignment — Rule-of-Six now: 7079b4d +
ee2abd9 β.12a + f70c2e1 γ.7 + 20ea228 δ.8 + 5466644 ε.1.b.4 +
this ζ.1 commit):
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains the
  one value.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets a matching entry per CLAUDE.md Rule #9 exhaustivity.

Backend ``WindowsFindingSource`` Literal in ``app/schemas/finding.py``
is also extended in this same commit so the typed source constant in
``finding_service.py`` (``_SOURCE_AMCACHE_INSTALL``) compile-checks
against the new value.

Revision ID ``f2b3c4d5e6f7`` was pre-validated FREE against the
63-revision versions tree before authoring per
``.mex/patterns/add-alembic-migration.md``.
"""

from alembic import op


revision: str = "f2b3c4d5e6f7"
down_revision: str | None = "f1a2b3c4d5e6"
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
    # upgrade and downgrade (ζ.1 emit hook persisted findings), remap
    # them to 'manual' so the prior CHECK accepts the row. Same shape
    # as e1a2b3c4d5e6's downgrade.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ('windows_amcache_install')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES if v != "windows_amcache_install"
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
