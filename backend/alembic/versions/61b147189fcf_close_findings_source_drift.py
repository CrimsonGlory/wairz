"""close findings.source CHECK ↔ FindingSource union drift

Revision ID: 61b147189fcf
Revises: c1d2e3f4a5b6
Create Date: 2026-05-06

Closes intake ``findings-source-tag-drift-ci-2026-05-04`` by reconciling
the ``ck_findings_source`` CHECK constraint with the frontend
``FindingSource`` TypeScript union.

Net change in this migration:

- ADD ``security_review`` — emitted by
  ``services/assessment_service.py`` via ``ASSESSMENT_SOURCE`` constant
  through ``_create_finding`` (line 270).  Pre-fix the DB CHECK rejected
  every assessment-service finding write with an IntegrityError; 0
  production rows exist for this source today, confirming the path
  hasn't been exercised since the CHECK was tightened (or its callers
  raise on the IntegrityError, which propagates as a 500 to the user).
- ADD ``ai_discovered`` — default source for MCP ``add_finding`` tool
  at ``ai/tools/reporting.py:242``.  Same silent-rejection footprint as
  ``security_review`` — 0 rows.
- REMOVE ``fuzzing_scan`` — legacy duplicate of ``fuzzing``.  0 rows in
  production at migration time, 0 SET sites in ``backend/app/``.

Frontend reconciliation lands in the same commit:
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains 6
  sources already in the DB (``attack_surface``, ``clamav_scan``,
  ``cwe_checker``, ``hardware_firmware_graph``, ``uefi_scan``,
  ``vt_scan``) and drops the dead ``known_good_scan`` entry (no SET
  site anywhere in the codebase; ``run_known_good_scan`` results
  persist with ``source='security_audit'`` via ``_persist_finding``).
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets matching entries per CLAUDE.md Rule #9 exhaustivity.

Mirrors the migration shape established by
``a9f4e9cdabe2_add_unpack_audit_source.py``.
"""
from typing import Sequence, Union

from alembic import op


revision: str = '61b147189fcf'
down_revision: Union[str, None] = 'c1d2e3f4a5b6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


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
    # Newly admitted (intake findings-source-tag-drift-ci-2026-05-04):
    "security_review",
    "ai_discovered",
    # Removed: "fuzzing_scan" (legacy duplicate of "fuzzing"; 0 rows, 0 SET sites)
)


_OLD_SOURCE_VALUES: tuple[str, ...] = (
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
    "fuzzing_scan",
    "unpack_audit",
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def upgrade() -> None:
    # Defensive backfill: re-tag any 'fuzzing_scan' rows to 'fuzzing'
    # before the CHECK forbids the legacy value. Production is 0 rows
    # at migration authoring time, but a row could land between author
    # and apply on a long-running deploy.
    op.execute("UPDATE findings SET source = 'fuzzing' WHERE source = 'fuzzing_scan'")

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", _NEW_SOURCE_VALUES),
    )


def downgrade() -> None:
    # Defensive: rows tagged 'security_review' or 'ai_discovered' must
    # be remapped to a value the prior CHECK accepts before we re-tighten.
    # Pick 'manual' (legacy default) for both — same severity-neutral
    # bucket the unpack-audit downgrade would have used.
    op.execute("UPDATE findings SET source = 'manual' WHERE source IN ('security_review', 'ai_discovered')")

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", _OLD_SOURCE_VALUES),
    )
