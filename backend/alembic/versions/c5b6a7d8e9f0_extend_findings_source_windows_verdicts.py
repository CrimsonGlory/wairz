"""extend findings.source CHECK with windows_authenticode + windows_dbx_revoked

Revision ID: c5b6a7d8e9f0
Revises: b2a3c4d5e6f7
Create Date: 2026-05-08

Phase β.12a — extends ``ck_findings_source`` with two new verdict-bearing
sources so Phase β.4 (Authenticode chain) and Phase β.7 (offline DBX
revocation) verdicts surface as ``Finding`` rows the operator can triage
alongside CVE / SBOM / kernel findings:

- ``windows_authenticode`` — emitted by the Phase β.8 background runner
  when ``verify_pe_file`` produces a ``chain_status`` of ``revoked`` /
  ``never_valid`` (high severity) or ``unknown`` for a PE that's
  ``signed=True`` (medium severity).
- ``windows_dbx_revoked`` — emitted when ``match_dbx_revocation`` flags
  a PE's leaf serial as revoked (critical severity).

Live audit at migration-authoring time (2026-05-08, before this
migration applies):

    SELECT source, COUNT(*) FROM findings GROUP BY source ORDER BY 2 DESC;
    -- 0 rows for windows_authenticode / windows_dbx_revoked

Zero existing rows ⇒ "extend CHECK" path; no defensive backfill needed.
The Pydantic ``WindowsFindingSource`` Literal extension and the runner-
side emit-from-verdict helper land in subsequent commits (β.12b/β.12c).

Mirrors ``61b147189fcf_close_findings_source_drift.py`` (the most recent
recreator of ``ck_findings_source``) — same shape: drop-and-recreate the
CHECK with the extended ``_NEW_SOURCE_VALUES`` tuple. Tuple is exposed
under that exact name so ``test_finding_source_alignment._load_db_source_values``
can import it via ``importlib`` and assert agreement with the frontend
``FindingSource`` union (Rule #21 mirror discipline).

Frontend mirror (Rule #21) lands in this same commit:
- ``frontend/src/types/index.ts`` ``FindingSource`` union gains
  ``windows_authenticode`` + ``windows_dbx_revoked``.
- ``frontend/src/constants/statusConfig.ts`` ``FINDING_SOURCE_CONFIG``
  gets matching entries per CLAUDE.md Rule #9 exhaustivity.
"""
from typing import Sequence, Union

from alembic import op


revision: str = 'c5b6a7d8e9f0'
down_revision: Union[str, None] = 'b2a3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Allowlist tuple — exposed under `_NEW_SOURCE_VALUES` so the cross-stack
# alignment test can importlib-load the latest recreator and assert
# agreement with the frontend FindingSource union.
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
    # Phase β.12a additions:
    "windows_authenticode",
    "windows_dbx_revoked",
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
    # Defensive: if any rows were tagged with the new sources between
    # upgrade and downgrade (production runner emitted findings), remap
    # them to 'manual' so the prior CHECK accepts the row. Same shape as
    # 61b147189fcf's downgrade for security_review / ai_discovered.
    op.execute(
        "UPDATE findings SET source = 'manual' "
        "WHERE source IN ('windows_authenticode', 'windows_dbx_revoked')"
    )

    op.drop_constraint("ck_findings_source", "findings", type_="check")
    prior = tuple(
        v for v in _NEW_SOURCE_VALUES
        if v not in ("windows_authenticode", "windows_dbx_revoked")
    )
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        _in_list_sql("source", prior),
    )
