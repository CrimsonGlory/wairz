"""audit-2026-05-04 F-C-05: add CHECK constraints on status / mode / enum-like columns

Revision ID: 89007f64cfb0
Revises: d2e3f4a5b6c7
Create Date: 2026-05-07

audit-2026-05-04 Stream C finding F-C-05 measured 12 production
status / mode / enum-like columns lacking DB CHECK constraints — the
companion to the findings + sbom enums already constrained in
revision ``54c8864fbe0c``. CLAUDE.md Rule #33 (c) says status / enum-
like columns get BOTH a Pydantic Literal AND a DB CHECK; this is the
DB half for these columns.

Rule #19 evidence-first audit (live SQL inspection 2026-05-07): all
13 constraints below ALREADY EXIST on the production database from a
prior, since-removed migration file — only the alembic chain is
missing the CHECK-creating step. ``DROP CONSTRAINT IF EXISTS`` before
each create makes the upgrade safe to apply against both the live DB
(idempotent re-create) and a fresh CI/test DB (clean create).

Allowlists below mirror the live constraint definitions exactly:

- ``projects.status``: ``{created, unpacking, ready, error}`` —
  matches firmware router + arq_worker + device_service writes.
- ``security_reviews.status`` / ``review_agents.status``: ``{pending,
  running, completed, failed, cancelled}`` — covers the standard
  pending → running → terminal lifecycle plus user-cancellation.
- ``uart_sessions.status``: ``{created, connected, closed, error}`` —
  ``connected`` and ``closed`` are written today by uart_service;
  ``created`` and ``error`` reserve the lifecycle expansion (initial
  row state and bridge-failure path).
- ``cra_assessments.overall_status``: ``{in_progress, complete,
  exported}`` — matches CraStatus enum in schemas/cra_compliance.py.
- ``cra_requirement_results.status``: ``{pass, fail, partial,
  not_tested, not_applicable}`` — matches RequirementStatus enum.
- ``emulation_sessions.mode`` / ``emulation_presets.mode``: ``{user,
  system, system-full, qiling}``. Pydantic narrows POST input to
  {user, system}; ``system-full`` and ``qiling`` come from server
  paths that bypass the schema (system_emulation_service constructor;
  emulation/service.py:310 fallback).
- ``emulation_presets.stub_profile``: ``{none, generic, tenda}`` —
  matches schema Literal + model server_default.
- ``sbom_vulnerabilities.match_confidence``: ``{high, medium, low}``,
  NULL allowed. cve_matcher writes {high, low}; live DB has all
  three.
- ``sbom_vulnerabilities.match_tier``: ``{parser_version_pin,
  chipset_cpe, nvd_freetext, curated_yaml, kernel_cpe,
  kernel_subsystem}``, NULL allowed. cve_matcher writes
  {parser_version_pin, curated_yaml, kernel_cpe, kernel_subsystem};
  remaining values reserved for the chipset_cpe + nvd_freetext tiers
  documented in models/sbom.py.
- ``sbom_vulnerabilities.resolved_by``: ``{user, ai}``, NULL allowed.
  routers/sbom.py writes "user", ai/tools/sbom.py writes "ai".
- ``sbom_vulnerabilities.adjusted_severity``: ``{critical, high,
  medium, low, unknown}``, NULL allowed. Matches SBOM_SEVERITY_VALUES
  set used elsewhere; ``unknown`` (not ``info``) is the SBOM
  convention. The MCP ``adjust_severity`` tool's input enum currently
  drifts to ``{critical, high, medium, low, info}`` — that's tracked
  separately and not in scope for F-C-05 closure.

Each CHECK is independently droppable in downgrade; the alembic chain
walker test (``tests/test_status_check_constraint_alignment.py``)
imports the module-scope tuple constants below by name.
"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "89007f64cfb0"
down_revision: Union[str, None] = "d2e3f4a5b6c7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Allowlists — module constants so
# tests/test_status_check_constraint_alignment.py can import without
# parsing the SQL string.
PROJECT_STATUS_VALUES: tuple[str, ...] = (
    "created",
    "unpacking",
    "ready",
    "error",
)
SECURITY_REVIEW_STATUS_VALUES: tuple[str, ...] = (
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
)
REVIEW_AGENT_STATUS_VALUES: tuple[str, ...] = (
    "pending",
    "running",
    "completed",
    "failed",
    "cancelled",
)
UART_SESSION_STATUS_VALUES: tuple[str, ...] = (
    "created",
    "connected",
    "closed",
    "error",
)
CRA_ASSESSMENT_OVERALL_STATUS_VALUES: tuple[str, ...] = (
    "in_progress",
    "complete",
    "exported",
)
CRA_REQUIREMENT_STATUS_VALUES: tuple[str, ...] = (
    "pass",
    "fail",
    "partial",
    "not_tested",
    "not_applicable",
)
EMULATION_MODE_VALUES: tuple[str, ...] = (
    "user",
    "system",
    "system-full",
    "qiling",
)
EMULATION_PRESET_STUB_PROFILE_VALUES: tuple[str, ...] = (
    "none",
    "generic",
    "tenda",
)
SBOM_VULN_MATCH_CONFIDENCE_VALUES: tuple[str, ...] = (
    "high",
    "medium",
    "low",
)
SBOM_VULN_MATCH_TIER_VALUES: tuple[str, ...] = (
    "parser_version_pin",
    "chipset_cpe",
    "nvd_freetext",
    "curated_yaml",
    "kernel_cpe",
    "kernel_subsystem",
)
SBOM_VULN_RESOLVED_BY_VALUES: tuple[str, ...] = (
    "user",
    "ai",
)
SBOM_VULN_ADJUSTED_SEVERITY_VALUES: tuple[str, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "unknown",
)


_CONSTRAINTS: tuple[tuple[str, str, str, tuple[str, ...], bool], ...] = (
    # (constraint_name, table, column, values, nullable)
    ("ck_projects_status", "projects", "status",
     PROJECT_STATUS_VALUES, False),
    ("ck_security_reviews_status", "security_reviews", "status",
     SECURITY_REVIEW_STATUS_VALUES, False),
    ("ck_review_agents_status", "review_agents", "status",
     REVIEW_AGENT_STATUS_VALUES, False),
    ("ck_uart_sessions_status", "uart_sessions", "status",
     UART_SESSION_STATUS_VALUES, False),
    ("ck_cra_assessments_overall_status", "cra_assessments",
     "overall_status", CRA_ASSESSMENT_OVERALL_STATUS_VALUES, False),
    ("ck_cra_requirement_results_status", "cra_requirement_results",
     "status", CRA_REQUIREMENT_STATUS_VALUES, False),
    ("ck_emulation_sessions_mode", "emulation_sessions", "mode",
     EMULATION_MODE_VALUES, False),
    ("ck_emulation_presets_mode", "emulation_presets", "mode",
     EMULATION_MODE_VALUES, False),
    ("ck_emulation_presets_stub_profile", "emulation_presets",
     "stub_profile", EMULATION_PRESET_STUB_PROFILE_VALUES, False),
    ("ck_sbom_vulns_match_confidence", "sbom_vulnerabilities",
     "match_confidence", SBOM_VULN_MATCH_CONFIDENCE_VALUES, True),
    ("ck_sbom_vulns_match_tier", "sbom_vulnerabilities", "match_tier",
     SBOM_VULN_MATCH_TIER_VALUES, True),
    ("ck_sbom_vulns_resolved_by", "sbom_vulnerabilities", "resolved_by",
     SBOM_VULN_RESOLVED_BY_VALUES, True),
    ("ck_sbom_vulns_adjusted_severity", "sbom_vulnerabilities",
     "adjusted_severity", SBOM_VULN_ADJUSTED_SEVERITY_VALUES, True),
)


def _in_list_sql(column: str, values: tuple[str, ...]) -> str:
    quoted = ", ".join(f"'{v}'" for v in values)
    return f"{column} IN ({quoted})"


def _condition(column: str, values: tuple[str, ...], nullable: bool) -> str:
    inner = _in_list_sql(column, values)
    return f"{column} IS NULL OR {inner}" if nullable else inner


def upgrade() -> None:
    # Idempotent re-create — the live database already carries every
    # constraint below from a prior, since-removed migration file.
    # DROP IF EXISTS makes the chain walk on production a no-op when
    # the definition matches, and a corrective drop+create when it
    # has drifted.
    for cname, table, column, values, nullable in _CONSTRAINTS:
        op.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {cname};"
        )
        op.create_check_constraint(
            cname, table, _condition(column, values, nullable),
        )


def downgrade() -> None:
    for cname, table, *_ in _CONSTRAINTS:
        op.execute(
            f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {cname};"
        )
