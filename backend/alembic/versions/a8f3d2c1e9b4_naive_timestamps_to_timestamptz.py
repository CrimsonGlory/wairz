"""Convert 25 naive TIMESTAMP columns to TIMESTAMP WITH TIME ZONE (M-11 / F-C-03)

Existing rows are interpreted as UTC during the conversion (`AT TIME ZONE 'UTC'`),
matching the application semantics — every site that wrote into these columns
used `datetime.utcnow()` (naive UTC) or `func.now()` (postgres session time,
which the runtime configures to UTC). After this migration:

- ORM models declare `DateTime(timezone=True)` everywhere.
- Application code can switch from `datetime.utcnow()` (deprecated in py3.12+,
  removed in py3.13) to `datetime.now(timezone.utc)` without raising
  asyncpg `DataError: invalid input for query argument` on assignment.

Tables/columns affected (25 total):
- analysis_cache: created_at
- attack_surface_entries: created_at
- conversations: created_at, updated_at
- cra_assessments: created_at, updated_at
- cra_requirement_results: assessed_at, updated_at
- documents: created_at
- findings: created_at, updated_at
- firmware: cve_match_started_at, cve_match_finished_at, created_at
- projects: created_at, updated_at
- sbom_vulnerabilities: resolved_at
- security_reviews: started_at, completed_at, created_at, updated_at
- review_agents: started_at, completed_at, created_at, updated_at

Already-aware columns (untouched): emulation_sessions, emulation_presets,
fuzzing_campaigns, fuzzing_crashes, hardware_firmware_blobs,
sbom_components, sbom_vulnerabilities.{published_date, created_at},
uart_sessions.

Revision ID: a8f3d2c1e9b4
Revises: e3b1a4f97c5d
Create Date: 2026-05-05 22:30:00.000000
"""
from alembic import op


revision = "a8f3d2c1e9b4"
down_revision = "e3b1a4f97c5d"
branch_labels = None
depends_on = None


_COLUMNS = [
    ("analysis_cache", "created_at"),
    ("attack_surface_entries", "created_at"),
    ("conversations", "created_at"),
    ("conversations", "updated_at"),
    ("cra_assessments", "created_at"),
    ("cra_assessments", "updated_at"),
    ("cra_requirement_results", "assessed_at"),
    ("cra_requirement_results", "updated_at"),
    ("documents", "created_at"),
    ("findings", "created_at"),
    ("findings", "updated_at"),
    ("firmware", "cve_match_started_at"),
    ("firmware", "cve_match_finished_at"),
    ("firmware", "created_at"),
    ("projects", "created_at"),
    ("projects", "updated_at"),
    ("sbom_vulnerabilities", "resolved_at"),
    ("security_reviews", "started_at"),
    ("security_reviews", "completed_at"),
    ("security_reviews", "created_at"),
    ("security_reviews", "updated_at"),
    ("review_agents", "started_at"),
    ("review_agents", "completed_at"),
    ("review_agents", "created_at"),
    ("review_agents", "updated_at"),
]


def upgrade() -> None:
    for table, col in _COLUMNS:
        op.execute(
            f"ALTER TABLE {table} "
            f"ALTER COLUMN {col} TYPE TIMESTAMP WITH TIME ZONE "
            f"USING {col} AT TIME ZONE 'UTC'"
        )


def downgrade() -> None:
    for table, col in _COLUMNS:
        op.execute(
            f"ALTER TABLE {table} "
            f"ALTER COLUMN {col} TYPE TIMESTAMP WITHOUT TIME ZONE "
            f"USING {col} AT TIME ZONE 'UTC'"
        )
