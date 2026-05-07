---
title: "Audit DB-vs-alembic chain drift (orphan DDL inventory)"
status: pending
priority: low
target: backend/alembic/versions/ + production wairz database (read-only audit)
discovered: 2026-05-07
discovered_by: Fleet Wave 1 Stream β (audit-db-alembic-chain-drift)
---

## Background

The just-shipped migration `89007f64cfb0_audit_2026_05_04_add_status_check_constraints.py` (HEAD on `clean-history`, parent `d2e3f4a5b6c7`) restored 13 CHECK constraints that already existed in the production wairz DB but were not mentioned in any file under `backend/alembic/versions/`. Root cause: a previous migration that created those constraints was deleted at some point, leaving DDL state on disk in PostgreSQL that no `alembic downgrade` could roll back. The F-C-05 fix is idempotent (`DROP CONSTRAINT IF EXISTS` then `CREATE`) so the chain re-walks cleanly on both production and a fresh CI/test DB.

This audit asks: are there OTHER orphan DDL artefacts in the live DB whose creating migration is similarly missing? Three orthogonal classes are in scope:

1. **Orphan CHECK constraints** — exist in `pg_constraint (contype='c')` but no file in `backend/alembic/versions/` mentions the constraint name.
2. **Orphan indexes** — exist in `pg_indexes` but no file in `backend/alembic/versions/` mentions the index name. Auto-generated names (`_pkey`, `_fkey`) are filtered out as expected — they are products of `op.create_table(..., sa.PrimaryKeyConstraint(...))` rather than literal names.
3. **Orphan columns** — exist in `information_schema.columns` for the wairz tables but no migration file mentions the column name.

The 2026-05-05 audit `audit-models-orm-vs-db-schema-drift-2026-05-05.md` (resolved) covered ORM model drift against the DB; this audit covers the orthogonal direction — DB DDL drift against the alembic chain ledger. There is no overlap with that prior intake.

## Method

### Live DB inventory

Captured 2026-05-07 against `wairz-postgres-1` (postgres:16-alpine), database `wairz`, branch `clean-history` HEAD `8329933` (post-F-C-05). Each query was run with `redirect-then-cat` per Rule #35a.

```sql
-- /tmp/all_constraints.txt (83 rows)
SELECT conname, conrelid::regclass::text AS table_name, contype,
       pg_get_constraintdef(oid) AS definition
FROM pg_constraint
WHERE connamespace = 'public'::regnamespace
  AND conname NOT LIKE 'pg_%'
ORDER BY table_name, conname;

-- /tmp/all_indexes.txt (71 rows)
SELECT schemaname, tablename, indexname, indexdef
FROM pg_indexes
WHERE schemaname = 'public'
ORDER BY tablename, indexname;

-- /tmp/all_columns.txt (287 rows)
SELECT table_name, column_name, data_type, is_nullable, column_default
FROM information_schema.columns
WHERE table_schema = 'public'
ORDER BY table_name, ordinal_position;
```

### Cross-reference shape

Per name (constraint, index, column), `grep -l <name> backend/alembic/versions/*.py | wc -l` and bucket as covered (≥1 hit) or orphan (0 hits). The constraint and index passes used `IFS='|' read` to parse the pipe-delimited psql output safely (an early `for line in $(cat ...)` attempt split on whitespace inside the constraint definitions and was abandoned). The column pass used the pattern `[\"']${column}[\"']` to match `sa.Column("col", ...)` literals in migration files.

### Width canary (Rule #31)

For every name flagged as orphan by the narrow grep, a broader pattern was run as a width canary:

- Constraints: `grep -lE "\b${cname}\b" backend/alembic/versions/*.py`
- Columns: `grep -lE "\b${col}\b" backend/alembic/versions/*.py`

Zero divergence between narrow and broad — no name was orphan-by-narrow-but-covered-by-broad. The narrow patterns are reliable for this codebase.

### Verification of F-C-05 attribution

Sanity check: each of the 13 F-C-05 constraints (`ck_projects_status`, `ck_security_reviews_status`, `ck_review_agents_status`, `ck_uart_sessions_status`, `ck_cra_assessments_overall_status`, `ck_cra_requirement_results_status`, `ck_emulation_sessions_mode`, `ck_emulation_presets_mode`, `ck_emulation_presets_stub_profile`, `ck_sbom_vulns_match_confidence`, `ck_sbom_vulns_match_tier`, `ck_sbom_vulns_resolved_by`, `ck_sbom_vulns_adjusted_severity`) is attributed to exactly one migration: `89007f64cfb0_audit_2026_05_04_add_status_check_constraints.py`. Confirms the cross-reference is reading the just-shipped migration.

## Findings — Orphan CHECK constraints

**Count: 0.**

All 26 CHECK constraints in production are mapped to a creating migration:

| Constraint | Table | Migration (revision) |
|---|---|---|
| ck_cra_assessments_overall_status | cra_assessments | 89007f64cfb0 |
| ck_cra_requirement_results_status | cra_requirement_results | 89007f64cfb0 |
| ck_device_dump_sessions_status | device_dump_sessions | b0c1a2d3e4f5 |
| ck_emulation_presets_mode | emulation_presets | 89007f64cfb0 |
| ck_emulation_presets_stub_profile | emulation_presets | 89007f64cfb0 |
| ck_emulation_sessions_mode | emulation_sessions | 89007f64cfb0 |
| ck_emulation_sessions_status | emulation_sessions | 54c8864fbe0c, b0c1a2d3e4f5, c3f8a1b9e4d2 |
| ck_findings_confidence | findings | 54c8864fbe0c |
| ck_findings_severity | findings | 54c8864fbe0c |
| ck_findings_source | findings | 54c8864fbe0c, a9f4e9cdabe2, 61b147189fcf |
| ck_findings_status | findings | 54c8864fbe0c |
| ck_firmware_cve_match_status | firmware | b0c1a2d3e4f5, e6f7a8b9c0d1 |
| ck_firmware_upload_stage | firmware | d2e3f4a5b6c7 |
| ck_firmware_vuln_scan_status | firmware | c1d2e3f4a5b6 |
| ck_fuzzing_campaigns_status | fuzzing_campaigns | 54c8864fbe0c, b0c1a2d3e4f5, d8e9c4b5f7a2 |
| ck_projects_status | projects | 89007f64cfb0 |
| ck_review_agents_status | review_agents | 89007f64cfb0 |
| ck_sbom_vulns_adjusted_severity | sbom_vulnerabilities | 89007f64cfb0 |
| ck_sbom_vulns_component_or_blob | sbom_vulnerabilities | d9b2e3f5a6c7 |
| ck_sbom_vulns_match_confidence | sbom_vulnerabilities | 89007f64cfb0 |
| ck_sbom_vulns_match_tier | sbom_vulnerabilities | 89007f64cfb0 |
| ck_sbom_vulns_resolution_status | sbom_vulnerabilities | 54c8864fbe0c |
| ck_sbom_vulns_resolved_by | sbom_vulnerabilities | 89007f64cfb0 |
| ck_sbom_vulns_severity | sbom_vulnerabilities | 54c8864fbe0c |
| ck_security_reviews_status | security_reviews | 89007f64cfb0 |
| ck_uart_sessions_status | uart_sessions | 89007f64cfb0 |

The F-C-05 fix is the only restoration. No further drift remains in the CHECK class.

## Findings — Orphan UNIQUE constraints

**Count: 0.**

| Constraint | Table | Migration |
|---|---|---|
| uq_firmware_project_sha256 | firmware | ca95e2723392 |
| uq_hwfw_firmware_sha256 | hardware_firmware_blobs | c8a1f4e2d5b6 |
| uq_sbom_components_firmware_name_version_cpe | sbom_components | ca95e2723392 |

## Findings — Orphan indexes

**Count: 0** (after false-positive filter).

51 named indexes in production; all 51 covered by exactly one migration (most cases) or by a creating migration plus a later constraint-add migration (the `_unique` shadow indexes that PostgreSQL auto-creates from `op.create_unique_constraint(...)`).

The width canary returned the same zero. The single name flagged before the filter — `alembic_version_pkc` on the `alembic_version` table — is alembic's own bookkeeping table and is created by alembic itself outside the wairz migration chain; it is not part of the wairz schema.

For reference, the 51 covered named indexes are: `idx_cache_lookup`, `idx_device_dump_project`, `idx_device_dump_status`, `idx_emulation_project`, `idx_emulation_status`, `idx_findings_source`, `idx_sbom_firmware`, `idx_sbom_vulns_blob`, `idx_sbom_vulns_component`, `idx_sbom_vulns_cve`, `idx_sbom_vulns_firmware`, `idx_sbom_vulns_resolution`, plus 39 `ix_*` and `uq_*` indexes whose names mirror their owning tables/columns.

## Findings — Orphan columns

**Count: 0.**

287 columns scanned across all `public` tables. All 287 mapped to at least one migration file mentioning the column name in a quoted-string context (`sa.Column("name", ...)`, `op.add_column("table", sa.Column("name", ...))`, etc.).

The narrow pattern `[\"']${column}[\"']` agreed with the broader bare-word pattern `\b${column}\b` (Rule #31 width canary): zero false negatives.

## False-positive filter rules

Filters applied to keep the audit signal clean. Each is documented so a future re-run is reproducible.

1. **`alembic_version` table excluded** — alembic's own bookkeeping (`version_num` column, `alembic_version_pkc` PK, `alembic_version_pkc` index). Created by alembic at first migration; not part of wairz schema.
2. **PRIMARY KEY auto-generated names (`_pkey$`)** — 21 in `pg_constraint` (contype='p'), 20 also surface in `pg_indexes` (PG auto-creates a unique index for every PK). Names are auto-derived from the table name by SQLAlchemy/PostgreSQL when `op.create_table(..., sa.PrimaryKeyConstraint(...))` is called; literal names rarely appear in migration files.
3. **FOREIGN KEY auto-generated names (`_fkey$`)** — 30 in `pg_constraint` (contype='f'). Names are auto-derived from `<table>_<column>_fkey` by PostgreSQL when `sa.ForeignKey(...)` is declared on a column. Literal FK names rarely appear in migrations unless the migration uses `op.create_foreign_key(...)` with an explicit name argument.

Rule of thumb for a future audit: filter `_pkey$` and `_fkey$` from the orphan-name list before triaging. If a CHECK or UNIQUE name appears in the orphan list, that is real drift.

## Risk assessment

**No findings. Clean bill of health.**

The F-C-05 case was a one-off — a single deleted migration file produced 13 orphan CHECK constraints in production, and the F-C-05 closer restored them. Every other constraint, index, and column in production traces back to a creating migration in the chain.

Risk of regression: low. The mechanism that produced F-C-05 (deleting a migration file in `git` while leaving the DDL applied to production) is a process gap, not a structural one. Mitigations already in place:

- Rule #20 fast iteration discipline says `docker cp + alembic upgrade head` for single-file migration changes — the iteration cycle does not encourage migration deletion.
- The 2026-05-05 ORM-vs-DB drift audit established the pattern of running `alembic revision --autogenerate -m "drift sanity"` on a Rule #8-rebuilt backend; an empty autogenerate is the canary that catches BOTH ORM-vs-DB drift AND deleted-migration drift in one shot. (The 2026-05-05 audit closed Family A + Family B; this audit confirms there is no Family C.)

If a future migration is deleted, the natural detector is: the next `alembic upgrade head` against a fresh DB will fail because the chain has a gap — but a long-running production DB will silently retain the orphan DDL. The autogenerate-empty CI gate (mentioned in `audit-models-orm-vs-db-schema-drift-2026-05-05.md` "Acceptance Criteria") is the right durable backstop.

## Suggested closure path

Close this intake with a no-op disposition. The audit found nothing actionable. Next-touch:

- If an orphan is detected in a future audit, mirror the F-C-05 shape: a single migration with `DROP CONSTRAINT IF EXISTS` then `CREATE`, idempotent against both production (where the constraint is already present) and a fresh CI/test DB (where it isn't), with an allowlist tuple constant for any allowlist-style values.
- Wire the autogenerate-empty CI gate (the 2026-05-05 follow-up) so this entire audit class is detected continuously rather than re-investigated periodically.

## Out of scope

This audit covered constraints, indexes, and columns. NOT covered:

- **Trigger drift** — `pg_trigger` was not inventoried. wairz uses minimal triggers (none expected from the model files), but a sweep would be additive work.
- **Sequence drift** — `pg_class WHERE relkind='S'` was not inventoried. Most sequences are auto-managed by SERIAL columns, but custom sequences could exist.
- **Function drift** — `pg_proc` was not inventoried. wairz's models do not declare custom functions, but extensions like `pgcrypto` (which provides `gen_random_uuid()`) install some.
- **Type drift** — column type compatibility between ORM and DB was covered by the 2026-05-05 audit (Family A); this audit only checked column NAMES.
- **NULL/DEFAULT drift** — column nullability and `column_default` from `information_schema.columns` were collected but not cross-referenced. Whether ORM `nullable=` and `server_default=` match the DB is left to the 2026-05-05 audit family.
- **Granted privileges, RLS policies** — wairz does not use these; out of scope by design.

## Method-replay recipe (for the next audit run)

For reproducibility, the exact shell pipeline:

```bash
# 1. inventory
docker compose exec -T postgres psql -U wairz -d wairz -t -A -F'|' -c "
  SELECT conname, conrelid::regclass::text, contype, pg_get_constraintdef(oid)
  FROM pg_constraint WHERE connamespace = 'public'::regnamespace
  AND conname NOT LIKE 'pg_%' ORDER BY 2, 1;" > /tmp/all_constraints.txt 2>&1
docker compose exec -T postgres psql -U wairz -d wairz -t -A -F'|' -c "
  SELECT schemaname, tablename, indexname, indexdef
  FROM pg_indexes WHERE schemaname = 'public' ORDER BY 2, 3;" > /tmp/all_indexes.txt 2>&1
docker compose exec -T postgres psql -U wairz -d wairz -t -A -F'|' -c "
  SELECT table_name, column_name, data_type, is_nullable, column_default
  FROM information_schema.columns WHERE table_schema = 'public'
  ORDER BY 1, ordinal_position;" > /tmp/all_columns.txt 2>&1

# 2. cross-reference (constraint example)
while IFS='|' read -r cname table contype rest; do
  [ -z "$cname" ] && continue
  hits=$(grep -l "$cname" backend/alembic/versions/*.py 2>/dev/null | wc -l)
  echo "$cname|$table|$contype|$hits"
done < /tmp/all_constraints.txt > /tmp/constraint_hits.txt

# 3. report orphans (excluding _pkey$ and _fkey$)
awk -F'|' '$3 == "c" && $4 == 0' /tmp/constraint_hits.txt   # orphan CHECK
awk -F'|' '$3 == "u" && $4 == 0' /tmp/constraint_hits.txt   # orphan UNIQUE

# 4. width canary
while IFS='|' read -r cname table contype hits; do
  [ "$hits" = "0" ] || continue
  broader=$(grep -lE "\b${cname}\b" backend/alembic/versions/*.py 2>/dev/null | wc -l)
  [ "$broader" != "0" ] && echo "FALSE NEGATIVE: $cname narrow=0 broader=$broader"
done < /tmp/constraint_hits.txt
```

48 alembic revisions in `backend/alembic/versions/` at the time of this audit.

## Provenance

Audit run by Fleet Wave 1 Stream β (audit-db-alembic-chain-drift) dispatched after the F-C-05 CHECK-constraint migration shipped. Read-only — no DDL applied, no `alembic upgrade/downgrade` invoked. File-disjoint with streams α and γ.
