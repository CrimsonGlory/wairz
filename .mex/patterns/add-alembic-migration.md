---
name: add-alembic-migration
description: Author an alembic migration without hitting the rotating-hex revision-ID collision trap (δ.3 antipattern). Pre-checks the candidate ID against the full versions tree, picks the right per-migration shape (table-creator | column-adder | check-extender), and applies via Rule #20 fast iteration.
triggers:
  - "add alembic migration"
  - "alembic revision"
  - "new migration"
  - "alembic upgrade"
  - "table creator"
  - "column adder"
  - "check constraint extension"
edges:
  - target: context/conventions.md
    condition: for the Verify Checklist that lists Rule #8 rebuild parity (now includes migrator)
  - target: patterns/docker-rebuild-backend-worker.md
    condition: after the migration applies clean, before integration tests
  - target: patterns/add-jsonb-column.md
    condition: when the migration introduces a JSONB column — chain into the normaliser recipe
last_updated: 2026-05-08
---

# Add Alembic Migration

## Context

Every wairz schema change requires an alembic migration in `backend/alembic/versions/`. The pattern looks superficially simple (`alembic revision --autogenerate -m "msg"`) but two failure modes catch agents who skip the pre-check:

1. **Revision-ID collision with orphan migrations** (δ.3 antipattern #1): wairz has 57+ revision IDs in `backend/alembic/versions/` (more than the ~35 in the active chain) due to orphan files from unmerged branches. A "rotating-hex" pattern that increments from the last revision (`d2e3f4a5b6c7` → `d2e3f4a5b6c7` … wait, was that already used?) silently collides. Alembic refuses with `Revision X is present more than once` + `Cycle is detected`. The chain fails to load AT ALL — not just the new migration; the entire alembic head resolution breaks.
2. **Migrator stale image after migration lands** (δ.5 antipattern #2): rebuilding `backend worker` but skipping `migrator` causes the init container to start first using its OLD image, fail to find the new revision, and exit 255. CLAUDE.md Rule #8 was extended in 2026-05-08 to include migrator in the rebuild list — this pattern hard-codes that.

Cost of pre-checking the revision ID: 1 second. Cost of hitting the collision: 2 retries + ~2 minutes per cycle. The 1-second pre-check is mandatory.

## Decide: per-migration shape

Wairz alembic migrations fall into one of three shapes (12 migrations across α + β + γ + δ; the shapes are durable):

| Shape | When | Sample |
|-------|------|--------|
| **table-creator** | New ORM model with its own table | δ.1 `windows_update_packages`; γ.1 `windows_registry_extracts`; α.X `findings` |
| **column-adder** | Adding columns to an existing table (status sets, JSONB results) | δ.2 `firmware.dotnet_decompile_*` 5-col status set; γ.3 `firmware.registry_hive_walk_*` 5-col status set |
| **check-extender** | Extending a CHECK constraint allowlist (typically `ck_findings_source` for new finding-source values) | δ.8 `ck_findings_source` += `windows_r2r_stomp` + `windows_il_capa`; γ.7 same pattern; β.12a same |

Mechanical heuristic: if the change adds an `op.create_table(...)` it's a table-creator. If it adds `op.add_column(...)` lines on an existing table, it's a column-adder. If it drops + recreates a CHECK constraint with an extended allowlist, it's a check-extender.

## Steps

### 1. Pre-check the candidate revision ID

Run this from the repo root (or use a subshell so the cd is scoped; per Rule #38):

```sh
( cd backend && uv run python -c "
import re, glob
ids = set()
for p in glob.glob('alembic/versions/*.py'):
    txt = open(p).read()
    m = re.search(r'(?m)^revision[: \\w]*=\\s*[\"\\']?([a-f0-9]+)', txt)
    if m: ids.add(m.group(1))
cand = 'd3a4b5c6d7e8'  # ← the candidate
print('TAKEN' if cand in ids else 'FREE', cand, '/', len(ids), 'total')
" )
```

Replace `d3a4b5c6d7e8` with your candidate. Print output:
- `FREE d3a4b5c6d7e8 / 57 total` — go.
- `TAKEN d3a4b5c6d7e8 / 57 total` — pick another, re-run.

If you're authoring multiple migrations in one session (typical for a multi-sub-task phase like δ), pre-validate all candidates in one pass before authoring the first. δ pre-validated `d3a4b5c6d7e8` / `d4a5b6c7d8e9` / `d5a6b7c8d9e0` / etc. as a batch.

### 2. Generate the migration

For autogenerate (preferred — picks up model changes):

```sh
docker compose exec backend alembic revision --autogenerate -m "<msg>"
```

The generated file lands at `backend/alembic/versions/<id>_<msg>.py`.

For a hand-written migration (rare — only when autogenerate doesn't capture the intent, e.g. complex check-extender drops + creates):

```sh
docker compose exec backend alembic revision -m "<msg>"
```

Open the file. Set `revision = "<your-pre-checked-id>"` and `down_revision = "<previous-head>"`.

### 3. Author the migration body per shape

#### Shape A — table-creator

```python
def upgrade() -> None:
    op.create_table(
        "<table>",
        sa.Column("id", postgresql.UUID(as_uuid=True),
                  server_default=sa.text("gen_random_uuid()"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("<col>", sa.String(...), nullable=False),
        # ... domain columns ...
        sa.PrimaryKeyConstraint("id"),
        sa.ForeignKeyConstraint(["<fk>"], ["<other>.id"], ondelete="CASCADE"),
        sa.CheckConstraint("<col> IN (...)", name="ck_<table>_<col>"),  # if Rule #33 .c
    )
    op.create_index("ix_<table>_<col>", "<table>", ["<col>"])

def downgrade() -> None:
    op.drop_index("ix_<table>_<col>", table_name="<table>")
    op.drop_table("<table>")
```

Mandatory companions:
- ORM model in `backend/app/models/<name>.py` (singular: `WindowsUpdatePackage`).
- If a column is JSONB, chain into [`add-jsonb-column.md`](add-jsonb-column.md) for the normaliser.
- If a column has Pydantic `Literal` + DB CHECK, add the pair to `backend/tests/test_windows_check_literal_alignment.py::_PAIRS` (one tuple-extension; no helper duplication).

#### Shape B — column-adder

```python
def upgrade() -> None:
    op.add_column("firmware", sa.Column("<op>_status", sa.String(20),
                  nullable=False, server_default="idle"))
    op.add_column("firmware", sa.Column("<op>_started_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("firmware", sa.Column("<op>_finished_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("firmware", sa.Column("<op>_error", sa.Text(), nullable=True))
    op.add_column("firmware", sa.Column("<op>_result", postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.create_check_constraint(
        "ck_firmware_<op>_status",
        "firmware",
        "<op>_status IN ('idle', 'queued', 'running', 'completed', 'failed')",
    )

def downgrade() -> None:
    op.drop_constraint("ck_firmware_<op>_status", "firmware", type_="check")
    op.drop_column("firmware", "<op>_result")
    op.drop_column("firmware", "<op>_error")
    op.drop_column("firmware", "<op>_finished_at")
    op.drop_column("firmware", "<op>_started_at")
    op.drop_column("firmware", "<op>_status")
```

Mandatory companions:
- Pydantic `Literal` matching the CHECK allowlist (Rule #33 .c).
- Status helper docs (often `_row_to_status(row)`).
- Frontend rendering of the status pill (if FE surfaces the operation).

#### Shape C — check-extender

```python
# Drop + recreate the CHECK with the new allowlist. Postgres can't ALTER CHECK in place.
def upgrade() -> None:
    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source",
        "findings",
        "source IN ("
        "'<existing-1>', '<existing-2>', "
        "'<new-source-1>', '<new-source-2>'"  # ← the additions
        ")",
    )

def downgrade() -> None:
    op.drop_constraint("ck_findings_source", "findings", type_="check")
    op.create_check_constraint(
        "ck_findings_source", "findings",
        "source IN ('<existing-1>', '<existing-2>')",  # ← old allowlist
    )
```

Mandatory companions (Rule #25 single-slice exception #2 — bundle in ONE commit):
- Pydantic `Literal` extension (typically `WindowsFindingSource`) with the new values.
- Frontend `FindingSource` union extension in `frontend/src/types/index.ts`.
- Frontend `FINDING_SOURCE_CONFIG` entries in `frontend/src/constants/statusConfig.ts`.
- Any FE pages/routes that render the new sources (App.tsx route registration).
- `test_finding_source_alignment.py` will validate pairwise agreement automatically; no test edits needed when extending. If splitting across commits, the alignment test goes RED between commits — DO NOT split.

### 4. Apply via Rule #20 fast iteration

For migration validation against a running container without a full rebuild (saves 3-5 min vs `docker compose up -d --build`):

```sh
# 1. Copy the new migration file into the running container.
docker cp backend/alembic/versions/<id>_<msg>.py \
  $(docker compose ps -q backend):/app/alembic/versions/<id>_<msg>.py

# 2. Run alembic upgrade inside the container.
docker compose exec -T -w /app -e PYTHONPATH=/app backend \
  /app/.venv/bin/alembic upgrade head
```

Both `PYTHONPATH=/app` and `-w /app` are required for alembic to import `app.database`. If `alembic upgrade head` succeeds + prints `INFO  [alembic.runtime.migration] Running upgrade <prev> -> <new>`, the migration is valid.

**Class-shape exception (Rule #20 .a):** if the migration's ORM model adds, removes, or renames a field, the running process holds the OLD class via `@lru_cache`'d settings / SQLAlchemy metadata / module-level singletons. `docker cp` alone is insufficient. Either:
- `docker compose restart backend worker` (fast; ~30 s; image unchanged), OR
- Commit to the full Rule #8 rebuild now: `docker compose up -d --build backend worker migrator`.

Mechanical tell: if the diff adds/removes/renames a field in an ORM class definition, restart is required even for a one-file change.

### 5. Pre-merge: full Rule #8 rebuild

Before trusting the migration for the next session (or before pushing the branch):

```sh
docker compose up -d --build backend worker migrator
```

All three. The Rule #8 wording was extended in 2026-05-08 (postmortem-followups commit) to add migrator — δ.5 hit the failure mode where `up -d` failed because the migrator init container booted first using its stale image and couldn't find the new revision. **Always include migrator in the rebuild list.**

After the rebuild, run `docker compose ps` to confirm all expected services are running. δ.9 also caught a frontend container that exited during a failed-migrator cascade — recovered with `docker compose up -d frontend` in ~10 s.

### 6. Verify per Rule #11 + Rule #35b

```sh
# Rule #11 runtime smoke
docker compose exec -T backend /app/.venv/bin/python -c "
from app.models.<name> import <Class>
print('ok')
"

# Rule #35b live canary (when the migration introduces a writer path)
# — round-trip a row through the real ORM + SELECT it back.
```

For check-extender migrations, the `test_finding_source_alignment.py` + `test_windows_check_literal_alignment.py` test suites act as the alignment safety net. Run them targeted:

```sh
docker compose exec -T backend /app/.venv/bin/pytest \
  backend/tests/test_finding_source_alignment.py \
  backend/tests/test_windows_check_literal_alignment.py -v
```

## Gotchas

- **`docker compose exec backend alembic revision --autogenerate`** uses the ORM as source of truth. If your ORM change isn't loaded into the running backend, autogenerate produces an empty migration. Either rebuild backend before generating, or hand-write the migration with explicit op calls.
- **Empty migration body** (autogenerate produced nothing) usually means the model change wasn't picked up. Check `docker compose exec backend python -c "from app.models.<name> import <Class>; print(<Class>.__tablename__)"` first.
- **`--autogenerate` doesn't detect CHECK constraint changes.** Hand-write check-extender migrations.
- **`down_revision` mismatch** (you set it to a stale head) → alembic refuses with "Multiple head revisions". Run `docker compose exec backend alembic heads` to get the current head before authoring.
- **Forgetting `nullable=False` + `server_default`** on a non-nullable column with existing rows → migration fails on `null value in column "<col>" of relation "<table>" violates not-null constraint`. Either provide a `server_default` matching the type, or add the column nullable first + backfill + alter to non-null.
- **JSONB column server_default syntax** is fiddly: use `server_default="'[]'"` for an empty list (the inner quotes are part of the SQL literal), not `server_default='[]'`.
- **Model-only changes that need NO migration** (adding a `@hybrid_property`, a `@validates` method, a class-level cache attribute) — alembic autogenerate may produce noise. Discard the empty migration if so.
- **The migrator init container runs `alembic upgrade head` on every container start.** If a migration depends on a Postgres extension (`pg_trgm`, `unaccent`), ensure the extension is created in an earlier migration or in the database init script — the migrator can't enable extensions on its own without superuser.

## Verify

- [ ] Candidate revision ID was pre-checked against the full versions tree (Step 1 one-liner) — printed `FREE`.
- [ ] Per-migration shape identified (table-creator | column-adder | check-extender).
- [ ] Migration body matches the shape template.
- [ ] `down_revision` matches the current head (`alembic heads`).
- [ ] If table-creator: ORM model added; CHECK constraint named `ck_<table>_<col>` if Rule #33 .c.
- [ ] If column-adder: Pydantic `Literal` matches the CHECK allowlist; status-helper updated.
- [ ] If check-extender: bundled with Pydantic Literal + FE union + FE config + FE pages in ONE commit (Rule #25 single-slice exception #2). `test_finding_source_alignment.py` passes.
- [ ] If JSONB column introduced: `add-jsonb-column.md` recipe followed (normaliser + tests).
- [ ] Rule #20 fast iteration `docker cp` + `alembic upgrade head` succeeded inside the running container.
- [ ] Rule #20 .a: if class shape changed, `docker compose restart` issued OR full rebuild scheduled.
- [ ] Pre-merge: `docker compose up -d --build backend worker migrator` ran (all three; Rule #8 extended 2026-05-08).
- [ ] `docker compose ps` shows all services running post-rebuild.
- [ ] Rule #11 import smoke OK on the touched modules.
- [ ] Rule #35b live canary if the migration introduces a writer path.
- [ ] Targeted alignment tests pass (when applicable).

## Debug

- **`Revision X is present more than once` / `Cycle is detected`** → revision-ID collision. Pick a free ID via Step 1 one-liner; rename the file + update `revision = "..."`.
- **`Can't locate revision identified by 'XXX'` from migrator at startup** → migrator image is stale. `docker compose up -d --build migrator` (and rebuild backend + worker too — Rule #8 extension).
- **`service migrator didn't complete successfully: exit 255`** → check `docker compose logs migrator` for the actual alembic error. Usually one of: (a) the revision-ID collision above; (b) DB connection unreachable (postgres not started yet — check `depends_on`); (c) migration body raised an unhandled exception (check the autogenerate output for missing `op.create_check_constraint(...)` calls or syntax errors).
- **`alembic upgrade head` runs but no changes apply** → the new migration's `down_revision` doesn't match the current head. Fix the chain: `down_revision = "<output of alembic current>"`.
- **Migration applies but ORM still raises `column "<x>" does not exist`** → connection pool cached the old schema. Restart backend (`docker compose restart backend`) — psycopg pool refreshes on connection re-establish.
- **`relation already exists`** → the table was created in an earlier migration that didn't get a downgrade run. Check `alembic history`; consider `op.execute("DROP TABLE IF EXISTS <name> CASCADE")` at the top of the upgrade body if you're consolidating an orphan migration's effect.

## Update Scaffold

- [ ] If the per-migration shape repertoire grows (e.g. a new shape like "index-only-migration" emerges as a 4th category from a future phase), update the Decide table.
- [ ] If the revision-ID pre-check one-liner needs adjustment for a new alembic version, update Step 1.
- [ ] If the migrator stale-image pattern (Rule #8 extension) is re-litigated by a new ε.X incident, update Step 5 + Debug accordingly.

## References

- CLAUDE.md Rule #8 (rebuild parity — extended 2026-05-08 to include migrator)
- CLAUDE.md Rule #11 (runtime import smoke after split changes)
- CLAUDE.md Rule #20 (docker cp fast iteration + class-shape exception)
- CLAUDE.md Rule #25 single-slice exception #2 (cross-stack alignment bundling)
- CLAUDE.md Rule #33 .c (Pydantic Literal + DB CHECK alignment for status columns)
- CLAUDE.md Rule #35b (live canaries for writer paths)
- δ postmortem antipattern #1 (revision-ID collision with orphan migrations) — `.planning/knowledge/windows-coverage-godmode-delta-2026-05-09-antipatterns.md`
- δ postmortem antipattern #2 (migrator stale image) — same file
