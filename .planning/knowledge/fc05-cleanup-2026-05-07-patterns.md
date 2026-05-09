# Patterns: post-F-C-05 cleanup session 2026-05-07

> Extracted: 2026-05-07
> Campaign: `.planning/fleet/session-post-fc05-cleanup-2026-05-07.md` (fleet session) + 6 commits f2f0906..5d9a404
> Postmortem: none — extracted from commits + fleet session file directly

## Successful Patterns

### 1. Idempotent CHECK-restoration migration shape
- **Description:** When the live DB carries DDL that no migration file creates (orphan DDL after a deletion), a single restoration migration uses `op.execute("ALTER TABLE x DROP CONSTRAINT IF EXISTS y;")` followed by `op.create_check_constraint(...)` for each constraint. The `IF EXISTS` makes it idempotent on production (where the constraint already exists) AND clean on a fresh CI/test DB (where it doesn't).
- **Evidence:** `backend/alembic/versions/89007f64cfb0_audit_2026_05_04_add_status_check_constraints.py` (commit f2f0906); 13 constraints across 8 tables restored with one revision; `alembic upgrade head` succeeded against the live DB on first try.
- **Applies when:** Closing a Rule #35c-style F-C-05 incident — orphan DDL discovered in production, migration file missing or deleted. Same shape works for orphan UNIQUE / orphan named indexes.
- **Reference shape (verbatim):**
  ```python
  for cname, table, column, values, nullable in _CONSTRAINTS:
      op.execute(f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {cname};")
      op.create_check_constraint(cname, table, _condition(column, values, nullable))
  ```

### 2. Live-DB-as-source-of-truth for allowlist derivation
- **Description:** When restoring a deleted migration, derive the CHECK allowlist by `pg_get_constraintdef(oid) FROM pg_constraint WHERE conname='ck_X'` rather than reasoning from code or older intake docs. The live DB contains the values that have already been deployed without incident; the alembic file becomes a faithful mirror.
- **Evidence:** Initial draft of the F-C-05 migration used "what code writes" as the allowlist (PROJECT_STATUS_VALUES = `("created", "unpacking", "ready", "error")`) which was correct; but for `uart_sessions.status` the draft missed `created` and `error`, and for `security_reviews/review_agents` missed `cancelled`. Re-deriving from live DB caught all three. (commit f2f0906 final allowlist values)
- **Applies when:** Rule #19 evidence-first audit for any allowlist or schema-aligned tuple. Generalises Rule #19's "the spec describes intent, the DB describes truth" to allowlist values specifically.

### 3. Width canary discipline holds for alembic chain audits
- **Description:** Stream β cross-referenced 83 constraints / 71 indexes / 287 columns against 48 migration files using two patterns per name — narrow grep + broader regex. Every name's narrow count agreed with the broader count. Zero divergence = the audit is trustworthy.
- **Evidence:** `.planning/intake/resolved/audit-db-alembic-chain-drift-2026-05-07.md` "Width canary (Rule #31)" section.
- **Applies when:** Any large-name-set audit. Generalises Rule #31 (originally for code-grep scope) to DB-object-name vs migration-file cross-reference.

### 4. Fleet 3-stream parallelism without worktrees works under strict file-disjointness
- **Description:** Wave 1 ran α/β/γ in parallel on the main checkout, no `git worktree add`. Each agent received an explicit "you may modify ONLY these paths" constraint and used `git add <specific-paths>` (never `-A`). Outcome: 3 clean per-stream commits, zero cross-stream sweeps. Third documented success of Rule #23's "fallback (a)" discipline (after Wave-1+2 sessions 435cb5c2 and 198243b8).
- **Evidence:** Commits 8329933 (1 file), 3e2c078 (1 file), e96e6aa (1 file) — each touches exactly its stream's scope.
- **Applies when:** A Fleet wave where streams genuinely touch disjoint files AND worktrees are deliberately off (e.g. user policy, simpler local dev workflow). NOT a substitute for worktrees when scopes overlap.

### 5. Autogen-empty test pays for itself at delivery
- **Description:** Implementing a CHECK / drift-detection test almost always uncovers existing drift the test catches on first run. Don't be surprised; allocate scope for one residual fix in the same commit.
- **Evidence:** `backend/tests/test_alembic_autogenerate_empty.py` (commit 509b42d) — first run failed against `device_dump_sessions.project_id` duplicate-index drift. Fixed in same commit per Rule #25 single-root-cause.
- **Applies when:** Any "introduce a mechanical drift gate" task. Budget the gate AND one drift fix; ship as a single commit.

### 6. CI workflow as canonical post-rebuild test recipe
- **Description:** When a backend image excludes `tests/` (`.dockerignore`) AND strips dev deps (`uv sync --no-dev`), the CI workflow at `.github/workflows/backend-tests.yml` documents the exact pattern: `docker cp backend/tests wairz-backend-1:/app/tests` + `pip install pytest pytest-asyncio` + run with `-w /app -e PYTHONPATH=/app`.
- **Evidence:** `.github/workflows/backend-tests.yml:46-64` (steps "Copy tests into container", "Install test runner", "Run pytest"). Mirrored in this session's manual workflow when the rebuild stripped tests.
- **Applies when:** Any local "rebuild then run tests" iteration after `.dockerignore` excludes tests OR after `uv sync --no-dev` strips dev deps. Read the CI workflow first; it's the source of truth.

### 7. Migration docstring as audit cross-link
- **Description:** The F-C-05 migration's docstring explicitly notes the MCP-tool-vs-DB-CHECK drift it does NOT close (`info`/`unknown` for `adjusted_severity`). That note made the follow-up sweep (Stream α) discoverable rather than buried. Cross-linking from the migration → the in-flight drift → the eventual fix lets future readers reconstruct the decision chain.
- **Evidence:** `backend/alembic/versions/89007f64cfb0_*.py` docstring "out of scope" section pointed at the MCP enum drift; commit 8329933 closed it; commit 5d9a404 audit-doc cross-references both.
- **Applies when:** Any "ship a migration that's correct but documents a known-but-out-of-scope adjacent drift". Note > silence.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Match live DB exactly for F-C-05 allowlists | Rule #19 — DB describes truth; missed `cancelled`/`created`/`error` in initial draft | ✓ first-try alembic upgrade |
| Single bundled commit for F-C-05 (vs per-table split) | Rule #25 — single root cause (audit finding F-C-05); 13 constraints flow from one event | ✓ clean revert path: one `git revert 89007f64` undoes all |
| Per-stream commits for Fleet Wave 1 | Different root causes per stream (α=enum, β=audit, γ=corpus) — 3 commits, 3 reverts available | ✓ clean parallel ledger |
| Drop `index=True` for `device_dump_sessions.project_id` | Mirror 2026-05-05 audit's resolution policy: "Model has, DB doesn't (different name)" → drop column-level, keep named `Index()` in `__table_args__` | ✓ consistent with f5c0824, 7f65908 |
| Narrow MCP enum to match DB (drop `info`) rather than widen DB | `info` had never been persistable; widening DB would let bogus historical values land. Strict-set is the safer choice | ✓ commit 8329933 |
| Defer mechanical MCP-vs-CHECK alignment test as a future intake | Audit found 0 drifts → test would be insurance against a 0-rate failure mode → maintenance burden likely > value | ✓ documented in `audit-mcp-enum-vs-db-check-alignment-2026-05-07.md` recipe |

## Quality Rule Candidates

None of high-enough confidence for harness.json's regex-based qualityRules. The session's lessons are conceptual (idempotent migration shape; live-DB-as-truth; CI workflow as recipe) — they don't reduce to a `pattern` regex over file content. Captured in the patterns above for the next intake-pattern reader instead.
