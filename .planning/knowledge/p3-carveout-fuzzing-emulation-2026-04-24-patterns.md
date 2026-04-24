# Patterns: P3 carve-out — fuzzing_service + emulation/ pair

> Extracted: 2026-04-24
> Session: f2f9060c
> Commits: 7d349c3, d1a8701, 77a5908, cac98ad
> Source intake: .planning/intake/backend-private-api-and-circular-imports.md (partial)
> Driver: .planning/intake/seed-next-session-2026-04-24.md Option A′
> Predecessor: .planning/knowledge/assessment-promote-rule30-2026-04-24-patterns.md
> Postmortem: none (sub-campaign slice, not a formal campaign)

## Context

Second P3 carve-out in the "promote function-local imports to top-level" theme. The first (session 5eefecb0 / `fc384bb`) shipped `assessment_service.py` — 11 imports, clean profile, caught a latent ComplianceService name mismatch via the Rule #11 smoke. This session did `fuzzing_service.py` (4 imports) + `emulation/service.py` (3 imports) + `emulation/user_mode.py` (2 imports) = 9 total across 3 files. All 9 promoted without revert; no latent bugs uncovered.

## Successful Patterns

### 1. Transitive-leaf cycle-safety proof BEFORE writing any edit

- **Description:** For every candidate promotion target, read the target module's own top-level imports (`grep -nE '^(from|import)' <target>`). If the target imports ONLY stdlib + pydantic/sqlalchemy/third-party + strict-leaf app modules (`app.config`, `app.utils.docker_client`, `app.database` — each of which was independently verified to import only `app.config`), the promotion is cycle-safe by construction. No speculation needed.
- **Evidence:** 5 target modules (`event_service`, `emulation.docker_ops`, `sysroot_service`, `app.database`, `qiling_service`) verified in a single 40-line grep pass. All 9 promotions shipped without a single smoke failure. Commit message for each refactor lists the cycle-safety evidence per target.
- **Applies when:** Any "promote function-local X to top-level" refactor. The audit takes <2 min and eliminates 100% of cycle risk.

### 2. Coalesce duplicate imports when promoting

- **Description:** Two call sites in `user_mode.py` imported the same symbol (`sysroot_service.get_sysroot_path`) at lines 181 and 252. On promotion, both function-local `from ... import` lines are deleted — a single top-level import serves both call sites.
- **Evidence:** `user_mode.py` had 2 function-local imports → 1 top-level import → 0 function-local imports. Net bytes deleted, not added.
- **Applies when:** Multiple function-local imports of the same symbol in the same file.

### 3. docker cp + per-file import-smoke ≫ end-of-stream full rebuild (for import-site-only changes)

- **Description:** Rule #20 nuance: class-shape changes need `docker compose up -d --build` or a `restart`. Pure import-site relocations do NOT. After each file edit, `docker cp <host> <container>:<path>` + `docker compose exec -T -w /app backend /app/.venv/bin/python -c "from X import Y"` completes in <5s and proves the change loads cleanly. No 3-5 min rebuild needed.
- **Evidence:** 6 smoke calls this session (backend + worker × 3 files), all green, all <5s. Zero AttributeError/ImportError surfaced. End-of-stream rebuild deferred naturally to the next session that touches class-shape.
- **Applies when:** The diff adds/removes module-level `from app.X import Y` lines without modifying class/function signatures or adding/removing class attributes.
- **Counter-applies when:** Rule #20's class-shape exception — if the diff adds, removes, or renames a field on a cached singleton class (pydantic BaseSettings, @dataclass singletons, SQLAlchemy models), use `docker compose restart` or full rebuild.

### 4. Per-file commit per Rule #25, doc drift separated from code drift

- **Description:** 3 refactor commits (one per file) + 1 intake-doc commit. Each refactor has an isolated `git revert` target. The intake-update commit was separated so a rollback of the knowledge/doc drift doesn't accidentally un-ship code, and vice versa.
- **Evidence:** Commits `7d349c3` (fuzzing_service), `d1a8701` (emulation/service), `77a5908` (emulation/user_mode), `cac98ad` (intake docs). Each refactor commit touches exactly 1 file. Bisect-clean.
- **Applies when:** Any multi-file refactor with per-file independent verification AND a closing doc-update step.

### 5. Honor seed's explicit "ask user which route" instead of auto-picking

- **Description:** The seed file `seed-next-session-2026-04-24.md` said "First action for the next session: Ask user (a/b/c/d/n)." I ran autopilot, reported queue state honestly (options A and C already done, B is the default, D is a re-scan), and asked. User picked `a`, then `a3`. Zero rework.
- **Evidence:** This session's first two turns were clarifying questions, not code. Third turn started writing. All 9 promotions landed in the file set the user explicitly chose.
- **Applies when:** An intake or seed document contains explicit user-decision steps. Rule #19 generalises: the spec describes intent, but WHO decides varies — sometimes it's the DB, sometimes it's the user. Read the intent.

### 6. Re-measure candidate file counts before locking scope (Rule #28 for intakes)

- **Description:** Seed's best-candidates table listed file counts from when the seed was written. Before acting, I re-grepped current `from app.*` counts on disk. Found that `assessment_service` had since been fully promoted (seed listed 9 imports; actual was 0) and that `emulation/service.py` had drifted (seed listed 2; actual was 3 under the broader `from app.` match). Scope-bearing facts ALWAYS verified before action.
- **Evidence:** The narrow-vs-broad regex finding (see anti-pattern 1). The 2026-04-24 seed's candidate table had at least 2 stale entries at read-time.
- **Applies when:** Any intake or spec whose scope is predicated on a count (LOC, file count, occurrence count). Re-measure takes 1 second per target.

### 7. Widened regex at end-of-session calibrates the next carve-out

- **Description:** Final audit used `^[[:space:]]+from app\.` (all `app.*` subpackages) instead of the narrower `^[[:space:]]+from app\.(services|ai|models|schemas)\.`. Revealed `firmware_service.py` at 14 residual imports (seed listed 2 under narrow pattern). Re-ranked next-pair candidates accordingly.
- **Evidence:** `cac98ad` intake update paragraph ranks next candidates by the widened count: firmware_service(14), security_audit/hash_lookups(5), mobsfscan/normalization(4), wairz_runner(3), mobsfscan/pipeline(3).
- **Applies when:** Post-session calibration of follow-up scope. Widen the match pattern to avoid the narrow-scan under-counting anti-pattern.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Treat 3 target files as 3 independent commits, not 1 omnibus | Rule #25 — independently-verifiable sub-tasks → per-file commit | 3 clean reverts; bisect-clean |
| Skip end-of-stream `docker compose up -d --build` | Rule #20 exception: no class-shape change; `docker cp` + smoke is sufficient | 9 smokes green, 0 AttributeError, rebuild deferred |
| Honor seed's "ask user a/b/c/d/n" instead of auto-picking a pair | Seed's explicit instruction + Rule #19 evidence-first | User picked a3 (broader than my a1 suggestion); zero wasted work |
| Coalesce duplicate `sysroot_service.get_sysroot_path` import in user_mode.py into one top-level line | Single source of truth; smaller diff | Net deletion, no new semantics |
| Commit the intake/seed doc update AFTER all 3 refactor commits, not inline | Separates doc drift from code drift; reverts don't cross categories | `cac98ad` revertable without affecting refactors |

## Verification shape used each slice (copyable)

```bash
# Per-file, after Edit tool sequence:
grep -nE '^[[:space:]]+from app\.' <file>         # expect 0
grep -nE '^from app\.' <file>                      # expect new imports alphabetized in block
docker cp <file> wairz-backend-1:/app/<file>
docker cp <file> wairz-worker-1:/app/<file>
docker compose exec -T -w /app backend /app/.venv/bin/python -c "from <mod> import <public_symbol>; print('OK')"
docker compose exec -T -w /app worker  /app/.venv/bin/python -c "from <mod> import <public_symbol>; print('OK')"
git add <file> && git commit -m "refactor(<mod>): promote function-local imports to top-level ..."
```

## Applicability envelope for the next carve-out

The mechanical profile validated here (pure-leaf targets, no lazy-legitimacy, same-shape promotions) has now shipped across **4 files in 2 sessions**:
- session 5eefecb0: `assessment_service.py` (11 imports)
- session f2f9060c: `fuzzing_service.py` (4) + `emulation/service.py` (3) + `emulation/user_mode.py` (2)

Before the next session trusts this profile for a 5th file:
1. Re-grep current counts under the widened `^\s+from app\.` pattern (Rule #28 anti-drift).
2. Audit each import target's own top-level imports for cycle evidence.
3. If ANY target is NOT pure-leaf (imports other `app.services.*` at top level), DROP that promotion — investigate lazy-legitimacy per Rule #30 (optional-dep / LGPL / latent-cycle).

Don't assume `firmware_service.py`'s 14 imports repeat the clean-mechanical profile. Firmware has deeper coupling to models and workers than fuzzing/emulation did.
