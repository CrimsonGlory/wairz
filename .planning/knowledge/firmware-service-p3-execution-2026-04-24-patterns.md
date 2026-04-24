# Patterns: P3 session 78f772bd — firmware_service execution from pre-audited de-risk

> Extracted: 2026-04-24
> Session: 78f772bd (autopilot-driven; seed-next-session-2026-04-25.md as the linearised execution plan)
> Commits: 5e2cb18 (refactor), fd496f3 (intake + ROUTER + seed-resolution)
> Source intake: .planning/intake/backend-private-api-and-circular-imports.md (de-risk audit at top of file, predecessor commit 8e99ec4)
> Driver: .planning/intake/resolved/seed-next-session-2026-04-25.md (now resolved)
> Predecessor: p3-derisk-firmware-service-2026-04-24-patterns.md (the AUDIT phase; this file is the EXECUTION phase)
> Postmortem: none — clean execution, no incidents to autopsy

## Context

This is the EXECUTION half of a deliberately-bipartite multi-session refactor:

- **Session 3d9d854e (2026-04-24, AUDIT phase)** — committed the de-risk analysis (`8e99ec4`) classifying all 14 firmware_service.py function-body app.* imports as Rule #30 SAFE; wrote `seed-next-session-2026-04-25.md` (`3013124`) as a step-by-step execution plan baselined to that commit.
- **Session 78f772bd (2026-04-24, EXECUTION phase, this session)** — read the audit, executed mechanically, shipped 6th P3 carve-out as a single refactor commit per Rule #25, logged outcome to intake.

The headline finding: the audit-as-deliverable session shape (predecessor's pattern #1) crossed the session boundary cleanly. Audit predictions held with one minor calibration delta (post-residual 18 vs. predicted 19, traced to ast.walk nested-fn double-count).

## Successful Patterns

### 1. Bipartite audit + execution sessions across a session boundary

- **Description:** When a target is flagged "needs individual audit before execution" (predecessor session shape), splitting the work into `audit session → audit-committed-as-evidence → seed-with-execution-plan → execution session` produces a clean two-session unit where each half is independently revertable. The audit session's deliverable is the committed evidence + seed; the execution session's deliverable is the refactor + an intake-log entry that cites the audit's commit SHA.
- **Evidence:** Session 3d9d854e committed `8e99ec4` (28-line de-risk audit in intake) + `3013124` (189-line execution-plan seed). Session 78f772bd's first action was `git rev-parse HEAD` to confirm baseline `8e99ec4` (or descendant); pre-measure ran the seed's exact ast.walk script and got the seed's expected 14 unique import sites; edits applied symbol-based search-and-replace from the seed's catalog (NOT line-number-based, per the seed's own line-drift caveat); the resulting refactor commit `5e2cb18` has +15/-44 (vs. seed's predicted ~+15/-14, deletion delta noted in commit message). Rule #11 import smoke green on first attempt; ZERO rollback or rework. The seed's per-call Rule #30 audit predicted "no surprises" — and there were no surprises.
- **Applies when:** Any P3-style intake target where the seed flags "individual audit needed." Two consecutive sessions: first session does the audit, commits it, writes the next-session seed; second session executes from the seed. Cost: one extra session boundary; benefit: each half is small enough to fit comfortably in context, AND each half is independently revertable. This complements Rule #25 (per-file single-commit refactors) and Rule #27 (N additive + 1 cut-over for big splits) — those handle WITHIN-session decomposition; this handles BETWEEN-session decomposition.

### 2. Symbol-based search-and-replace beats line-number-based edits across session boundaries

- **Description:** When a multi-session work unit involves an audit committed in session N and execution in session N+1, file line numbers can drift between the two (other commits land, or the file is re-formatted). Using the import STATEMENT as the anchor for each edit (`from app.workers.unpack_common import widen_read_perms`) rather than the LINE NUMBER (`L362`) makes the execution robust to drift.
- **Evidence:** Seed-next-session-2026-04-25.md included BOTH a line-number catalog (L225, L343, L362, L412, L434, L473, L490, L527, L537, L355, L581, L614, L627, L675) AND an explicit risk note: "Line-number drift: If firmware_service.py is edited between this seed and execution, L-numbers in step 2 may drift. Mitigation: use the symbol-based catalog ... search-and-replace by content, not line number." Execution session honored the mitigation: every Edit tool call used `old_string` containing 2-3 lines of unique surrounding context (the import statement plus the line above and below). Zero edits failed; zero collisions on `replace_all=false`.
- **Applies when:** Any cross-session refactor where a seed/spec lists edit sites by line number. Treat line numbers as a catalog INDEX, not as the edit anchor. The actual anchor should be a symbol or unique string appearing in the line. Cost: a few extra characters per Edit call. Benefit: drift-resilience and obvious failure mode (Edit fails fast if the anchor isn't unique).

### 3. ast.walk nested-function double-count is a known artifact, not an error

- **Description:** When a function `inner` is defined inside an outer function `outer`, an ImportFrom node inside `inner.body` is reachable from BOTH `ast.walk(outer)` AND `ast.walk(inner)`. The naive counter `sum(1 for f in walk(tree) if isinstance(f, FunctionDef) for s in walk(f) if isinstance(s, ImportFrom))` double-counts that single statement. Mechanical fix: deduplicate by `(node.lineno, node.col_offset)` or use a single set traversal.
- **Evidence:** firmware_service.py L355 contains `from app.workers.unpack_linux import _firmware_tar_filter` inside `_extract_tar`, which is itself defined inside `upload`. Naive ast.walk count returned 15. Per-line enumeration showed two hits at L355 (one attributed to `upload`, one to `_extract_tar`). Visual inspection of L353-356 confirmed it's a single `from ... import ...` statement. Single deletion (one Edit call) cleared both apparent hits. Post-edit ast.walk count: 0 (single occurrence, single removal, count agrees).
- **Applies when:** Any ast.walk-based audit on Python code that may contain nested functions. Two robust counter shapes:
  - **Unique-line:** `len({(s.lineno, s.col_offset) for f in walk(tree) if isinstance(f, FunctionDef) for s in walk(f) if isinstance(s, ImportFrom) and s.module and s.module.startswith('app.')})`
  - **Single traversal:** Walk the whole tree once, gather ImportFroms, classify each by enclosing-function via parent-pointer. The naive nested-walk shape used in the seed/intake is FAST but susceptible to this artifact. Document the artifact in the file or commit message when raw count is published. (This is the second ast.walk error mode catalogued; combined with the predecessor session's docstring + multi-line continuation grep errors, total grep+ast bidirectional error modes documented = 4. Per Rule #31's "3rd incident promotes a rule" discipline, the ast.walk-specific issues are at incident #2; do NOT promote a Rule #32 yet, but the evidence is accumulating.)

### 4. Multi-line parenthesized imports inflate diff-stat -delete count without changing logical content

- **Description:** A function-body import like `from app.workers.unpack import (\n    detect_architecture,\n    detect_kernel,\n    detect_os_info,\n    find_filesystem_root,\n)` is ONE logical statement but SIX deleted lines in unified diff output. When predicting `git diff --stat` for a refactor that removes such blocks, multiply by ~5x for parenthesized multi-line imports.
- **Evidence:** Seed predicted `+15 ins / 14 del`. Actual: `+15 ins / 44 del` for `5e2cb18`. The 30-line delta is fully accounted for by 4 parenthesized multi-line imports being deleted. Commit message explicitly notes this calibration.
- **Applies when:** Any refactor-prediction in a seed/spec that estimates diff-stat numbers. Estimate INSERTIONS by counting top-level lines; estimate DELETIONS by counting actual deleted lines (not logical statements). Or: just say "+N logical imports, see commit for stat" and skip the misleading numeric prediction.

### 5. Rule #19 stop point recognition at diminishing-returns threshold

- **Description:** After 6 P3 carve-outs across 2 sessions (4 in 3d9d854e, 2 in 78f772bd), the residual function-body app.* import count across `backend/app/services/` dropped from ~50 (pre-Phase-5) to 18 across 15 files, with all remaining candidates at 1-2 imports each. At this point, each additional carve-out moves the count by 1-2, with the same per-target audit overhead (Rule #30). The marginal cost-benefit ratio inverts: audits become longer than the resulting code change. Recognising this pre-emptively and STOPPING (rather than chaining a 7th carve-out on momentum) honours Rule #19.
- **Evidence:** Seed explicitly listed `clamav_service.py`(2), `attack_surface_service.py`(2), `hardware_firmware/cve_matcher.py`(2) as "next-densest remaining candidates" and added: "But Rule #19 applies: no felt cycle pressure. Diminishing returns. Recommend STOP after firmware_service unless user directs further." Session 78f772bd executed firmware_service, logged the result, and explicitly did NOT chain a 7th carve-out. The user prompt for this session also reinforced the boundary: "Resist chaining a 7th carve-out (Rule #19: no felt pressure)."
- **Applies when:** Any continuation-style refactor session where the residual count is small-and-distributed and there's no concrete cycle pressure or build-time problem driving further work. The right answer is to STOP and let future sessions tackle individual files when actual pressure materialises (a real circular import, a build-time issue, a runtime cold-start cost). Aesthetic tidiness is not pressure. This pattern complements Rule #19 ("evidence-first before writing remediation code") at the strategic-pacing layer.

### 6. Single-commit Rule #25 precedent durable across 6 P3 sessions

- **Description:** Each P3 carve-out session has shipped its refactor as a single per-file commit, with a separate intake-log/ROUTER-update commit. Sessions: assessment_service (fc384bb + log), fuzzing+emulation (3 refactor commits + log), mobsfscan (2 refactor commits + log), hash_lookups (404f66d + log), wairz_runner (781a30e + log), firmware_service (5e2cb18 + log). Every refactor commit independently revertable; every log commit revertable without losing code; bisect-clean across the entire P3 chain.
- **Evidence:** `git log --oneline --grep='refactor.*promote function-body imports' --grep='refactor.*promote function-local imports'` returns the 6-commit refactor chain; each is `git revert <sha>` clean. The companion intake-log commits are similarly reversible without affecting code. Rule #25 status: stable across 6 sessions, no exception encountered.
- **Applies when:** Any continuation refactor session where the work is per-file. The shape is now mandatory (per the prior session's pattern #7 elevation). Any deviation should be flagged in the commit message with a reason.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Execute exactly the seed's catalog, no scope expansion | Seed represents pre-audited contract from prior session; treating it as the authoritative spec preserves the bipartite session shape | Clean execution, zero surprises, single refactor commit |
| Use symbol-based Edit anchors (not line-number) | Seed's own risk note flagged line-drift; mitigation cost is trivial | Zero drift collisions despite L355 being shared between two functions |
| Investigate the +1 ast count delta (15 vs seed's 14) before any edit | Rule #31 precedent: discrepancies between predicted and actual counts may be hidden scope or methodology error; cheap to verify | Identified nested-function double-count artifact; documented in commit + intake log; saved future audits from the same confusion |
| Honor Rule #19 stop point; do NOT chain 7th carve-out | User-prompt explicitly reinforced the boundary; seed itself recommended STOP; remaining candidates have no concrete pressure | Session ends clean at 2 commits; queue closed (`resolved/`) |
| Rule #20 fast-path (`docker cp` + exec) sufficient — no `docker compose restart` | Diff is import-only; no class-shape change (no fields added/removed/renamed); no module-level singleton invalidation | Smoke ran in <30s; no rebuild needed; matches predecessor session pattern |
| Move resolved seed to `.planning/intake/resolved/` (not delete) | Prior precedent: resolved seeds preserved as audit trail; SessionStart hook stops flagging it as pending | Clean queue; full history available for retrospective |
| Calibrate intake post-residual count to 18 (not seed's predicted 19) | The -1 delta is the L355 ast-walk artifact; correct number IS 18 | Honest log; future sessions re-running the same counter get 18 too |

## Verification shape used (durable from prior P3 sessions, with one addition)

```bash
# STEP 1: Confirm baseline matches the seed's pinned commit
git rev-parse HEAD  # expect 8e99ec4 or a descendant

# STEP 2: Pre-measure with the seed's authoritative counter
python3 -c "
import ast, pathlib
tree = ast.parse(pathlib.Path('<target>').read_text())
n = sum(1 for f in ast.walk(tree) if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef))
        for s in ast.walk(f) if s is not f and isinstance(s, ast.ImportFrom)
        and s.module and s.module.startswith('app.'))
print(n)
"
# If the count differs from the seed's prediction by 1-2, enumerate per-line
# (look for nested functions OR multi-line continuations) BEFORE editing.

# STEP 3: Per-import enumeration when a delta surfaces
python3 -c "
import ast, pathlib
tree = ast.parse(pathlib.Path('<target>').read_text())
for f in ast.walk(tree):
    if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for s in ast.walk(f):
            if s is not f and isinstance(s, ast.ImportFrom) and s.module and s.module.startswith('app.'):
                print(f'L{s.lineno}  fn={f.name}  from {s.module} import {[a.name for a in s.names]}')
"
# Two rows with same lineno = nested-function artifact (one statement, dedup)
# A row with lineno >= line-of-opening-paren but =! line-of-actual-import =
#     multi-line continuation (single statement, multi-line)

# STEP 4: Symbol-based search-and-replace per import (NOT line-number-based)
# Use Edit tool with old_string containing the import statement + 2 surrounding
# lines as anchor context; replace_all=false ensures unique-match-or-fail.

# STEP 5: Post-measure (expect 0)
# Re-run STEP 2.

# STEP 6: Rule #11 import smoke via Rule #20 fast-path
docker cp <file> wairz-backend-1:/app/<file>
docker cp <file> wairz-worker-1:/app/<file>
docker compose exec -T -w /app -e PYTHONPATH=/app backend \
  /app/.venv/bin/python -c "from app.services.<mod> import <Sym>"
docker compose exec -T -w /app -e PYTHONPATH=/app worker \
  /app/.venv/bin/python -c "from app.services.<mod> import <Sym>"

# STEP 7: Single refactor commit per Rule #25
git add backend/app/services/<mod>.py
git commit -m "refactor(<mod>): promote function-body imports to top-level ..."

# STEP 8: Separate intake-log + ROUTER + seed-resolution commit
git mv .planning/intake/<seed>.md .planning/intake/resolved/<seed>.md
# Edit intake log + ROUTER.md
git add ...
git commit -m "intake: log session ... ; close seed; update ROUTER residual"
```
