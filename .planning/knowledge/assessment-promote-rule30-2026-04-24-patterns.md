# Patterns: assessment_service promotion + Rule #30 codification (2026-04-24)

> Extracted: 2026-04-24
> Campaign: none (direct session work — commits `e343c52` → `565c9d7`)
> Postmortem: not found
> Audit telemetry: 30 tool-call events (routine), no alerts
> Session: `5eefecb0-2105-4717-bcb8-c386f2e22c62`

## Successful Patterns

### 1. Four-route scoring with evidence before executing the seed's default recommendation
- **Description:** Given a seed with 4 named routes (A/B/C/D) and a nominal recommendation, refuse to execute blindly. Build an evidence matrix: for each route, grep / measure the premise. D was marked "low yield" but turned out to be **empty** (all 20 arch-review items' frontmatter `status: completed`). A's named cycle pair was **stale** (`security_audit_service` deleted in Phase 5). C had 3 concrete obligations (untracked files, Rule #30 candidate, Rule #21 sync). B had zero pressure signals. The cheapest refutation per route was a single grep or `ls`; the scoring completed in ~3 minutes and inverted the default ranking.
- **Evidence:** Session transcript Step 1-2 cross-checks; `status:` grep matrix across `.planning/intake/*.md`; fresh `grep -rn "^from app\.services\.$mod\b"` per callee of `assessment_service`.
- **Applies when:** Inheriting a seed / intake / plan older than 48 h. Re-verify named entities still exist, named cycles are still cyclic, named scopes still match reality. The base rate for seed-to-execution drift in wairz observed this session: Phase 5 Part 2 deleted a service 3 days before the seed referenced it by name.

### 2. Double-grep cycle audit before promoting any lazy import (forward + back)
- **Description:** Two one-liner greps per candidate import: **forward** `grep -rln "^from app\.services\.<mod>\b" backend/app/ | grep -v <self>` — if N>0, the module is ALREADY top-level-imported elsewhere, so lazy-import here saves zero startup cost and is safe to promote. **Back** `grep -rn "from app\.services\.<self>\|<SelfClass>" backend/app/services/<mod>*` — if 0, the callee does not back-import; no cycle forms. For this session: 9 assessment_service callees × 2 greps = 18 queries, all done in one `Bash` call, 2 seconds wall-clock. Result: 8/10 modules already top-level elsewhere (sbom at 21 other importers, security_audit at 9, etc.); 0/9 back-imports. Pre-flight safety established cheaply.
- **Evidence:** Session Step 2 grep output — `sbom: 21 top-level importers elsewhere`, `security_audit: 9`, etc.; back-import audit returned `(empty = no cycles)`.
- **Applies when:** Any lazy→top-level promotion. Mandatory per CLAUDE.md Rule #30 companion guidance. Cheap enough to do pre-commit every time. Companion to Rule #11 runtime smoke — grep is first-order, smoke is transitive-cycle-safety-net.

### 3. Runtime import smoke in the REAL container (not local py_compile) — Rule #30 companion
- **Description:** After promoting N function-local imports in `assessment_service.py`, ran `docker cp <file> <container>:/app/... && docker compose exec backend python -c "from app.services.assessment_service import AssessmentService, <12 promoted symbols>"`. First run failed: `ImportError: cannot import name 'ComplianceService' from 'app.services.compliance_service'. Did you mean: 'ETSIComplianceService'?`. This defect was **invisible** to `python -m py_compile` — both `ComplianceService` and `ETSIComplianceService` are valid Python identifiers; only actually resolving against the current module object catches stale references. Same smoke in the worker container confirmed worker-specific import paths (worker has a slightly different entrypoint).
- **Evidence:** Session Step "Verification pass" output — `Traceback ... line 23 ... ImportError: cannot import name 'ComplianceService'`; fix at commit `fc384bb`; post-fix smoke: `OK: all 12 promoted imports resolve cleanly` in both backend + worker.
- **Applies when:** Any top-level import added to a service module. The smoke is Rule #30's mandatory companion for lazy→top-level promotions, but the principle generalizes to any "new top-level import" change — py_compile checks syntax, not resolution.

### 4. Same-commit Rule #21 sync: CLAUDE.md + .mex/context/conventions.md Verify Checklist
- **Description:** When adding CLAUDE.md Rule #30 (commit `01ca65d`), the same commit appended the mirror line to `.mex/context/conventions.md` Verify Checklist. Rule #21 explicitly mandates "in the same commit"; splitting creates a window where the checklist disagrees with canonical rules — exactly the rot Rule #21 was created to prevent. Diff-stat: `2 files changed, 3 insertions(+)`.
- **Evidence:** `git show --stat 01ca65d` — both CLAUDE.md and `.mex/context/conventions.md` mutated atomically; `.mex` entry cites `Learned Rule #30` by number, preserving the cross-reference.
- **Applies when:** Any addition, modification, renumbering, or removal of a CLAUDE.md Learned Rule. The `.mex/context/conventions.md` Verify Checklist is auto-derived from CLAUDE.md per its own prologue (`Derived from CLAUDE.md Learned Rules (canonical source)`); sync is not optional.

### 5. Reframing the task scope pre-execution: "mechanical cleanup" when "surgical cycle-breaking" no longer applies
- **Description:** The seed framed Route A as surgical ("pick ONE cycle pair and ship a single-session fix"). Evidence showed Phase 5 had already removed the cycles; the remaining function-locals were mostly import-laziness artifacts. Task rescoped mid-plan to "mechanical promotion of one heaviest file (10 service imports + 1 model + 1 cross-layer `app.ai.tools.binary`)" — less glamorous but shippable with a clean acceptance grep and zero cycle-surgery risk. Narrative shift: from "break a cycle" to "clean up a relic."
- **Evidence:** `backend-private-api-and-circular-imports.md` intake's own "Phase 3 is open-ended" guidance; session fresh-audit showing 0 back-imports across 9 callees; `security_audit_service` deletion harness rule confirming the seed's named pair was stale.
- **Applies when:** An intake's chosen scope depends on assumptions (e.g., "cycle exists") that have been invalidated by subsequent work. Re-scope to what the code actually needs, not what the intake imagined. Companion to Rule #28 (LOC re-measure): both rules are evidence-first rescoping.

### 6. Per-import Rule #30 legitimate-lazy audit, not mechanical sweep
- **Description:** 2 of 10 service imports in assessment_service were candidates for Rule #30 legitimate-lazy protection: `yara_service` (yara-python is a C-extension that cold-loads) and `androguard_service` (LGPL + slow). For each: inspected the target module's own top-level imports. **`yara_service.py` already does `import yara` at top level** — meaning `yara` loads whenever anything imports `yara_service`; so this file's LAZY-import in assessment_service saved zero cost (the cost was already paid by yara_service's other importers, and there's 1). **`androguard_service.py` does NOT import `androguard` at top level** — it lazy-imports within method bodies; so importing the wrapper CLASS `AndroguardService` at top level is safe (the LGPL / cold-import cost is still deferred until `AndroguardService().scan(...)` actually runs). Both promoted safely. A mechanical sweep without the per-target top-level audit would have either (a) produced dead work (yara was always top-level) or (b) promoted an LGPL-contaminating symbol (if someone had done `from app.services.androguard_service import APK` instead of the wrapper class).
- **Evidence:** Session Step 2b grep output — `yara_service` top-level: `import yara\nfrom app.services.security_audit import SecurityFinding`; `androguard_service` top-level: stdlib + `ManifestChecker` only, no `androguard` at top.
- **Applies when:** Any lazy→top-level promotion touching a wrapper around an optional / slow / licensed dependency. The wrapper class is usually safe; the library primitives are usually not. Per-target top-level `grep -E "^import |^from "` takes 1 second and resolves the question.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Execute C before A | Doc edits discharge Rule #21 sync obligation before any new code references the rule; if A breaks, C's durable value survives a revert. | Both shipped cleanly. Rule #30 codified BEFORE the promotion that demonstrated it, giving the commit message a citable rule number. |
| Promote `AndroguardService` wrapper, not androguard primitives | Rule #30 legitimate-lazy protected at the LIBRARY boundary (androguard lazy-imports stay inside `androguard_service.py` method bodies); wrapper import is cycle-free and cost-free. | Promotion shipped without triggering androguard cold-import at startup (verified by backend startup still passing healthcheck post-rebuild). |
| Fix ETSI/ComplianceService latent bug in the SAME commit as the promotion | Bug surfaced BECAUSE of the promotion (import smoke caught it); single-commit attribution keeps `git revert` and `git bisect` clean. | Commit `fc384bb` is one atomic "promote + fix-discovered-bug" unit; revert takes both back together. |
| Single-file atomic commit for A, not per-import commits | Import-block reorganization is atomically one change; Rule #25 exception "single-atomic-change task is one commit" applies. Per-import commits would churn the import block N times and produce meaningless micro-diffs. | One commit `fc384bb`, diff-stat `12 insertions + 31 deletions`, coherent to read. |
| No new harness quality rule added | Existing harness already catches the androguard-narrow case (`patch.*androguard.*(APK\|AnalyzeAPK\|DEX\|dx)`). ETSI/Compliance rename is a one-off; a rule would be narrow and non-durable. Phase-wrapper `try/except pass` pattern is too broad for a safe regex. | Skipped — Rule #30 doc is the durable form; narrow regex enforcement isn't needed on top. |
| Intake housekeeping in a fourth separate commit | Seed-update + P3-progress-note are doc changes orthogonal to both C and A; bundling with A would mix code + planning intent. | Commit `565c9d7` cleanly separable; seed status field now reflects reality for next session's bootstrap. |

## Metrics

- Commits: **4** (e343c52 knowledge commit, 01ca65d Rule #30 + mex sync, fc384bb refactor + bug fix, 565c9d7 intake housekeeping)
- Files touched: **6** (2 knowledge files, CLAUDE.md, `.mex/context/conventions.md`, assessment_service.py, 2 intake files)
- Rule #30 runtime import smoke surfaced: **1 latent bug** (`_phase_compliance` dead since `ETSIComplianceService` rename)
- Function-local `from app.services.*` delta: codebase **37 → 26** (-11); assessment_service: **10 → 0**
- Test regressions: **0** (55 adjacent tests pass; 1710 tests collect clean)
- Rebuild required at session end: backend + worker (Rule #8) — completed post-session
- Tests for `_phase_compliance` found: **0** (explains latent-bug longevity)
