# Patterns: P3 session aa8b4a17 — triple-close at the structural floor

> Extracted: 2026-04-24
> Session: aa8b4a17 (user-directed continuation past the session-78f772bd Rule #19 stop)
> Commits: `8f9d261` clamav_service, `4bd491b` attack_surface_service, `9a26c1a` cve_matcher, `78669d3` intake log + ROUTER, `e84f02e` intake frontmatter close
> Source intake: `.planning/intake/backend-private-api-and-circular-imports.md` (now `status: completed`)
> Predecessor: `firmware-service-p3-execution-2026-04-24-patterns.md` (6th carve-out; this file is carve-outs 7/8/9 + thread close)
> Postmortem: none — clean execution, no incidents to autopsy

## Context

This session closed the P3 thread on `backend-private-api-and-circular-imports`. The user explicitly overrode the session-78f772bd "Rule #19 stop" recommendation with: *"we have cycles to burn down backlog so we can proceed as long as we burn down risk first and proceed with deep research and thinking at each step and across steps."* Three files with 2 lazy imports each were candidates: `clamav_service.py`, `attack_surface_service.py`, `hardware_firmware/cve_matcher.py`.

Headline outcome: 3 refactor commits + 2 bookkeeping commits; repo residual went 18/15 → 12/12 (flat 1-per-file distribution). Intake `status: partial → completed`; ROUTER "Not yet built" queue is now empty. 0 reverts, 0 smoke failures, 0 cross-file surprises.

## Successful Patterns

### 1. Risk-ordered triple-play in one session (ascending blast-radius)

- **Description:** Execute N P3 files in a single session, ordered by ASCENDING blast-radius (fewest downstream callers first). Each successful Rule #11 smoke validates the playbook before the next, riskier candidate. Complements Rule #25 (per-file commits) with an intra-session ordering discipline.
- **Evidence:** This session: clamav (4 callers: hash_lookups + router + 2 tool sites) → attack_surface (4 callers: router + tool×2 + test) → cve_matcher (11 callers: router + tool×2 + 4 test files + backfill_detection script). The simplest case (clamav, 2 duplicate get_settings imports, pure-stdlib target) cleared first in <5 min; the edge case (cve_matcher, Tier-1-stub + Tier-5 intra-subpackage) cleared last with extra try/except-semantics analysis already informed by the cleaner precedents. Zero regressions; each commit `git revert <sha>` clean.
- **Applies when:** Any P3-style session with 2+ candidate files to carve-out in one go. Blast-radius rank is one `grep -rn "from app.services.<mod>" backend/` call per candidate, runnable in parallel at the top of the session. Accept the ordering as a fail-fast safety net — it costs nothing and demotes the highest-risk file until you've validated the mechanics twice. Inverse rule: if cycles pressure you to do only ONE file this session, pick the LOWEST blast-radius (safest), not the highest-density (more improvement).

### 2. Parallel width-canary triage ahead of sequential execution

- **Description:** At the TOP of the session, run Rule #31 (narrow/wide/wider grep) + Rule #28 (`ast.walk` unique-line pre-measure) + blast-radius grep on ALL candidate files IN ONE PARALLEL BASH BATCH, before any editing. Converts "N sequential audits" into "1 parallel scoping pass + N mechanical executions." Cost: one bash call (~5s); benefit: every audit input is on the table before a single edit.
- **Evidence:** This session's opening batch triaged all 3 files in a single message: `grep -nE "^\s+from app\." <file>` × 3 (narrow vs wide canary), `wc -l` × 3 (Rule #28), `grep -rn "from app.services.<mod>" backend/` × 3 (blast-radius). Result: all 3 files confirmed narrow==wide==wider=2 (Rule #31 held; no under-counting), LOC known (174 / 536 / 610), caller counts known (4 / 4 / 11). From that single table, risk ordering was mechanical. Contrast: per-file triage during execution would have repeated the same tool-load cost 3x and left earlier execution blind to later files' context.
- **Applies when:** Any N≥2 refactor session where the candidate files share a common audit shape (function-body imports, caller-list size, target-leaf purity). The width-canary is cheap enough (~1s per file) to run even when you think the counts are right — the downside-case (narrow missed hidden scope) is session-wrecking; the upside-case (canary confirmed) costs a few seconds of parallel I/O.

### 3. Identity-check assertions in Rule #11 smoke catch rebinding bugs

- **Description:** After promoting an import, add an in-container Python one-liner that imports the symbol from BOTH the source module AND the target module and asserts identity: `from app.services.analysis_service import check_binary_protections as original; from app.services.attack_surface_service import check_binary_protections as promoted; print('identity:', original is promoted)`. Distinguishes "zero ImportError" from "zero accidental rebinding." Would catch Rule #10 (router function shadowing service import), a pasted `check_binary_protections = ...` assignment that shadows the import, or a broken re-export at the service-module scope.
- **Evidence:** This session ran identity checks on both non-trivial promotions:
  - attack_surface: `original is promoted` for `check_binary_protections` → True.
  - cve_matcher: identity on `CpeDictionaryService` (True) AND on the aliased `kvi` module object (True).
  Zero bugs found — but the ASSERTION is the deliverable, not the result. Prior sessions' smokes stopped at "import did not raise," which silently passes if the symbol is re-bound to a router function with the same name. Identity is a separate invariant and cheap to assert.
- **Applies when:** Any promotion where the target symbol is a function, class, or module-object (not a primitive like `int`/`str`). Especially load-bearing when the file uses Rule #10 shadowing conventions (suffix `_endpoint` for router functions sharing a name with service imports).

### 4. Fail-soft semantic classification at the import-site level

- **Description:** When a function-body import lives inside `try/except Exception`, the decision for promotion is NOT automatic — it depends on whether the except catches an IMPORT failure or a CALL failure. Three shapes observed this session, each handled differently:
  - **Import inside try/except, but top-level of target is reliable:** Remove the import; keep the except wrapping the subsequent runtime call(s). Example: attack_surface L193 `analysis_service.check_binary_protections` — elftools is a hard dep, no module-load failure possible; except catches pyelftools runtime errors on malformed ELF. Diff: `try: from ... import X; return X(path)` → `try: return X(path)` (with X now top-level).
  - **Import inside try/except, target has HEAVY optional deps:** Keep lazy. Example (NOT in this session, but the rule): a module importing `torch` or `tensorflow` inside try/except for a fallback pipeline — promotion would slow cold-start and fail for minimal deployments.
  - **Import OUTSIDE try/except, try starts AFTER the import:** Plain promotion; no semantic change. Example: cve_matcher L481 `kernel_vulns_index as kvi` — the try at L484 wraps `await kvi.is_populated()`, not the import.
- **Evidence:** cve_matcher L251 (inside try, cpe_dictionary_service top-level is httpx+redis+stdlib — reliable): promoted, kept try/except around `svc = CpeDictionaryService(); await svc.ensure_loaded()`. cve_matcher L481 (outside try): promoted, no try/except change. attack_surface L193 (inside try, analysis_service top-level is elftools — hard dep present in all Docker environments): promoted, kept try/except around the CALL. All 3 cleared Rule #11 smoke + identity check.
- **Applies when:** Any P3 candidate whose lazy import is inside `try/except Exception`. Don't treat the try/except as blocking — read it, classify the failure mode, and promote if the except's purpose is runtime-safety rather than import-safety. The mechanical check: (a) grep target module's top-level for fragile/optional deps; (b) if all reliable → promotable with try/except kept around the CALL; (c) if any optional/heavy → keep lazy (Rule #30 caveat a/b). Do NOT leave the try/except unchanged wrapping a top-level name; rebalance to wrap only the call.

### 5. Orthogonal latent-bug discipline — document-don't-fix during refactors

- **Description:** When a per-call audit surfaces a latent bug ORTHOGONAL to the refactor's contract, document it in the commit message's observation section; do NOT fix it in the same diff. Preserves atomic diffs, matches CLAUDE.md's "don't expand scope," and creates an audit trail for future session reopening. The refactor's Rule #30 chain completes without collateral risk.
- **Evidence:** attack_surface audit surfaced: `_LIEF_ELF_ARCH_MAP` is a module-level empty `dict[int, str] = {}` populated ONLY by `binary_analysis_service._ensure_lief()` via `.update()`. attack_surface never calls `_ensure_lief()`, so `arch = _LIEF_ELF_ARCH_MAP.get(binary.header.machine_type)` returns None unless some OTHER caller in the same process has triggered population. This is a silent side-effect dependency — a real latent bug in the architecture-reporting path. Commit `4bd491b` documented it in a dedicated "Behavior preservation" paragraph but did NOT add a `_ensure_lief()` call to attack_surface. Rationale: dict-by-reference Python semantics mean the import promotion is behavior-preserving regardless; fixing the side-effect-dependency is a separate product decision (arch is a nice-to-have, not load-bearing) and deserves its own diff + reviewer context.
- **Applies when:** Any refactor where a Rule #30 audit reads enough surrounding code to surface unrelated findings. Mechanical tell: if a discovery's fix would (a) touch files outside the refactor's scope, OR (b) change a runtime behavior not described in the refactor's intent, OR (c) require a separate test to validate — it belongs in the commit-message "out-of-scope observation" section and optionally in a new intake item, NOT in the diff. This generalises CLAUDE.md Rule #19 (evidence-first) to refactor hygiene: the diff describes WHAT changes; the commit message describes WHAT ELSE WAS FOUND AND LEFT ALONE.

### 6. Structural floor recognition as a QUANTITATIVE stop signal beyond Rule #19

- **Description:** Rule #19 says "stop when you don't feel cycle pressure" (qualitative). This session upgraded the stop signal with a quantitative test: when the residual distribution becomes FLAT 1-per-file across the candidate set, each additional carve-out delivers −1 on the repo-wide count at full Rule #30 audit + Rule #11 smoke + separate commit cost. There is no gradient left to exploit; cost-benefit ratio is at its worst. This is the "structural floor."
- **Evidence:** Pre-session: 18 runtime function-body `app.*` imports across 15 files (via `ast.walk` unique-line). Distribution was: 3 files with 2 each + 12 files with 1 each. After clearing the three 2-import files, distribution becomes: 12 files with 1 each. Flat. Each subsequent carve-out would clear exactly one file for the full Rule #30 + Rule #11 overhead. The intake's original P3 acceptance criteria ("audit-based, scoped per service pair, not bulk") is STRUCTURALLY satisfied at this boundary. The intake frontmatter was updated `status: partial → completed` on this rationale, not on "no felt pressure."
- **Applies when:** Any multi-session refactor thread where the work is per-file and each file's audit overhead is roughly constant. Monitor the residual distribution (not just the count). The transition from "some files with 2+ each, rest with 1 each" to "all files with 1 each" is the floor — past it, the work is marginal and deserves close. Qualitative stop (Rule #19) + quantitative stop (structural floor) together form a stronger close signal than either alone. Intake/ROUTER updates should cite BOTH when closing.

### 7. Alias preservation at promotion time saves N call-site edits

- **Description:** When promoting an aliased function-body import (`from X import Y as Z`) to top-level, PRESERVE the alias. Dropping the alias at promotion time requires rewriting every call site from `Z.foo()` to `Y.foo()` — zero-gain mechanical churn, and a Rule #22 multi-file grep/edit loop.
- **Evidence:** cve_matcher L481 was `from app.services.hardware_firmware import kernel_vulns_index as kvi`. Grep showed `kvi.is_populated()`, `kvi.lookup(...)` across Tier 5. Promotion kept `as kvi`; 0 call-site edits required. Identity check `kvi is kernel_vulns_index` → True confirms the alias is the module itself. Alternative (drop alias, edit callers): ~6 edits in the same file, zero behavioral change, extra noise in the diff and extra Rule #11 smoke surface. Rejected.
- **Applies when:** Any `from X import Y as Z` being promoted. The alias is a local symbol table entry; it costs nothing to preserve. The only time to drop the alias is if it's dead code (not used anywhere in the file post-promotion) — grep first.

### 8. Intra-subpackage cycle-check must read `__init__.py`

- **Description:** When a module `pkg/foo.py` is about to import a sibling `pkg/bar.py` at top level, the cycle-check must read `pkg/__init__.py` too. If `__init__.py` eagerly imports anything that transitively reaches `pkg/foo.py`, the new top-level import in `pkg/foo.py` creates a cycle at `pkg/foo.py`'s module load — detected only at runtime as `ImportError: cannot import name 'X' from partially initialized module`.
- **Evidence:** cve_matcher (in `services/hardware_firmware/`) was about to import `services/hardware_firmware/kernel_vulns_index` at top level. Cycle-check: `hardware_firmware/__init__.py` eagerly imports `detector`, which transitively imports `classifier + parsers + firmware_paths + models.*`. None of these reach cve_matcher. Cycle-safe. If `__init__.py` had done `from .cve_matcher import match_firmware_cves`, the promotion would have been a cycle. Mechanical check: `head backend/app/services/hardware_firmware/__init__.py` before any intra-subpackage top-level import.
- **Applies when:** Any intra-subpackage top-level promotion. The `__init__.py` is an often-skipped input to the cycle-check; it's easy to focus on the TARGET module's top-level and miss the `__init__.py`'s eager imports. Add it to the mechanical checklist for this class of refactor.

### 9. P3 thread close bookkeeping shape

- **Description:** After the final carve-out of a multi-session intake thread, the close bookkeeping produces a 2-commit tail: (a) a "log" commit that adds the session's progress paragraph to the intake body + updates ROUTER residual + records the new session short hash, and (b) a "close" commit that updates the intake frontmatter (`status: partial → completed`, adds `completed_at`, `completed_in`, `shipped_commits` list of all SHAs in the thread, `closed_by` human-readable string) plus a ROUTER "Not yet built" queue cleanup. The close commit is bookkeeping-only, no code change.
- **Evidence:** This session: commit `78669d3` (log + ROUTER residual; 2 files, 14 lines) followed by commit `e84f02e` (intake frontmatter + ROUTER queue close; 2 files, 26+ lines). The frontmatter updated to the shape already present on other completed intakes (`infra-cleanup-migration-and-observability.md`, `security-auth-hardening.md`) — `shipped_commits: [list of SHAs]` + `closed_by` field. ROUTER's "Not yet built" section went from "P3 residual promotion..." to "(None.)" and the 12 residual 1-each files moved to "Known issues" as dormant. Separating log from close keeps the log commit re-runnable (every session adds to it; no collision) and makes the close commit a clean atomic status transition.
- **Applies when:** Any intake/campaign thread closure. The 2-commit shape beats 1-commit because the log and close are conceptually different operations and the close commit's diff is the most scannable audit trail ("this is the moment the status changed"). `git revert <close-sha>` reopens the thread without losing the log entry.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Execute all 3 in one session despite session-78f772bd Rule #19 stop recommendation | User explicit direction ("burn down risk first, deep research at each step and across steps"); cycles available; candidate blast-radii ≤ 11 callers (manageable audit scope) | Clean — no regressions, P3 thread closed, 5 commits shipped |
| Risk-ordered execution (clamav → attack_surface → cve_matcher) | Lowest blast-radius first = cheapest fail-fast; each success validates the playbook before the next | All 3 passed Rule #11 smoke on first attempt; cve_matcher (judgment-call file) benefited from prior 2 as reference |
| `import clamd` kept lazy in clamav_service | Rule #30 caveat (a): optional third-party dep; top-level import would break environments without python-clamd | Legitimate lazy-import preserved; deploys unchanged |
| Try/except around `check_binary_protections(path)` CALL retained; only import promoted | Analysis_service's elftools import is a hard dep (reliable); runtime exceptions on malformed ELF are the actual fail-soft concern | Behavior-preserving; fail-soft semantics preserved |
| `as kvi` alias preserved on top-level import | N call-sites use `kvi.is_populated`/`kvi.lookup`; dropping the alias = zero-gain mechanical churn | Zero call-site edits; diff stayed atomic |
| `_LIEF_ELF_ARCH_MAP` latent bug documented in commit but NOT fixed | CLAUDE.md: "don't expand scope beyond task requires"; bug is orthogonal to the lazy-import refactor's contract | Documented for future; refactor stayed atomic; audit trail preserved for when the product-side arch reporting is reopened |
| P3 thread closed (status: partial → completed) at 12/12 flat residual | Structural floor reached — qualitative (Rule #19) + quantitative (no gradient) stop signals both active | Intake frontmatter updated with shipped_commits list; ROUTER cleaned |
| No new quality rules appended to harness.json | All session-extractable patterns are procedural (session-shape, audit-sequence discipline) rather than code-level regexes; existing rules already cover enforceable patterns | Knowledge files written; harness.json unchanged |

## Verification shape used (evolution of the P3 playbook)

```bash
# STEP 0 (NEW): Parallel width-canary triage on ALL candidates, before editing
for f in backend/app/services/X.py backend/app/services/Y.py backend/app/services/Z.py; do
  echo "=== $f ==="
  wc -l "$f"
  grep -nE "^\s+from app\.(services|ai|models|schemas)\." "$f" | head -20   # narrow
  grep -nE "^\s+from app\." "$f" | head -30                                   # wide
  grep -nE "^\s+(from app\.|import app\.|importlib\.)" "$f" | head -30       # wider
  grep -rn "from app\.services\.<mod>" backend/ 2>/dev/null | head -20       # blast-radius
done
# Agreement narrow==wide==wider → trust the count. Divergence → investigate BEFORE any edit.
# Rank candidates by blast-radius ASCENDING for execution order.

# STEP 1: ast.walk authoritative pre-measure (per file, unique-line)
python3 -c "
import ast, pathlib
for p in ['<file1>', '<file2>', '<file3>']:
    tree = ast.parse(pathlib.Path(p).read_text())
    sites = set()
    for f in ast.walk(tree):
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for s in ast.walk(f):
                if s is not f and isinstance(s, ast.ImportFrom) and s.module and s.module.startswith('app.'):
                    sites.add((s.lineno, s.col_offset, s.module, tuple(a.name for a in s.names)))
    print(f'{p}: {len(sites)} sites')
    for ln, col, mod, names in sorted(sites):
        print(f'  L{ln}  from {mod} import {names}')
"

# STEP 2 (per file, sequential): Rule #30 per-import audit
#   a. Check target module's top-level for fragile/optional deps
#      head backend/app/services/<target>.py | grep -E "^(from|import) "
#   b. Check target has no reverse import to the file being edited
#      grep -n "<file_base>" backend/app/services/<target>.py
#   c. Check tests for patch("app.services.<file>.<symbol>") — Rule #30 reverse
#   d. For intra-subpackage: ALSO check __init__.py eager imports
#      head backend/app/services/<pkg>/__init__.py

# STEP 3 (per file): Symbol-based Edit with try/except semantic classification
#   - If import inside try/except AND target top-level is reliable:
#     remove import; keep except wrapping subsequent CALL
#   - If import outside try/except: plain move to top-level
#   - Preserve `as alias` if present and used by callers

# STEP 4 (per file): ast.walk post-count (expect 0) + py_compile
python3 -c "..."
python3 -m py_compile backend/app/services/<file>.py

# STEP 5 (per file): Rule #11 import smoke via Rule #20 fast-path
docker cp <file> wairz-backend-1:/app/app/services/<file-relative>
docker cp <file> wairz-worker-1:/app/app/services/<file-relative>
docker compose exec -T -w /app -e PYTHONPATH=/app backend \
  /app/.venv/bin/python -c "
from app.services.<mod> import <Sym1>, <Sym2>
# IDENTITY CHECK (catches Rule #10 shadowing + rebinding bugs):
from <source_module> import <Sym1> as _orig
from app.services.<mod> import <Sym1> as _prom
print('identity:', _orig is _prom)
"
# Also smoke downstream blast-radius (router, tool, tests that depend on it)

# STEP 6 (per file): Single commit per Rule #25
git add backend/app/services/<file>.py
git commit -m "refactor(<file>): promote function-body imports to top-level

Move L<N> ... to module top-level.

Cycle-safety (Rule #30):
- Target top-level: <summary>
- Reverse check: zero patch() sites
- [intra-subpackage] __init__.py eager imports: <summary>

[Any orthogonal latent observation:]
- <finding> — documented; out-of-scope for this refactor

Nth P3 carve-out. File residual X → 0.
Rule #11 import smoke green on backend + worker + <blast-radius>;
identity check 'original is promoted' passes.
"

# STEP 7 (end of session, after last refactor): 2-commit close
# (a) Log commit: append session paragraph to intake + update ROUTER residual
# (b) Close commit: intake frontmatter (status + shipped_commits + closed_by)
#     + ROUTER "Not yet built" queue update
```
