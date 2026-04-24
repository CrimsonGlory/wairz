# Patterns: P3 carve-out — mobsfscan/ pair (continuation)

> Extracted: 2026-04-24
> Session: f2f9060c continuation
> Commits: b213795, ff111d2, 681a592
> Source intake: .planning/intake/backend-private-api-and-circular-imports.md (partial)
> Driver: .planning/intake/seed-next-session-2026-04-24.md (+A-prime-continuation)
> Predecessors: .planning/knowledge/p3-carveout-fuzzing-emulation-2026-04-24-patterns.md · .planning/knowledge/assessment-promote-rule30-2026-04-24-patterns.md
> Postmortem: none (sub-campaign slice)

## Context

Third P3 carve-out in the "promote function-local imports to top-level" theme; **first session to operate under codified Learned Rule #31** (width-canary for grep-derived scope counts, committed in `836b24d`). Predecessor's antipattern #1 ("narrow regex silently under-reported residual work") graduated into a canonical rule this session; the discipline was applied PRE-edit rather than discovered post-hoc.

Scope: `mobsfscan/normalization.py` (2 runtime → 0) + `mobsfscan/pipeline.py` (2 runtime → 0, de-duplicated to 1 top-level import). 4 genuine runtime function-local imports promoted. 3 `TYPE_CHECKING`-guarded imports preserved untouched. No revert, no test breakage, one Rule #20 false-negative near-miss diagnosed and recovered.

Mechanical-safe profile now validated across **5 files in 3 sessions** (assessment_service + fuzzing_service + emulation/service + emulation/user_mode + mobsfscan/{normalization,pipeline}).

## Successful Patterns

### 1. Rule #31 width-canary APPLIED pre-edit (not discovered post-hoc)

- **Description:** First thing after resolving the target was to run both the narrow and broad grep patterns side-by-side. Broad `^\s+from app\.` returned 7 hits across the two files; narrow `^\s+from app\.(services|ai|models|schemas)\.` returned 4. The 3-hit delta was entirely `app.utils.firmware_context` imports that the narrow pattern structurally cannot match. A saturation check (`import app\.` + relative + `importlib.import_module`) returned 0 new hits — pattern saturated at 7.
- **Evidence:** Audit log entries at 15:15:05Z (broad), 15:15:06Z (narrow), 15:15:08Z (saturation). The narrow count would have silently under-reported scope by 43% (4 of 7). If the session had acted on the narrow count, 3 real lazy imports in `normalization.py` would have been invisible and the "pair cleared" claim would have been false.
- **Applies when:** Any session that enters with a grep-derived scope count. Rule #31 mandates the canary; this session is evidence that applying it pre-edit (vs. post-hoc) is materially cheaper — no wasted edits on an under-scoped plan.

### 2. TYPE_CHECKING-vs-runtime triage separates legitimate lazy imports from candidates

- **Description:** The broad `^\s+from app\.` regex catches BOTH runtime function-body imports AND `if TYPE_CHECKING:`-block imports — both are indented `from app.*` lines. Before classifying any hit as a promotion target, `sed -n` the surrounding block and determine whether the enclosing scope is `if TYPE_CHECKING:` (legitimate, preserve) or a function body (genuine lazy, audit). In this session: 7 broad hits → 3 TYPE_CHECKING-guarded (normalization lines 44-45; pipeline line 50) + 4 runtime (normalization 469, 477; pipeline 243, 257). Only the 4 runtime were promotion candidates.
- **Evidence:** normalization.py pre-edit had 4 broad hits; post-edit has 2 broad hits remaining (the TYPE_CHECKING block). pipeline.py pre-edit had 3; post-edit has 1. Zero TYPE_CHECKING lines were disturbed.
- **Applies when:** Any file that uses `from __future__ import annotations` + `if TYPE_CHECKING:` for type-only imports. TYPE_CHECKING is PEP 484's sanctioned mechanism to import sqlalchemy/pydantic/large deps for type hints without paying the runtime cost; flattening those imports into module scope defeats the optimization and can introduce circular imports that TYPE_CHECKING was installed to avoid.

### 3. Coalesce duplicate lazy-imports on promotion (extends predecessor's pattern #2)

- **Description:** pipeline.py's 2 function-body imports (lines 243, 257) were BOTH `from app.services.jadx_service import get_jadx_cache` — in sibling `@staticmethod` helpers `_materialise_sources_from_cache` and `_ensure_decompilation`. Promotion collapsed both to a single top-level import. Net: +1 insert, -4 deletes on pipeline.py.
- **Evidence:** `git show ff111d2 --stat` reports `1 file changed, 1 insertion(+), 4 deletions(-)`. Same pattern as predecessor session's user_mode.py (2 `sysroot_service.get_sysroot_path` sites → 1 top-level).
- **Applies when:** Multiple function-body imports of the same symbol in the same file. Net byte reduction, cleaner diff, same semantics.

### 4. Rule #30 first-party audit (not just third-party)

- **Description:** Rule #30's core text targets third-party symbols (androguard, etc.). For first-party `app.*` promotions, the `patch()` risk is lower but not zero — a test could monkey-patch `app.services.mobsfscan.normalization.Finding` to inject a test model. Audit ran `grep -rnE 'patch\s*\(\s*["']app\.services\.mobsfscan\.(normalization|pipeline)\.(Finding|enrich_description|enrich_evidence|get_jadx_cache)'` — returned 0. Safe to promote without breaking any test.
- **Evidence:** Audit command logged at 15:18Z; zero matches. Also zero top-level test imports of these internal modules.
- **Applies when:** Any lazy-import-to-top-level promotion, even for purely first-party symbols. Cost: one grep. Prevents silent test breakage from stale `patch()` targets.

### 5. Rule #20 fast-path + diagnostic recovery when first smoke looks failed

- **Description:** Rule #11 import-smoke needs to run in-container, but both backend and worker were 15h old (image pre-dates this session's edits, no bind mount). First smoke attempt (before docker-cp) returned `hasattr(normalization, 'Finding') = False` and similar for all four promoted symbols — looked like the refactor had broken the module. Correct diagnosis: the container's `/app/...` paths still hold the PRE-edit source; the import succeeded but against the old code where these symbols were only function-body imports (not module attributes). Fix: `docker cp <host>:<container>:<path>` for both files into both containers, re-ran the same smoke — all green. No restart needed (pure import reordering, no class-shape change per Rule #20).
- **Evidence:** Two smoke invocations — first returned `False` for all 4 attributes; after `docker cp` of normalization.py + pipeline.py into backend and worker, second invocation returned the symbols' `__name__` strings and `persist_mobsfscan_findings still has old body imports? False`.
- **Applies when:** Any session where the edited files are under a path that is NOT bind-mounted into the running container, AND the container image was built before the current edits. If first smoke looks broken, check Rule #20 stale-container diagnosis BEFORE assuming the refactor is wrong. Cost to verify: one `docker cp` pair + re-run. Cost of misdiagnosis: rolling back good commits.

### 6. Per-file commit + intake-update commit per Rule #25 (durability now at 3 sessions)

- **Description:** 2 refactor commits (`b213795` normalization, `ff111d2` pipeline) + 1 intake-doc commit (`681a592`). Each refactor touches exactly 1 file in `backend/app/services/`; each has an isolated `git revert` target. The intake paragraph was appended (not overwritten) to preserve the audit trail of the 3-session chain: 5eefecb0 (assessment) → f2f9060c (fuzzing + emulation) → f2f9060c-cont (mobsfscan).
- **Evidence:** `git log --oneline -5` shows the clean per-commit boundary. `681a592` diff adds +2 lines in the intake doc + updates 1 line in the seed status — zero code churn.
- **Applies when:** Any multi-file refactor session where the final step is a doc update. The intake update is always the LAST commit so the code is atomically revertable without the doc rolling back with it.

## Key Decisions

| Decision | Rationale | Outcome |
|---|---|---|
| Scope = mobsfscan/{normalization,pipeline} only (not firmware_service) | Seed explicitly flagged firmware_service as non-mechanical; density ranking (14 broad hits) is a red flag not a green light | Session closed cleanly at 3 commits; firmware_service deferred to a future session with proper per-call audits |
| Preserve all 3 TYPE_CHECKING-guarded imports untouched | Minimal blast radius; TYPE_CHECKING is a sanctioned PEP-484 optimization; promoting those lines defeats the optimization and may introduce runtime sqlalchemy import on modules that only need it for type hints | Post-edit: 3 TYPE_CHECKING hits remain (all legitimate); 0 runtime function-body `app.*` imports |
| De-dupe pipeline's 2 `get_jadx_cache` body imports to 1 top-level | Single source of truth; smaller diff; same semantics | `ff111d2`: +1/-4 net |
| docker cp both edited files into backend + worker (Rule #20 fast-path) | No class-shape change; imports-only diff; `docker cp` + venv-python smoke runs in <30s vs 3-5min rebuild | Smoke green post-cp; rebuild deferred naturally |
| Commit intake+seed update AFTER both refactors, not inline with either | Separates doc drift from code drift; preserves independent-revert property per Rule #25 | `681a592` revertable without touching `b213795` or `ff111d2` |

## Verification shape used each slice (copyable — unchanged from predecessor)

```bash
# Per-file, after Edit tool sequence:
grep -nE '^[[:space:]]+from app\.' <file>          # expect: only TYPE_CHECKING-guarded hits, none in function bodies
python3 -m py_compile <file>                       # Rule-17-adjacent sanity
docker cp <file> $(docker compose ps -q backend):/app/<file>
docker cp <file> $(docker compose ps -q worker):/app/<file>
docker compose exec -T -w /app -e PYTHONPATH=/app backend /app/.venv/bin/python \
  -c "from app.services.X import Y; print(Y.__name__)"
docker compose exec -T -w /app -e PYTHONPATH=/app worker  /app/.venv/bin/python \
  -c "from app.services.X import Y; print(Y.__name__)"
git add <file> && git commit -m "refactor(X): promote function-local imports to top-level ..."
```

## Applicability envelope for the next carve-out

The mechanical-safe profile has now shipped across:
- session 5eefecb0: `assessment_service.py` (11 imports)
- session f2f9060c: `fuzzing_service.py` (4) + `emulation/service.py` (3) + `emulation/user_mode.py` (2)
- session f2f9060c cont: `mobsfscan/normalization.py` (2 runtime) + `mobsfscan/pipeline.py` (2 runtime → 1 after de-dupe)

**5 files, 3 sessions, 22 genuine runtime promotions, 0 reverts, 0 class-shape rebuilds.** The pattern is now durable enough to be the default shape — BUT see antipattern #3 (firmware_service is flagged non-mechanical for a reason).

Remaining mechanical-safe candidates (widened residual, TYPE_CHECKING-excluded; next session should re-measure per Rule #28):
- `security_audit/hash_lookups.py` (5 runtime)
- `wairz_runner.py` (3 runtime)
- `hardware_firmware/cve_matcher.py` (2 runtime)
- `clamav_service.py` (2 runtime)
- `attack_surface_service.py` (2 runtime)
- 13 more files at 1 runtime each

Before trusting this profile for a 6th file:
1. Re-grep current counts under `^\s+from app\.` pattern (Rule #28 anti-drift — intake counts age at 14-22% growth rate per Rule #28 evidence).
2. Run Rule #31 width-canary: broad vs narrow, investigate any delta.
3. TYPE_CHECKING-triage every hit before classifying as a promotion target.
4. Rule #30 audit on the target module's own top-level imports + reverse-mention grep.
5. If ANY target is NOT pure-leaf (imports other `app.services.*` at top level), DROP that promotion and investigate lazy-legitimacy per Rule #30.

Do NOT pick `firmware_service.py` based on density alone. Seed's explicit "non-mechanical" flag is evidence-backed — firmware sits close to workers, unpack pipelines, and model graph; 14 lazy imports span deep cross-layer coupling that needs individual Rule #30 legitimate-lazy audits.
