# Anti-patterns: P3 carve-out — mobsfscan/ pair (continuation)

> Extracted: 2026-04-24
> Session: f2f9060c continuation
> Commits: b213795, ff111d2, 681a592

## Failed Patterns (near misses — none triggered to completion this session)

### 1. Interpreting a stale-container smoke as refactor failure

- **What was done:** Post-edit Rule #11 import-smoke was run against the live backend container (15h old, image predates this session). First result: `hasattr(normalization, 'Finding') = False`, same for `enrich_description`, `enrich_evidence`, `get_jadx_cache`. Looks like the refactor broke the modules.
- **Near-miss failure mode:** If diagnosed as a refactor bug, the natural next step would have been to revert `b213795` and/or `ff111d2` and search for the "bug" that doesn't exist. The refactor is correct; the containers are stale. A misdiagnosis here destroys good commits and introduces actual regression in the subsequent re-attempt.
- **Evidence:** First smoke invocation returned all `False`. Second invocation (same command, same python, same container) AFTER `docker cp normalization.py + pipeline.py into both backend and worker` returned all module attributes correctly. Rule #20 correctly diagnoses this: "A running backend/worker container with no dev bind mount won't see host-side new files."
- **How to avoid:** Before treating any in-container import smoke result as evidence of refactor failure, verify that the container actually has the edited files. Two options:
  - **Check container age vs. edit time:** `docker compose ps --format '{{.Service}}\t{{.Status}}'` — if uptime > edit timestamp, container has stale code.
  - **`docker cp` the edited files in** (Rule #20 fast-path when diff is imports-only / no class-shape change) and re-run the smoke.
  A False smoke result against a stale container is indistinguishable from a refactor bug on the surface; the diagnosis is a Rule-20 mechanical tell, not semantic.

### 2. Flattening TYPE_CHECKING-guarded imports "to simplify the import list"

- **What was done:** Did NOT do this — but the temptation was present. normalization.py has a `TYPE_CHECKING:` block at lines 41-45 that imports `AsyncSession`, `MobsfScanResult`, and `FirmwareContext` as type-only symbols. When promoting `enrich_description` / `enrich_evidence` to runtime (which loads the `app.utils.firmware_context` module at import time anyway), `FirmwareContext` becomes a runtime-loaded module member regardless of whether its import line sits inside TYPE_CHECKING or not. Tempting conclusion: "flatten it — the TYPE_CHECKING guard is now redundant for FirmwareContext."
- **Near-miss failure mode:** Flattening defeats the selective runtime-vs-type-only intent. `AsyncSession` stays TYPE_CHECKING-only because sqlalchemy is a heavy dep and the module uses it ONLY in type hints; the guard is there to avoid importing sqalchemy at module load for modules that don't need it at runtime. Mixing type-only and runtime concerns into a single flat block either (a) forces sqlalchemy to load when this module loads (wrong) or (b) requires splitting the block anyway (no net change). Additionally, `MobsfScanResult` genuinely cannot be promoted — `app.services.mobsfscan.parser` imports FROM `mobsfscan/__init__.py` indirectly, creating a cycle at module-import time. TYPE_CHECKING is the correct tool for that case.
- **Evidence:** TYPE_CHECKING block preserved untouched in both files. Post-edit measurement: `grep '^\s\+from app\.'` returns 3 lines; all 3 are inside the TYPE_CHECKING block.
- **How to avoid:** TYPE_CHECKING block is a deliberate design decision by whoever wrote the module. Treat it as a black box for the duration of a mechanical promotion refactor. Only touch it if the refactor's scope is explicitly "audit TYPE_CHECKING correctness" (different task, different rules).

### 3. Picking firmware_service.py because its density ranking is highest

- **What was done:** Did NOT do this. Post-session residual: `firmware_service.py` carries 14 runtime function-local `app.*` imports — nearly 3× the next-highest file. Ranking purely by "most imports = biggest cleanup win" would have put it at the top of the next session's list.
- **Near-miss failure mode:** Seed-next-session-2026-04-24.md explicitly flagged firmware_service as "non-mechanical" BEFORE the count was even widened. The widened count (14) LOOKS like a fat win but firmware_service sits close to workers (unpack, `wairz_runner`), background tasks, and the Firmware model graph — multiple top-level call sites in `routers/`, `workers/`, `ai/tools/filesystem.py`. Many of those 14 imports likely have legitimate-lazy reasons (circular-avoidance, lazy worker dep, optional file-format deps via unblob/binwalk). A bulk mechanical promotion would ship at least one real latent-cycle bug OR slow startup by forcing worker-only deps into the main import graph.
- **Evidence:** Seed file `.planning/intake/seed-next-session-2026-04-24.md` Option A section; intake paragraph in `cac98ad` and the predecessor's pattern #6 ("Don't assume firmware_service.py's 14 imports repeat the clean-mechanical profile").
- **How to avoid:** Density ranking is ONE factor, not the only one. Always read the seed's "non-mechanical" / "needs individual audit" flags before sorting candidates. When a seed explicitly warns against a file, the warning overrides the count. If a future session DOES want to tackle firmware_service, it should run per-call Rule #30 audits on each of the 14 lazy imports (optional-dep / LGPL / latent-cycle classification) and split the work across multiple sessions, not one mechanical sweep.

### 4. Applying the predecessor's mechanical-safe profile without re-verifying (related to predecessor antipattern #3)

- **What was done:** Did NOT do this. Even though this is the 3rd consecutive session in the chain, each of the 4 promotion targets (Finding, enrich_description, enrich_evidence, get_jadx_cache) got a fresh cycle-safety audit:
  - `grep -n "mobsfscan" <target_module>.py` — checks reverse-dep (target module imports mobsfscan?)
  - `grep "^\(from\|import\) " <target_module>.py` — lists target's own top-level imports
- **Near-miss failure mode:** The predecessor session warned: "No bulk promotions based on 'the last session was clean.' Each target is its own evidence case." If this session had trusted the predecessor's cleanliness, it would have skipped the jadx_service audit — and jadx_service has 3 top-level `app.*` imports (config, `_cache`, `utils.hashing`). If any of those had back-imported mobsfscan, promoting `get_jadx_cache` to module-scope in pipeline.py would have produced a cycle at import time.
- **Evidence:** Audit log at 15:15:45Z shows the reverse-dep grep (`Does jadx_service import mobsfscan?` / `Does firmware_context import mobsfscan?` / `Does models/finding import mobsfscan?`) — all 3 returned 0 matches. Forward-dep grep at 15:25Z shows jadx_service imports only `app.config`, `app.services._cache`, `app.utils.hashing`.
- **How to avoid:** Fresh per-target audit every session. The audit takes <30s per target and is evidence, not intuition.

## Quality Rule Candidates

No high- or medium-confidence candidates emerge from this slice.

- **Rule #31 width-canary:** Already canonical in `CLAUDE.md`; the discipline is a workflow step (run-two-greps-compare), not a regex that can be matched against source files.
- **TYPE_CHECKING preservation:** Regex `^\s+from app\.` fires on BOTH legitimate TYPE_CHECKING lines AND genuine lazy imports. A harness rule would produce false positives on every module that uses `from __future__ import annotations` — roughly 40% of the backend. Skip.
- **Rule #20 stale-container diagnosis:** A mental checklist, not a regex. No harness rule fits.
- **First-party patch-target audit:** The existing `auto-pytest-mock-patch-androguard-at-service` narrow rule already covers the high-risk family (third-party Android deps); a broader `patch\s*\(\s*["']app\.` rule would fire on legitimate test mocks (99% of which are correct). Skip.
- **"Don't promote firmware_service bulk":** Session-specific; not rule-shaped.

No entries added to `.claude/harness.json` qualityRules.custom this session. Predecessor reached the same conclusion; the pattern is stable.
