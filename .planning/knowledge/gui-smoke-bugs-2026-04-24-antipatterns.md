# Anti-patterns: GUI golden-path smoke (post-P3 verification, 2026-04-24)

> Extracted: 2026-04-24
> Campaign: `.planning/intake/gui-smoke-bugs-2026-04-24.md` (intake-as-campaign — single-session smoke)
> Postmortem: not found
> Source session: `d8edd200-4399-44f2-bf9f-374feccc1c02`

## Failed Patterns (anti-patterns the smoke surfaced or witnessed)

### 1. Concurrent long-ops on shared backend without considering memory

- **What was done:** Fired `POST /security/audit` (long-op, 700s ceiling) in background and `POST /hardware-firmware/cve-match` (long-op) in foreground simultaneously, expecting them to be independent.
- **Failure mode:** Backend kernel-OOM'd at ~100s. Both calls returned `HTTP=000` with no response written. Backend container restarted, lost ~5 minutes of audit progress.
- **Evidence:** `/tmp/wairz-smoke-logs.txt` shows `Killed` at line 12 (UTC 23:39:55), 11× CPE dictionary loads in a 3.1s window from cve-match's `_match_chipset_cpe`, audit's findings flush abandoned mid-pipeline.
- **How to avoid:** When two long-ops both load module-level singletons or large in-memory indexes, their concurrent memory footprints can exceed the container limit. Either run sequentially OR provision higher container memory before parallelism. For exploratory smoke, sequential is always safer — concurrent runs only become valuable when total elapsed time is the constraint, AND each individual op's memory ceiling is known.
- **Rule-#23-adjacent observation:** This is the single-process analog of Rule #23's worktree discipline. Concurrent file edits on a shared checkout corrupt commit attribution; concurrent long-ops on a shared backend corrupt resource-attribution diagnostics. Isolation in both cases prevents diffuse failure modes.

### 2. Per-call instantiation of a Redis-backed service that already has a singleton accessor

- **What was done:** `cve_matcher.py:253` does `svc = CpeDictionaryService()` inside `_match_chipset_cpe`, which is called per blob with `chipset_target IS NOT NULL`. The module already exports `get_cpe_dictionary_service()` at line 354 as a singleton accessor, but this caller bypasses it.
- **Failure mode:** With 11 chipset-tagged blobs in this firmware, 11 fresh `CpeDictionaryService` instances were created, each loading the 37,268-product CPE index from Redis into a per-instance `self._index` dict. Combined memory exceeded the 4 GiB container limit → kernel SIGKILL.
- **Evidence:** Log shows exactly 11 "CPE dictionary loaded from Redis cache (37268 products)" events in a 3.1-second window during the OOM-causing run; `SELECT chipset_target, COUNT(*) ... WHERE chipset_target IS NOT NULL` returns exactly 11 (10× am4372, 1× bcm43438) — the perfect 1:1 confirms causation.
- **How to avoid:** Whenever a module exports both a class AND a `get_*_service()` singleton accessor, prefer the accessor. Direct class instantiation is appropriate ONLY for tests that want to bypass shared state. Production callers always go through the accessor.
- **Mechanical detection (regex candidate, low confidence):** `(\w+Service)\(\)` followed within 5 lines by `\.ensure_loaded\(\)` or `\.load\(\)` is suspicious. Too many false positives to ship as a quality rule.
- **Companion lesson:** The bug predated the P3 carve-out by 8 days (commit `1fbcce4` vs `9a26c1a`). The P3 work moved the `CpeDictionaryService` import to module top-level, which made the stale instantiation pattern more visible during smoke — but did NOT introduce it. **Refactors can surface latent bugs without causing them**; git blame is the discriminator.

### 3. VARCHAR-bounded title field for path-derived strings

- **What was done:** `findings.title` is `VARCHAR(255)`. The credentials-detector composes title as `f"Hardcoded credential in {path}"` where `{path}` can be the full nested-extract path (e.g., `/zImage-restore.tar.xz_extract/xz.uncompressed_extract/.../etc/ImageMagick-7/delegates.xml`).
- **Failure mode:** Audit ran the entire scanner pipeline + 4-source threat-intel loop across 3 firmwares (~12 minutes) and only failed at the per-finding `db.flush()` with `StringDataRightTruncationError: value too long for type character varying(255)`. The exception bubbled up to the request handler and rolled back the ENTIRE audit transaction — zero findings persisted.
- **Evidence:** Failed-row from `/tmp/wairz-smoke-logs.txt` at UTC 00:05:08; title length ~290 chars in a 255-byte column. Existing-finding distribution (max title length across all sources = 211 chars) confirms the column had never been stress-tested by deeply-nested firmware.
- **How to avoid:** Whenever a column stores a path, a path-derived label, or any string composed from external/file-tree input, default to `Text` or at minimum `String(1024)`. Use `String(N<=255)` only for fixed-vocabulary fields (status, severity, source enum strings).
- **Rule #15 instance #2:** First was `analysis_cache.operation` VARCHAR(100→512) for JADX cache keys (Java class names with synthetic lambdas). Same pattern: developer-time intuition about field length under-estimates production data length. Now two recurrences — bordering on a documented quality rule.
- **Pre-existing, not P3-caused:** `git log --since='2026-04-21' backend/app/models/finding.py` returns no commits; the schema was untouched by the P3 work.

### 4. Lazy-populated module-level dict relied on without ensuring the populating side-effect ran

- **What was done:** `binary_analysis_service.py:16` declares `_LIEF_ELF_ARCH_MAP: dict[int, str] = {}`, populated by `_ensure_lief()` via `.update(...)`. `attack_surface_service.py:142` reads it with `.get(machine_type)` but the scan path doesn't call `_ensure_lief()` first.
- **Failure mode:** Lookup returns `None` for every blob; `signals.architecture = arch (=None)`; persisted as NULL across 1624 `attack_surface_entries` rows. GUI Attack Surface page renders an empty arch column for every row.
- **Evidence:** DB query `SELECT COUNT(*) FILTER (WHERE architecture IS NULL)` = 1624/1624. Documented explicitly in commit `4bd491b`'s message: "Pre-existing latent semantic — if nobody in the session calls binary_analysis_service._ensure_lief() first, _LIEF_ELF_ARCH_MAP.get(...) always returns None. Out-of-scope for this refactor; documented for the audit trail."
- **How to avoid:** Module-level mutable state populated lazily by a side-effect function is OK, but every consumer code path MUST either (a) call the populating function explicitly at entry, OR (b) the populator must be idempotent and called at module init. Consumer-side responsibility is fragile — a new caller (or one in a different code path that wasn't audited) silently gets the empty default. Prefer ensuring population at module init when the cost is bounded (LIEF cold-import is ~500ms; only forced if any ELF arch lookup happens).
- **Companion lesson — believe the prior commit's "documented but not fixed" notes.** The P3 author deliberately documented this latent bug rather than expanding scope. The smoke confirmed the documentation accurate; the fix is now scheduled for next session via the intake. Reading commit messages saves duplicate investigation.

### 5. Trusting client-side `HTTP=000` as evidence the server work failed

- **What was done:** Fired `curl -s -m 700 -X POST .../security/audit` and observed `HTTP=000 time=699.999875s`. Initial assumption: "audit failed at 700s timeout."
- **Failure mode:** The backend continued processing the request asynchronously for ~10 more minutes after curl gave up (audit's `await loop.run_in_executor` calls don't yield to detect peer disconnect). The actual failure (`StringDataRightTruncationError`) happened at UTC 00:05:08, ~10 minutes AFTER curl exited at 23:56:35. The "audit failed at 700s" hypothesis would have missed the real bug.
- **Evidence:** Log timestamps: curl exited at 23:56:35 (per `time=699.999875s` math), threat-intel HTTP calls continued through 23:58:46, persistence flush failure at 00:05:08.
- **How to avoid:** When curl times out on a long-op endpoint:
  1. The server may still be processing — verify via continued log activity, not just the curl exit code
  2. The work may eventually complete OR fail at a stage curl never observes
  3. Ground truth is `docker compose logs backend` + DB state queries, not the HTTP response
- **Rule #29 corollary:** even with aligned timeouts, the client and server can disagree about "did this complete." Frontend timeout alignment is necessary but not sufficient — for production use cases, the 202+polling pattern (firmware unpack precedent, emulation/fuzzing fix shipped 2026-04-20) is the durable answer because the server response is decoupled from the work duration.

### 6. Mistaking pre-existing bugs for refactor regressions

- **What was done:** Initial reaction to the OOM was "did the P3 carve-out break cve_matcher?" Initial reaction to arch=NULL was "did the P3 carve-out break attack_surface_service?"
- **Failure mode:** False causation hypothesis. Without `git blame`, the next 30+ minutes would have been spent reverting / re-auditing the P3 imports (which were correctly promoted) — wasted work.
- **Evidence:** `git blame -L 250,260 backend/app/services/hardware_firmware/cve_matcher.py` immediately resolved to commit `1fbcce4` from 2026-04-16 (8 days before the P3 work at `9a26c1a`). Same pattern for the other two bugs.
- **How to avoid:** When a refactor and a bug coincide in time, the cheap default is to ASSUME the refactor caused it. The cheaper test is `git blame {file}:{line}` + commit-date comparison. ~30 seconds per check. If blame predates the refactor by days/weeks → regression hypothesis is dead, look elsewhere. Refactors can MAKE bugs visible (because the affected code is now exercised differently) without CAUSING them.
- **Pattern reinforcement:** Pattern #5 in the patterns file documents this discipline — anti-pattern #6 here is its mirror, the failure mode the discipline prevents.

---

## Addendum: Fix-session anti-patterns (2026-04-25, session 56797be2)

> Failures observed during execution against the intake's three-bug spec.

### 7. `docker cp` + Rule #11 import smoke is INSUFFICIENT for verifying a long-lived process picked up the change

- **What was done:** Bug #1's fix swapped two lines in `cve_matcher.py` (import + call site). Per intake spec + Rule #20, used `docker cp backend/app/services/hardware_firmware/cve_matcher.py wairz-backend-1:/app/...` (and to wairz-worker-1) plus a Rule #11 import smoke: `docker compose exec -T backend /app/.venv/bin/python -c "from app.services.hardware_firmware.cve_matcher import match_firmware_cves; print('ok')"`. Both succeeded. Proceeded to commit.
- **Failure mode:** First post-fix `/cve-match` smoke ran the OLD code anyway. The 11× CPE dictionary loads (the exact pre-fix behaviour the intake was eliminating) appeared in logs at 21:07:26 onwards, and the backend OOM-killed at 21:08:57. The fix was on disk in both containers, but the running uvicorn process had cached the OLD `cve_matcher` module in `sys.modules` BEFORE the docker cp arrived. Subsequent imports inside the live process returned the cached module.
- **Why Rule #11 import smoke didn't catch this:** `docker compose exec backend python -c "from ... import ..."` spawns a NEW Python subprocess that imports fresh from disk. That subprocess ran the new code correctly. But the long-lived uvicorn process is a SEPARATE Python interpreter — it doesn't share `sys.modules` with the smoke subprocess.
- **Evidence:** `docker inspect wairz-backend-1` showed `RestartCount: 1` after the first cve-match (vs 0 pre-smoke); the backend's startup log at 21:11:27 (post-restart) eagerly loaded the dictionary again — visible in logs. The SECOND cve-match smoke (post-OOM-restart) showed 0 CPE dictionary loads — the fix was in effect ONLY after the kernel-induced restart cleared the module cache.
- **How to avoid:** For ANY change to a Python module that the running uvicorn process imports — even pure function-body call swaps — the minimum-safe pattern is `docker cp` + `docker compose restart <service>` (~5–10 s for a service that boots fast and doesn't need a new image layer). Rule #11 import smoke remains useful (it verifies syntactic correctness + module loads cleanly in isolation), but it is NOT sufficient to verify the change is LIVE in the running process. Treat Rule #11 as a "loadability check," not a "deployed check."
- **Candidate Rule #20 sub-clause refinement:** the existing Rule #20 caveat covers class-shape changes (cached mappers, `BaseSettings` lru_cache). This anti-pattern extends the caveat to ANY function-body change in a module the running process imports — because Python's module cache is invariant to the cause of the change. The mechanical tell is unchanged: "if the diff modifies a Python file under a directory the running process imports from, assume a restart is needed."
- **Companion bitter lesson:** the FIRST cve-match smoke that ran the old code was attributed to the intake's hypothesis ("11 CPE dictionary loads → OOM"). It LOOKED like the fix didn't work. Only after re-running on the post-OOM-restarted backend (with 0 CPE loads) did the actual residual surface. Another minute of `docker compose restart backend` after `docker cp` would have eliminated this confusion entirely.

### 8. Trusting an intake's "single root cause" hypothesis when the endpoint touches multiple unaudited tiers

- **What was done:** Intake's Bug #1 analysis attributed the cve-match OOM entirely to per-blob `CpeDictionaryService()` instantiation: "11 chipset-tagged blobs × 11 fresh CpeDictionaryService instances × 37,268 CPE products each." Acceptance criteria #2 said "backend memory rises by < 200 MiB during the call (single dictionary load, not 11)." Fix shape was a 2-line swap.
- **Failure mode:** Fix WAS correct (eliminated the 11× loads). But cve-match endpoint STILL OOMs the backend at ~85 s with 0 CPE dictionary loads in the log. Intake hypothesis was complete-but-narrow: per-blob instantiation was ONE memory hog, not the only one. The unaudited Tier 4 (`_match_kernel_cpe`, kernel components × kmod blobs matrix) and Tier 5 (`_match_kernel_subsystem`, Redis-backed kernel.org vulns.git CNA index) are most likely candidates for the residual cause.
- **Why the intake missed this:** The pre-fix smoke OOM'd at the 11× CPE-load phase BEFORE Tier 4/5 work was reached. The intake's investigator could only see the first OOM trigger; later tiers' memory pressure was masked by the earlier OOM. After the fix, the work progresses past Tier 1 into the previously-masked code paths and exhausts memory there too.
- **Evidence:** Post-fix smoke produced ZERO log lines during 85 s of cve-match work (between request start and kernel-kill), then the backend restarted. The silent window matches Tier 4 / Tier 5 (both `async def` doing pure DB / Redis work without per-iteration logging). Bug #1's commit f71f978 IS correct in isolation; its acceptance criterion #2 fails because the criterion was written against an incomplete model of the endpoint.
- **How to avoid:** When an intake's hypothesis blames ONE function in a multi-tier endpoint for an OOM, especially when the diagnosis is built on log evidence from a smoke that crashed early — TREAT THE INTAKE'S BLAME AS THE FIRST HYPOTHESIS, NOT THE ONLY ONE. Before declaring "fix complete," explicitly check (a) does the endpoint have other significant memory consumers? (b) was the pre-fix smoke able to exercise those? If (a)=yes and (b)=no, expect the fix to surface the masked next bug. The right disposition is: ship the fix, acknowledge the partial completion, file a follow-up.
- **Companion to Rule #19:** evidence-first applies to intake hypotheses too. The intake describes the investigator's BEST GUESS at the time of writing; live re-verification is the discipline.

### 9. POST request body conventions: query vs JSON-body parameter placement

- **What was done:** First `/attack-surface/scan?force_rescan=true` smoke sent `force_rescan` as a URL query parameter and `{}` as the JSON body. Backend returned 200 in 0.38 s with `architecture: null` for every entry — looked like the Bug #2 fix had failed.
- **Failure mode:** Wrong parameter location. The endpoint's signature is `body: AttackSurfaceScanRequest | None = None` and `force_rescan = body.force_rescan if body else False`. URL query params bound to function parameters DIRECTLY don't reach `body`. With `body == {}` (or default empty body), `force_rescan` was False → endpoint returned cached pre-fix entries. Cached entries had `architecture: null` from BEFORE the fix.
- **Evidence:** Re-running with `-d '{"force_rescan": true}'` (JSON body) returned 200 in 14.5 s (matches intake's prior 16.6 s), and DB query confirmed arch=NULL went from 1624 to 11 (1613 entries now arch='arm').
- **How to avoid:** Read the endpoint's Pydantic body model BEFORE composing the curl request. The intake provided the correct curl invocation (`-d '{"force_rescan": true}'`); the fix-session author rewrote it incorrectly because the URL-query convention is more familiar. Mechanical check: when an endpoint accepts a `body: SomeRequest | None` parameter, parameters MUST go in `-d '{...}'`, not URL query. URL query is for parameters whose function signature is `force_rescan: bool = False` directly (FastAPI `Query`-bound).
- **Cost:** ~1 minute of investigation + one re-run. Cheap to fix once spotted; would have cost much more if the cached-results behaviour had been mistaken for a fix-failure and triggered un-needed code investigation.

### 10. 15-minute smoke budget vs ~16-minute audit reality (operational under-budgeting)

- **What was done:** User-spec abort condition: "If the smoke re-run hangs past 15 minutes total: STOP and capture log state." The /security/audit alone took ~16 min wall-clock (with no failures, all scanners running fully). Total smoke: ~23 min.
- **Failure mode:** The 15-min budget didn't account for the fact that AFTER the Bug #3 fix, the audit would run THROUGH the prior crash point and into MORE phases. Pre-fix, audit "took ~12 min" because it crashed at the per-finding flush; post-fix, audit succeeds and continues into more scanners + threat-intel HTTP calls. Wall-clock GROWS with the fix, not shrinks.
- **Evidence:** Pre-fix smoke (intake's d8edd200 session): "audit | (curl -m 700 timed out at 11m40s; backend continued detached)". Post-fix smoke (this session): findings flushed at ~16 min total elapsed, then more scanner phases continued for additional minutes.
- **How to avoid:** When budgeting smoke time AFTER a fix that removes an early-failure shortcut, expect the post-fix runtime to EXCEED the pre-fix runtime — the work that previously crashed early now completes. Add a 1.5-2× factor over pre-fix observed wall-clock. For this audit, a ~20-25 min budget would have been appropriate; 15 min was unrealistically tight for the spec.
- **What this session did:** Continued past the 15-min mark because evidence was decisive (findings count growing, 0 truncation errors). Per the abort condition's spirit ("hangs"), the audit wasn't hanging — it was making progress. But this is a judgment call; a stricter reading of the spec would STOP at 15 min regardless.
- **Companion lesson:** Abort conditions defined as "X minutes total" are fragile when the underlying work duration is itself a downstream of the fix being applied. Better forms: "if no DB activity for 5 consecutive minutes" or "if container restarts during the smoke." Behaviour-based aborts beat clock-based aborts when the clock is the variable being affected.

### 11. Pre-execution scaffolded knowledge files vs post-execution actual learnings

- **What was done:** The discovery session (d8edd200) wrote BOTH the intake AND the `gui-smoke-bugs-2026-04-24-{patterns,antipatterns}.md` files at 14:29-14:30 UTC, BEFORE the fix session even began. The files documented the SMOKE session's own learnings (how the bugs were found) and stayed untracked-in-git pending later confirmation.
- **Failure mode (potential):** The fix session might have invoked /learn and naively OVERWRITTEN the discovery-session content with fix-session content, losing the (correct, valuable) discovery learnings. Or, conversely, /learn might have been a no-op against the existing files because they already exist.
- **What this session did:** Read the existing files first; recognized they cover the discovery session; APPENDED a clearly-marked "Fix-session lessons" addendum rather than overwrite. Both sets of learnings are preserved with attribution.
- **How to avoid:** Before invoking /learn (or any extraction skill that writes to existing files), READ the existing files. If they already contain content from a prior session that is still valuable, append rather than overwrite. The /learn skill's idempotency guarantee is "rerunning is safe" but it doesn't protect against semantic loss when two sessions have different relevant lessons for the same intake/campaign slug.
- **Process insight:** Multi-session intakes (one for discovery, one for execution) benefit from ADDITIVE knowledge updates, not overwrite. Single-session intakes can use overwrite safely.
