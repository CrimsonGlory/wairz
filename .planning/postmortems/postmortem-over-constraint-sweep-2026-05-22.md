# Postmortem: Over-Constraint Sweep — Rate-Limit + Resource Ceilings + Silent Caps + DB Column Widening

> Date: 2026-05-22
> Campaign: ad-hoc session (no formal campaign file; routed via Citadel 4-scout Wave-1 audit + per-piece execution per validated do-them-all pattern)
> Duration: ~3.5 hours (10:43 first user prompt → 14:15 final commit; 5 shipping commits + 1 housekeeping commit, plus the upload-fix kick-off before the audit even started)
> Outcome: completed
> Trigger: operator reported failed firmware upload → diagnosis surfaced (a) frontend nginx env-drift on `MAX_UPLOAD_SIZE_MB` AND (b) RIGHT-IN-FRONT-OF-THE-USER `TIER_A_HEAVY` rate-limit on `/firmware/{id}/unpack` that would block iterative research workflow even after the upload-size fix → operator directed "deep research and deep review all the places we have over-constrained" → 4-scout Wave-1 audit → 5-commit per-piece execution

## Summary

Operator hit HTTP 413 on a 2.46 GiB upload (nginx `client_max_body_size: 2048M` despite `.env` declaring `MAX_UPLOAD_SIZE_MB=20480` — frontend container 17 hours stale with the Dockerfile default). Immediate fix was a 1-command `docker compose up -d --force-recreate frontend` that re-ran `envsubst` against the current env. Operator then asked WHY there was an unpack rate limit and directed a full over-constraint audit.

4 parallel Wave-1 research scouts (rate-limit decorators / frontend timeouts + polling / resource ceilings + concurrency / code-level constraints) returned 50+ findings across 4 axes. Synthesis surfaced a SYSTEMIC defect: Rule #51's tier framework had been applied with the wrong axis — endpoints were tagged `TIER_A_HEAVY` based on "the work takes a while", not "the work pins the backend event loop". Six rate-limit decorators were misclassified; seven other surfaces (resource ceilings, silent caps, DB columns) had Rule-#15-family or Rule-#29-derivation drift.

5-commit per-piece sweep shipped per Rule #25 single-slice discipline: (1) rate-limit re-tier; (2) arq/walker concurrency to match the new burst envelope; (3) timeout misalignments (backend subprocess + frontend axios + frontend polling cadence); (4) silent output cap surfacing (MAX_FINDINGS_PER_CHECK + 3 SBOM JSON truncations + 2 `+N more` sentinels); (5) DB column widening per Rule #15 family.

## What Broke

### 1. Frontend container env-drift on `MAX_UPLOAD_SIZE_MB`

- **What happened:** `.env` declared `MAX_UPLOAD_SIZE_MB=20480` (20 GiB). Backend container picked up the value 14h ago via a backend rebuild. Frontend container had been running 17h with the Dockerfile-baked default `2048M`. `nginx.conf.template` runs `envsubst` at container START (not build), so the substitution was frozen at the env-at-startup-time value. Operator's 2.46 GiB upload hit nginx with HTTP 413 on 4 retry attempts (12:11-12:13). The backend never saw the request.
- **Caught by:** Symptom report ("I just tried to upload a file and it didn't succeed"). I read frontend nginx logs and traced the 413 to the live nginx config (`client_max_body_size 2048M`) vs the declared env (20480).
- **Cost:** Direct operator friction (4 failed upload attempts before report). ~5 min to diagnose, ~5 sec to fix (`docker compose up -d --force-recreate frontend`).
- **Fix:** No code change — `docker compose up -d --force-recreate frontend` (NOT rebuild — the Vite bundle was fine; only the nginx entrypoint envsubst needed to re-run with current env).
- **Infrastructure created:** None this session. Open candidate intake: "env-var changes to `.env` require frontend recreate, not just backend rebuild" — sibling rule to Rule #26 (frontend rebuild after src/** changes). Deferred to a future post-mortem-driven rule promotion if Rule-of-Two surfaces.

### 2. `TIER_A_HEAVY` mis-classified at 6 sites (Rule #51 axis confusion)

- **What happened:** `TIER_A_HEAVY = "5/hour"` was applied at `firmware.py:251 unpack` (commit `8766710`), `device.py:101 start_dump` (same commit), and `comparison.py:54/82/128/169/203` (commit `3677f1c`) based on "the detached work / executor work takes >2 min on representative input". But Rule #51's framework prescribes classification by EVENT-LOOP PINNING, not detached-work duration. Unpack and start_dump return 202 sub-second with arq/asyncio.create_task dispatch — the backend loop is free immediately. compare_firmware + compare_binary run in `run_in_executor` — the loop is free during executor work. compare_text + compare_instructions are sub-second sync — sub-second work doesn't need a HEAVY tier at all.
- **Caught by:** Operator question ("I don't understand why we even have an unpack rate limit") → 4-scout Wave-1 audit → Scout A's rate-limit decorator audit independently identified the same 6 mis-classifications.
- **Cost:** Iterative research workflow throttled. Operator's natural cadence (re-upload variant firmware to debug extraction bugs) hits 5/hour easily. No active 429 evidence in audit.jsonl, so the throttle had been silent except for this session's report.
- **Fix:** Commit `89b87d3` — re-tier 6 decorators per Rule #51 framework. firmware unpack + device dumps + compare firmware + compare binary → TIER_A_LIGHT_ACK (30/hour). compare text + compare instructions → TIER_C_DEFAULT (100/minute). compare decompilation STAYS TIER_A_HEAVY (legitimate — 2× cold-cache Ghidra calls = ~10 min event-loop pinning). 95 insertions / 57 deletions across 5 files (Rule #48 Shape-1 single-slice cross-stack alignment including `_EXPECTED_TIERS` test pinning + `rate_limit.py` docstring rewrite + dynamic-test endpoint switch).
- **Infrastructure created:** None new — Rule #51 was already in place from the 2026-05-18 sweep. This commit is the FIRST APPLICATION of the rule to surfaces that pre-existed it (the 2026-05-18 sweep authored Rule #51 in response to vuln-scan; the unpack/device/comparison endpoints were never reviewed under the new rule).

### 3. arq `max_jobs=4` and walker semaphore `Semaphore(4)` stale vs Rule #51 .iv envelope

- **What happened:** Rule #51 .iv bumped the DB pool to 40 (15 + 25 overflow) on 2026-05-18 to support 30/hour TIER_A_LIGHT_ACK burst. But two consumer-side caps were never re-sized: arq `max_jobs=4` (`workers/arq_worker.py:884`) and the cross-firmware walker semaphore `_WALKER_FANOUT_SEMAPHORE=4` (`workers/unpack.py:62`). After Commit 1 relaxed the rate limit from 5/hr to 30/hr, the legitimate burst would have queued on these consumer caps instead — pool headroom unusable in practice.
- **Caught by:** Scout C's resource-ceiling audit + my own Wave-2 self-critique trace ("if Commit 1 lands but consumer caps stay, does the new envelope actually flow through?").
- **Cost:** Would have neutralized Commit 1's user-visible improvement.
- **Fix:** Commit `df7d403` — `max_jobs` 4 → 6, `_WALKER_FANOUT_SEMAPHORE` 4 → 6 (matched). Also deduped the emulation memory double-gate (compose 1024M + config.py 1024M used the same value, QEMU had no process overhead headroom) — compose bumped to 2048M.
- **Infrastructure created:** None. Reinforced "Rule #51 conversion = invariant sweep" lesson from the 2026-05-18 sweep — the pool bump WITHOUT the consumer-cap bumps was the original incomplete change; this commit closes it.

### 4. Backend subprocess `timeout=120` too tight for multi-GB firmware

- **What happened:** Two `asyncio.wait_for(proc.communicate(), timeout=120)` sites — `firmware_metadata_service.py:177 binwalk3` and `assessment_service.py:481 semgrep` — would abort on multi-GB firmware. binwalk3 streaming-read at ~100 MB/s on 15 GB ILLUMISITE is ~150s; 120s aborted pre-completion. Semgrep on hundreds-of-files PE catalog with per-file `--timeout 60` needs an outer aggregate window larger than 120s.
- **Caught by:** Scout C audit.
- **Cost:** Legitimate scans on large firmware silently returned `[]` and `0`; operator saw "no signal" results instead of an explicit error.
- **Fix:** Commit `2efe094` — both timeouts 120 → 300.
- **Infrastructure created:** None. Calibration update.

### 5. Frontend `comparison.ts:70` 1.4× under-constrained for cold-cache Ghidra pairs

- **What happened:** `diffDecompilation` carried `timeout: 120_000` ms — under the SINGLE Ghidra call's worst case (300s = 360_000ms). Backend calls Ghidra TWICE (firmware A + firmware B); cold-cache worst case is 600s. Required `frontend_ms = backend_s × 1200 = 720_000` per Rule #29 derivation math. The analysis_cache shortcuts repeats to sub-second so this only bit on cold-cache pairs, but when it bit, axios aborted while Ghidra was still working.
- **Caught by:** Scout B audit + Rule #29 derivation check.
- **Cost:** Silent abort on cold-cache decompilation diffs.
- **Fix:** Commit `2efe094` — new `GHIDRA_PAIR_TIMEOUT = 720_000` in `timeouts.ts`; comparison.ts imports it.
- **Infrastructure created:** `GHIDRA_PAIR_TIMEOUT` tier constant joins the canonical `timeouts.ts` registry.

### 6. `DeviceAcquisitionPage` polled at 1000 ms (Rule #33 prescribes 2000 ms)

- **What happened:** `setInterval(pollDump, 1000)` at `DeviceAcquisitionPage.tsx:198`. Rule #33 firmware-unpack precedent prescribes 2000 ms. On a 30-minute full-flash dump, 1s vs 2s = 1800 GETs vs 900 — pure server load with no UX gain (operator can't perceive sub-2s progress on partition dumps).
- **Caught by:** Scout B polling-cadence audit.
- **Cost:** Server load × 2 per active dump session.
- **Fix:** Commit `2efe094` — 1000 → 2000ms with inline rationale citing Rule #33.
- **Infrastructure created:** None.

### 7. `MAX_FINDINGS_PER_CHECK = 50` silent cap on security audit findings

- **What happened:** `security_audit/_base.py:13 MAX_FINDINGS_PER_CHECK = 50` applied via `if count >= MAX_FINDINGS_PER_CHECK: return findings` at 13 call sites across credentials/network/permissions/external_scanners. Hard-stopped every security audit check at 50. No `... +N more` notice, no operator override. Medtronic ILLUMISITE-class firmware surfaces hundreds of insecure permissions / dozens of hardcoded credentials — all legitimately distinct findings, all silently masked past #50.
- **Caught by:** Scout D code-level constraint audit — Scout D flagged this as the HIGHEST-impact silent cap in the codebase.
- **Cost:** Operator-facing visibility loss on multi-GB security audits. Likely had been masking signal for the entire deployment.
- **Fix:** Commit `1afa3a6` — bumped 50 → 500 with inline rationale. Per-call-site `+N more` sentinel deferred (~25 edit sites) per Rule #25 single-slice discipline.
- **Infrastructure created:** None. Per-call-site sentinel queued as follow-up intake.

### 8. SBOM export MCP tool returned parse-broken JSON above 30 KB

- **What happened:** `ai/tools/sbom.py:799,861,880` used `json.dumps(...)[:30000]` to cap MCP tool output. Cut mid-token. Calling Claude would parse-fail on truncated JSON; operator never saw a "this is truncated" marker.
- **Caught by:** Scout D audit + inline comment at line 813 explicitly noting "5-7MB outputs cut to 30 KB".
- **Cost:** SBOM export via MCP was structurally unusable for any firmware whose document exceeded 30 KB (probably all real-world firmware).
- **Fix:** Commit `1afa3a6` — added `_sbom_truncation_marker()` helper that returns a CLEAN structured JSON object with `status: "truncated"`, `original_size_bytes`, `format`, and a `rest_endpoint` pointer. All three call sites use it.
- **Infrastructure created:** `_sbom_truncation_marker()` factory function. Pattern can be lifted to a shared utility if a Rule-of-Two emerges with similar JSON-bounded MCP outputs.

### 9. `Finding.title` / `Finding.file_path` / `sbom.purl` String(512) — Rule #15 family

- **What happened:** Three String(512) columns at risk of silent truncation. `Finding.title` — CRA / compliance / windows / ICS titles include OEM model + CWE list + check description, approaching 512 chars. `Finding.file_path` — Windows long-paths in Win11 ISO (`\Windows\WinSxS\amd64_microsoft-windows-...`) routinely exceed 512. `sbom.purl` — nested Maven shaded jars and npm scoped purls with classifier metadata exceed 512.
- **Caught by:** Scout D Rule #15 family audit. CLAUDE.md Rule #15 precedent: `analysis_cache.operation` needed VARCHAR(512), was VARCHAR(100). Same class.
- **Cost:** Latent. PG raises `value too long for type character varying(512)` on insert — would have surfaced as 500 errors on edge-case firmware.
- **Fix:** Commit `c5f53ca` — alembic migration `3dba4e5f6a7b` widens to 1024/2048/1024 respectively. ORM models updated to match. ALTER COLUMN with larger N is PG metadata-only — no table rewrite. Downgrade uses `USING substring(...)` so rows that grow during the new-cap window can safely truncate-rollback.
- **Infrastructure created:** Migration + ORM update. Rule-of-Three for String widening family now exists (analysis_cache.operation 100→512 in 2026-04; window_path-class columns at 4096/2048 already; this commit's 512→1024/2048). Mechanical detection: any new model column declared `String(N≤512)` where the field semantically carries paths / titles / identifiers should default to `String(1024)` minimum.

## What Worked Surprisingly Well

### 1. Wave-1 4-scout parallel audit nailed scope on first pass

The 4-scout decomposition (rate-limit decorators / frontend timeouts+polling / resource ceilings / code-level caps) covered the over-constraint surface area with zero overlap. Each scout returned 600-1000 words of structured findings; synthesis took 1 round-trip and produced the 5-commit plan that ultimately shipped. No Wave-2 needed — the user's prompt was tight enough ("over-constrained where?") that Wave-1 single-axis scouts were sufficient. The Wave-1+2 methodology codified in memory `feedback_wave2_cross_feature_methodology.md` is for closed-grammar Rule #52 extensions; ad-hoc "find me X" audits are well-served by single-pass Wave-1.

### 2. Operator's "deep research and deep review" prompt routed cleanly via /do

The user's intent was clear: research first, ship after. I dispatched 4 Agent scouts in parallel BEFORE making any code change. The synthesis took ~1500 words and presented a prioritized fix sequence with a clean ship/defer split. This is the validated do-them-all pattern (memory `feedback_do_them_all_pattern.md`) applied at audit-and-execute scope rather than just execute scope.

### 3. Per-piece commits per Rule #25 + docker cp + restart per Rule #20 = fast iteration

Each commit landed independently with its own validation step. Total session time: ~3.5 hours for 5 shipping commits, 1 housekeeping commit, postmortem, knowledge extraction. Without Rule #20 fast-iteration discipline (docker cp + restart instead of full rebuild between commits), this would have been ~2× longer.

### 4. Rule #46 META-CANARY caught upstream test silently

`test_expensive_posts_are_rate_limited` was failing on `main` BEFORE my edits (sbom `/generate` multi-line decorator pattern not matched by single-line regex). I caught this when running my targeted pytest — the META-CANARY discipline of "verify the gate fires" surfaced this pre-existing latent issue, which I fixed in the same Commit 1 as a cleanup.

## What Could Have Gone Better

### 1. Rule #24 canary tripped Rule #35a pipe-induced silent exit

When running the mandatory tsc canary at the start of Commit 3, I used `npx tsc -b --force 2>&1 | head -10` with `echo "exit=$?"`. The pipe captured tsc's output but `$?` reflected the LAST command in the pipe (head -10), which always returns 0. The canary printed `error TS2322: Type 'string' is not assignable to type 'number'.` (proving tsc was checking) AND `exit=0` (proving the pipe was hiding the real exit code). I recognized the symptom mid-run and re-ran without the pipe to confirm tsc was working. **Cost:** ~30 seconds. **Lesson:** Rule #35a's "capture exit code via direct invocation OR `${PIPESTATUS[0]}`" needs to be applied to EVERY exit-code-checking command, not just the one Rule #35a originally surfaced.

### 2. Two pre-existing pytest failures unrelated to my work

`test_expensive_posts_are_rate_limited` was failing on `main` (sbom multi-line pattern, fixed in Commit 1). `test_dynamic_429_response_shape_on_unpack` requires Docker DNS resolution for `db:5432` and fails on host pytest (not in container) — a pre-existing host-pytest limitation. Both required ~5 min of triage to confirm they weren't caused by my changes. **Lesson:** A clean baseline (`pytest` passing on `main` before any session edits) would have made this faster. Action: add a pre-session-start "is `main` green?" check to the campaign-opening shape.

### 3. Edit tool's read-before-edit rule tripped me twice

`Edit` requires reading the file once before editing it. I tried to edit `timeouts.ts` and `DeviceAcquisitionPage.tsx` without reading them first (the Read in C3 was for `comparison.ts` only). Two Edit calls failed, retried after Read. **Cost:** ~30 seconds × 2 = ~1 min. **Lesson:** When editing a file mid-session that I haven't read THIS session, Read first even if I've seen it before in the same conversation.

### 4. Backend container has no pytest

`docker compose exec backend pytest` failed — pytest is a dev dependency excluded from the production image. Ran via host venv `(cd backend && .venv/bin/pytest ...)` instead. **Cost:** Zero (host venv has full deps). **Lesson:** The host venv is the canonical test environment; the in-container `pytest` was never going to work. This is fine.

## Patterns Promoted / Reinforced

- **Rule #51 (rate-limit tier discipline)** — first APPLICATION to surfaces that pre-existed it. 6 mis-classifications corrected; the original Rule #51 promotion (2026-05-18) authored the framework but only retroactively fixed 2 sites at that time. This commit is the broader sweep.
- **Rule #15 family (DB column widening)** — Rule-of-Three+ instances now in the family (analysis_cache.operation 100→512 in 2026-04; windows_mft_record.full_path/lnk.target_path already wide; this session's findings.title/file_path + sbom.purl). The mechanical heuristic ("any new column declared `String(N≤512)` carrying paths/titles/identifiers defaults to `String(1024)` minimum") is now reinforced enough to consider an explicit rule promotion if a 4th instance lands.
- **Rule #25 single-slice exception #2 (cross-stack alignment commits)** — Commit 1 shipped decorator changes + `_EXPECTED_TIERS` test pinning + `rate_limit.py` docstring + dynamic-test endpoint switch as ONE atomic commit per Rule #48 Shape-1.
- **Rule #20 docker cp + restart fast iteration** — used 5 times across 5 commits. Each commit's validation cycle was <30s vs ~3min full rebuild.
- **Rule #46 META-CANARY discipline** — the existing META-CANARY in `test_rate_limit_tiers.py` correctly fired on my modified decorators; no Rule #46 regression introduced.
- **do-them-all parallel-research pattern** — fourth validated invocation; consistently produces 5-commit sweep in ~3 hours.

## Open Threads / Backlog

- ~25 `MAX_FINDINGS_PER_CHECK` call sites still need `+N more` sentinel (Commit 4 deferred per Rule #25 single-slice; bumped cap to 500 covers most workflows).
- Backend + worker memory caps at 4 GB — not bumped this session despite Scout C HIGH severity flag. Current usage stays under cap; host has only 15 GiB RAM total. Bump deferred to evidence-driven follow-up if real OOM surfaces.
- 11 frontend timeout sites re-declare values locally instead of importing from `timeouts.ts` — drift surface, not active breakage. Scout B finding; deferred per Rule #25 single-slice (would be its own consolidation commit).
- ClamAV `max_files=500` / HashLookup `max_files=200` — Scout C medium severity. Silently miss 99%+ of binaries on large firmware. Operator-tunable "no cap" mode would be the right fix. Deferred to dedicated intake.
- 18 Scout D MEDIUM slice truncations (pcap conversations[:50], cipher_suites[:20], CRA evidence[:15], etc.) — most are display-shape decisions, not data-loss. Deferred unless operator surfaces a specific report.
- Frontend env-drift on `.env` changes → frontend recreate (vs Rule #26 rebuild). Open candidate for a sibling rule promotion if Rule-of-Two surfaces.

## Pattern Capture

- `.planning/knowledge/over-constraint-sweep-2026-05-22-patterns.md` (1 NEW pattern: Wave-1 single-axis sufficiency for ad-hoc audits)
- `.planning/knowledge/over-constraint-sweep-2026-05-22-antipatterns.md` (4 NEW antipatterns: pipe-induced silent exit on tsc canary; tier-by-duration not tier-by-loop-pinning; consumer-cap drift on pool resize; silent truncation without `+N more`)
- Rule #51 reinforcement (broad application beyond original commit)
- Rule #15 family Rule-of-Three+ confirmation
