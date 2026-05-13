---
postmortem_id: postmortem-post-kappa-windows-test-extension-2026-05-12
title: Post-κ Windows-test extension — walker-bridge fix + UX upload-progress + Rule #47 + 2 new antipatterns
status: closed
opened: 2026-05-12
trust_level: trusted (direct-push to main per-piece, Pattern P5)
parent_campaign: windows-coverage-godmode-kappa-2026-05-12 (session-close-1 cfa10bf)
extension_session: this file (session-close-2 cfbd7ff)
trigger: operator's Windows-firmware test request (`is our local docker all updated fully?! I want to test the changes we've made, especially Windows`) surfaced 2 real bugs + 1 UX paper-cut during a 15.57 GB Medtronic ILLUMISITE upload
commits_extension:
  - 140bde8 fix(frontend): UPLOAD_TIMEOUT 600_000 → 1_800_000 (Rule #29 math)
  - 14dfc00 feat(ui): 'finalizing' phase for firmware upload (Shape 1 from research-fleet)
  - 12955a6 feat(workers): factor walker auto-trigger registry into shared module
  - 5f3d195 feat(services): wire walker auto-triggers into upload pipeline (Shape A bridge)
  - e375eec docs(research-fleet): .tibx Acronis support brief (HOLD verdict)
  - 273c48b docs(rules): codify Rule #47 — state-machine refactor consumer-hook enumeration
  - 7b91481 docs(intake): walker auto-trigger gap + A13 antipattern
  - fde4204 docs(intake): UX upload-progress Rule #29 axios correction
  - c1f513e docs(intake): UX upload-progress multi-stage indicator + 3-scout synthesis
  - 9fc363c docs(learn): κ antipattern A12 (sub-agent smoke gap on service-module imports)
  - cfbd7ff chore(session-close-2): harness 191→192 + extension summary
metrics:
  research_fleet_outputs: 6 scouts (3 for UX upload-progress + 1 walker-bridge + 1 .tibx + 1 manual codebase audit)
  bugs_resolved: 2 (walker auto-trigger gap; UPLOAD_TIMEOUT too short for multi-GB)
  ux_fixes: 1 ('finalizing' phase)
  new_rules_codified: 1 (Rule #47 — Rule-of-One)
  new_antipatterns_codified: 2 (A12 sub-agent smoke gap; A13 orchestrator shell-script Rule #46 violation)
  pre_existing_bugs_backfilled: 1 (ι.D EFS test-gate whitespace-tolerant regex)
  harness_counter: 191 → 192
  duration_extension: ~3-4 hr orchestrator wall (post-κ-close through this commit)
---

# Post-κ Windows-test extension postmortem

## Executive summary

Operator requested a Windows-firmware test of the freshly-shipped κ walkers
("is our local docker all updated fully?! I want to test the changes we've
made, especially Windows"). During the test session — 15.57 GB Medtronic
ILLUMISITE upload — the test surfaced 2 real bugs + 1 UX paper-cut + 2 new
antipatterns about the orchestrator's own discipline. All resolved in
~11 commits; HEAD `cfbd7ff`.

**The walker-auto-trigger-gap bug was the most significant find** — every
firmware uploaded since `847eae9` (the upload-pipeline refactor, ~5 days
prior to this session) reached `upload_stage='ready'` but NEVER fired any
of the 22 walker auto-triggers. The entire κ campaign's walker output
(plus η/θ/ι walker output) was dead-code for any new upload. This is a
campaign-blocking discovery — operators who uploaded firmware in the past
5 days saw zero findings emitted regardless of artefact richness.

## Per-fix summary

### Fix 1 — Walker auto-trigger gap (commits `12955a6` + `5f3d195`)

**Root cause:** `847eae9` refactor introduced `_post_process_pipeline`
(`backend/app/services/firmware_service.py:540-755`) which migrated the
visible `upload_stage` polling but silently orphaned the walker
auto-trigger registrations at `backend/app/workers/unpack.py:129-162`. The
new pipeline never invoked the OLD hook chain. All 22 walker
`auto_<op>_walk_firmware_safe` callbacks became dead code.

**Detection:** operator's ILLUMISITE test showed `upload_stage=ready` AND
ALL 21 walker `*_walk_status` columns at `idle` AND `extracted_path` NULL
AND 0 findings.

**Fix shape (Shape A from intake):**
1. Factored `WALKER_AUTO_TRIGGERS` list into new
   `backend/app/workers/walker_registry.py` (single source of truth)
2. Refactored `unpack.py` to import from the registry
3. Added `_fire_walker_auto_triggers` helper in `firmware_service.py`
4. Wired the helper into `_post_process_pipeline`'s analyzing phase
5. Ensured `extracted_path` is set during extraction so walkers can find files

**Test gate:** new `backend/tests/test_walker_auto_trigger_bridge.py` (8 tests
PASS, 2.01s) with Rule #35b live canary against `make_live_db` firmware row.

**Verification on existing ILLUMISITE firmware:** patched `extracted_path`
on the existing row, invoked `_fire_walker_auto_triggers` directly. Result:
BCD walker found 9 entries, 4 other walkers stamped JSONB results
(bcd/esp/appcompat/registry_hive/evtx). Bug closed.

**Count discrepancy lesson:** intake said "21 walkers"; actual count was 22.
Rule #31 width-canary discipline (grep widest before trusting a count)
should have caught this at intake-authoring time — codified as a companion
gotcha in Rule #47.

### Fix 2 — UPLOAD_TIMEOUT bump (commit `140bde8`)

**Root cause:** `UPLOAD_TIMEOUT = 600_000` (10 min) was too short for
multi-GB firmware. Empirically: 15.57 GB ILLUMISITE upload at ~80-130 MB/s
takes 5-10 min to fully forward through nginx + 2-3 min for inline SHA256
= ~10-13 min wall, which exceeds 600s.

**Fix:** bumped to `1_800_000` (30 min) per Rule #29 math
(`frontend_ms ≥ backend_s × 1200`; 25 min × 1200 ≈ 1.5M ms; rounded to
1.8M for headroom).

**Deeper proper fix (deferred):** 202-fast refactor — return 202
immediately on raw-bytes-received, move hash + dedup + INSERT to a
background task per Rule #33 .a discipline. Documented in
`.planning/intake/ux-upload-progress-multistage-2026-05-12.md` §"Future
escalation path."

### Fix 3 — UX 'finalizing' phase (commit `14dfc00`)

**Root cause:** progress bar hit 100% as soon as browser→nginx finished;
sat at 100% for 5-25+ min while nginx→backend forwarding + inline SHA256
ran; operator concluded system was hung.

**Fix shape (Shape 1 from 3-scout research-fleet):** added `'finalizing'`
Phase value to `FirmwareUpload.tsx`; useEffect transitions when
`uploadProgress >= 100 && phase === 'uploading'`; new branch renders
permanent ✓ "Upload bytes received" + indeterminate spinner + "Server is
finalizing..." copy. ARIA `aria-live="polite"` (not assertive, per Scout 1
recommendation).

**Industry-survey synthesis (Scout 1):** 6 major tools surveyed (Google
Drive 2025-2026, Dropbox, GitHub LFS, YouTube, AWS S3 multipart, Hugging
Face). Converged shape: single persistent surface + named phase transitions
+ permanent stage checkmarks + indeterminate-spinner for opaque server work.

### Fix 4 — `.tibx` research-fleet (commit `e375eec`)

**Verdict: HOLD/soft-NO-GO at current intake strength.** No
AGPL-compatible `.tibx` parser exists; only OSS tool (`dennisss/acronis-tib`,
MIT, 13 commits) is `.tib`-only. Writing parser from scratch is multi-month
libyal-tier RE. Strategic-value floor: N=1 (Medtronic).

**Critical companion finding:** the OUTER Windows recovery ISO containing
the `.tibx` files is ALREADY walkable via existing `unpack_iso9660.py` +
`unpack_wim.py` — once the walker-bridge fix lands, the operator gets the
boot-chain artefacts (`bootmgr`, `BCD`, `.efi`, `boot.wim`, signed binaries)
walkable today without ever cracking the `.tibx` wrapper.

**Revisit triggers:** (a) 2+ additional `.tibx` operator encounters in
different device families, OR (b) credible OSS `.tibx` reader with
encryption support emerges.

### Fix 5 — ι.D EFS test-gate backfill (commit `9f09ff3`, already shipped pre-extension)

κ.D DPAPI walker discovery (whitespace-tolerant regex) surfaced that ι.D
EFS's `test_walker_no_decrypt` had the same vulnerability. Backfilled with
6 pattern updates + new `test_efs_walker_no_decrypt_gate_actually_fires`
canary test.

## New rule codified

### Rule #47 — State-machine refactor consumer-hook enumeration (Rule-of-One)

Earned by the walker-bridge fix. Codified at commit `273c48b` in CLAUDE.md
+ mirrored to `.mex/context/conventions.md`.

**Rule:** when refactoring an existing state machine to a new one, the
refactor MUST enumerate every CONSUMER HOOK of the OLD state machine and
explicitly migrate or bridge them.

**Mechanical detection:** `grep -rn '<old_state>' backend/app/` then enumerate
every match with explicit status (migrated / bridged / deleted / N/A) in
the refactor PR body.

**Width-canary companion (Rule #31):** the intake said "21 walkers" but the
actual count was 22. Run the grep TWICE with progressively broader patterns;
verify count is stable before trusting.

**Promotable to Rule-of-Two** if a similar refactor-orphan surfaces in λ
or later.

## New antipatterns codified

### A12 (Rule-of-One): Sub-agent smoke gap on service-module imports

**Surface:** κ.B.D added `_appcompat_evidence_lines(... last_modified_ts:
datetime | None ...)` to `finding_service.py` without `from datetime import
datetime` at module top. Backend uvicorn startup raised `NameError` on
module-load. Sub-agent smoke imported the WALKER + MCP tools but NOT
`finding_service` itself. Alignment test imports schemas only. Orchestrator
Pattern P7 didn't probe `RestartCount` post-rebuild. Bug masked for ~3 hours
before user observed HTTP 502.

**Mitigation:** when a stream's .D commit modifies `finding_service.py` (or
any eagerly-imported service module), sub-agent smoke MUST import the service
specifically AND verify the new method/symbol is present. Orchestrator Pattern
P7 MUST add a backend `RestartCount` probe when the rebuild loads new
finding_service.

### A13 (Rule-of-One — extends Rule #46 to ORCHESTRATOR-LAYER shell-script gates): `grep -q -` silently broken on ugrep-aliased systems

**Surface:** orchestrator-side until-loop watcher used `grep -q -` to check
"is there any output". On this system `grep` is aliased to `ugrep` which
emits `no PATTERN specified` and exits non-zero. The until-loop ran forever.
Operator waited 10+ min before flagging it.

**Mitigation:** NEVER use `grep -q -` for "any output" check. Use `grep -q .`
OR `[ -n "$(cmd)" ]` (POSIX-portable, no grep dependency). Rule #46 partner:
canary the watcher pre-trust by forcing a synthetic positive.

**Rule #46 extension:** the canary discipline applies to orchestrator-layer
shell-script gates, not just sub-agent Python test gates. Rule-of-Five for
the broader Rule #46 (Rule #17 base + Rule #24 + κ.D test-gate + κ.E
meta-canary + A13 orchestrator gates).

## Pattern observations

### Pattern: "Do-them-all" research-fleet → ship-per-piece (2 successful applications in single session)

The validated user pattern from auto-memory: "For 'do them all + deep research
+ Citadel' directives: 3-4 parallel research scouts → synthesize → ship
per-piece." Applied TWICE in this extension:

1. **UX upload-progress** — 3 parallel scouts (industry survey + integration
   architecture + minimum-effective-change) → synthesis → Shape 1 ~15 LOC ship.
2. **All-the-findings push** — 2 parallel sub-agents (walker-bridge full fix +
   .tibx research-fleet) + 2 trivial foreground ships (UPLOAD_TIMEOUT bump +
   'finalizing' phase) running concurrent. Net: 6 commits in ~45 min wall.

**Rule-of-Two** for the do-them-all pattern within a single extended session.
Per the memory entry: "Validated 2026-05-12 across 10 commits / 2 directive
issuances." This extension validates it AGAIN across 11 commits / 2 directive
issuances within this session.

## Strategic position post-extension

- **Wairz post-`847eae9` upload path was structurally broken** for ~5 days
  before this extension caught it. Every operator who uploaded firmware in
  that window got zero findings. Fix is in main; backend rebuilt with the
  fix loaded; future uploads will fire all 22 walkers correctly.
- **Operator UX significantly improved** — multi-GB uploads no longer
  appear "stuck"; UPLOAD_TIMEOUT covers 30-min wall budgets.
- **Pre-existing firmware rows still have NULL `extracted_path`** —
  documented backfill path in intake. NOT addressed this extension.
- **3 `.tibx` companion intakes filed** for future scheduling (HOLD on the
  parent intake; revisit-triggers documented).

## Forward signal — what next session inherits

- **The walker-bridge fix benefits NEW uploads** only. Pre-existing firmware
  rows uploaded between `847eae9` and `5f3d195` (~5-day window) need a
  one-off backfill SQL: `UPDATE firmware SET extracted_path = ... WHERE
  upload_stage='ready' AND extracted_path IS NULL AND zip_contents/ exists`.
  Recommended as a κ.X carve-out before λ kickoff.
- **Rule #47 is at Rule-of-One.** Watch λ + future refactors for
  Rule-of-Two promotion to "durable" status.
- **3 .tibx companion intakes** queued — most actionable is
  `acronis-recovery-pe-iso-walker-2026-05-12` (use existing iso/wim
  walkers; ~no-op now that walker-bridge fires correctly).
- **11 Rule #44 cross-firmware-aggregation backfills** remain across η/θ/pre-ι
  walkers (queued since κ close).
- **λ campaign (memory-forensic-godmode-α / Vol3)** — 3-scout research-fleet
  pre-pass + 8-stream/2-3-session build per κ Scout 3 estimate.

## Closing reflection

This extension demonstrated that the operator-driven smoke test cycle has
**high signal value**: a single 30-min Windows-firmware upload test surfaced
a 5-day-latent campaign-blocking bug (walker auto-trigger gap), a
multi-GB-upload timeout class (UPLOAD_TIMEOUT), an operator UX paper-cut
('finalizing' phase), and 2 disciplines worth codifying (Rule #47 +
A12/A13). The "do them all + research + ship per-piece" pattern produced
~50 commits across the full session (κ + extension) with zero net
regressions on main.

**Per-extension cadence:** ~3-4 hr orchestrator wall, 11 commits, 1 new
CLAUDE.md rule, 2 new antipatterns, 6 sub-agent dispatches (3 UX scouts +
1 walker-bridge + 1 .tibx scout + 1 codebase audit). Pattern P1 single-
sub-agent per stream + Pattern P5 per-piece direct-push + Rule #23 worktree
isolation + Pattern P7 trust-but-verify all held without regression.
