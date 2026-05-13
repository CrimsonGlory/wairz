# Patterns: Post-κ Windows-test extension

> Extracted: 2026-05-12
> Source postmortem: `.planning/postmortems/postmortem-post-kappa-windows-test-extension-2026-05-12.md`
> No formal campaign file — work was a session-extension triggered by operator's Windows-firmware test request

## Successful patterns

### 1. Operator-driven smoke test as a high-signal regression source
- **Description:** Operator ran a real Windows firmware (Medtronic ILLUMISITE 15.57 GB) against the freshly-shipped κ walkers, immediately after the κ campaign close. The single 30-min test surfaced a 5-day-latent campaign-blocking bug (walker auto-trigger gap) that wairz's existing unit/integration tests had missed entirely.
- **Evidence:** Commits `12955a6` + `5f3d195` (walker bridge) closed a bug introduced in `847eae9` ~5 days prior. The bug rendered every walker γ.4 → κ.E dead-code for new uploads.
- **Applies when:** any major campaign close should be followed by an operator-driven real-firmware test BEFORE the next campaign opens. Synthetic test fixtures structurally cannot replicate the actual nginx → backend → walker fan-out for multi-GB inputs.

### 2. "Do them all + deep research + Citadel" multi-persona pattern — Rule-of-Two
- **Description:** When user issues a "do them all + deep research + Citadel" directive, dispatch 3-4 parallel research scouts → synthesize → ship per-piece. Validated previously 2026-05-12 across the κ scope decision (10 commits / 2 directives). This extension validates again across 11 commits / 2 directive issuances within the same session.
- **Evidence:** UX upload-progress 3-scout fleet → 3 research outputs → Shape 1 ~15 LOC frontend-only ship (commit `14dfc00`). Second directive: walker-bridge + .tibx parallel → 2 sub-agents → ~6 commits in 45 min wall.
- **Applies when:** user explicitly invokes the do-them-all pattern OR work decomposes into independent research + shippable streams. Single-session orchestrator; not a multi-session campaign.

### 3. Shape-A minimum bridge (refactor consumer rescue)
- **Description:** When refactoring a state machine orphans consumer hooks, ship a MINIMUM bridge that wires consumers into the new pipeline without changing semantics. Don't migrate everything (Shape B); don't revert (Shape C). Factor a shared registry + a single helper invocation.
- **Evidence:** Walker-bridge fix at commits `12955a6` (factor `WALKER_AUTO_TRIGGERS` registry) + `5f3d195` (wire `_fire_walker_auto_triggers` into `_post_process_pipeline`). ~30-50 LOC vs Shape B's 200-300 LOC full migration.
- **Applies when:** consumer-hook orphan discovered post-refactor; minimum-effective-change cheaper than full migration; registry factor enables future cleanup without burning that bridge.

### 4. Browser-side-only UX fix for "100%-stuck" multi-stage uploads (Shape 1)
- **Description:** When `onUploadProgress` reports 100% before backend completes processing, add a `'finalizing'` phase via `useEffect([uploadProgress, phase])` that transitions when uploadProgress >= 100. Render permanent ✓ "Upload bytes received" checkmark + indeterminate spinner + named-phase copy. ZERO backend change required.
- **Evidence:** Commit `14dfc00`, ~15 LOC frontend-only. Industry-validated across 6 major tools (Google Drive, Dropbox, GitHub LFS, YouTube, AWS S3 multipart, Hugging Face).
- **Applies when:** opaque server-side processing follows a determinate byte-transfer leg. Cheaper than SSE/WebSocket alternatives unless real-time stage-progress is genuinely needed.

### 5. Research-fleet HOLD as a positive outcome
- **Description:** A research-fleet that returns HOLD/NO-GO is a SUCCESSFUL outcome — it prevents committing to multi-month work without evidence. The `.tibx` brief returned HOLD with documented revisit-triggers.
- **Evidence:** Commit `e375eec`, 80-line brief, single-scout 3-angle synthesis. Identified that the outer recovery ISO is already walkable today via existing `unpack_iso9660.py` + `unpack_wim.py` — the deferred work is the PROPRIETARY format, not the test surface.
- **Applies when:** scoping decision for new dependency/format adoption; the strategic-value floor is N=1 OR the implementation cost is multi-month against a moving target.

## Key decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Choose Shape A (minimum bridge) over Shape B (full migration) for walker-orphan fix | Faster ship; preserves registry-factor benefit for future cleanup; lowest regression risk | Shipped in ~55 min sub-agent wall; 8/8 tests pass; 38/38 regression tests pass; ILLUMISITE re-test succeeded |
| Bump UPLOAD_TIMEOUT vs full 202-fast refactor | Empirical observation (15+ GB ILLUMISITE timed out at 600s) needed immediate fix; 202-fast deeper refactor documented as future scope | UPLOAD_TIMEOUT now 30 min; 202-fast deferred to Rule #33 .a campaign |
| `.tibx` HOLD verdict | No AGPL-compatible parser; multi-month RE chasing yearly-updated proprietary format; N=1 strategic floor | HOLD with documented revisit triggers + 3 companion intakes |
| Codify Rule #47 (state-machine refactor consumer-hook enumeration) at Rule-of-One | Walker-bridge evidence so strong; mechanically detectable via grep; promotable to Rule-of-Two on next refactor-orphan | Rule shipped at `273c48b` with CLAUDE.md + .mex mirror |
| Defer pre-existing-firmware-row backfill SQL to next session | Out-of-scope for the bug-fix stream; needs separate intake + decision (UPDATE WHERE shape) | Documented in extension postmortem §"Forward signal" |

## Forward — patterns durable for λ + future sessions

- Operator-driven smoke test cadence: each campaign close → real-firmware test before next campaign opens. Schedule before λ.
- Rule #47 + Rule #31 width-canary partnership: enumerate consumer-hooks at refactor time via TWO grep patterns of progressively broader width.
- "Do them all" pattern Rule-of-Two validated within this session; promotable to Rule-of-Three on the next user-issued directive.
