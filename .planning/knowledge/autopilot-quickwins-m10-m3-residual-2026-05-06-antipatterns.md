# Anti-patterns: Autopilot quick-wins sweep (M-10 + M-3 residual) — 2026-05-06

> Extracted: 2026-05-06
> Campaign: ad-hoc autopilot pass (no campaign file)
> Postmortem: none

## Failed Patterns

### 1. Blindly applying audit option (a) without checking compatibility

- **What was done (anti-pattern shape):** An audit-derived intake lists alternative resolutions for a finding (e.g. F-H-01 listed "(a) add `USER wairz` directive at image level OR (b) document the trade-off"). The naïve reading is to always pick the "stronger" option. M-10b would have been a near-miss for this anti-pattern: blindly applying `USER wairz` to backend/Dockerfile would have BROKEN the entrypoint's runtime GID fix-up (groupmod + usermod require root), causing emulation/fuzzing container management to silently fail when the host's docker socket GID differs from the build-time DOCKER_GID arg.
- **Failure mode:** Cargo-cult "stronger fix" application without reading the surrounding code's constraints. Audit recommendations describe what's POSSIBLE; only the surrounding code can tell you what's COMPATIBLE.
- **Evidence:** Avoided by reading `backend/entrypoint.sh:1-13` BEFORE picking the resolution. The comments there explicitly call out the GID fix-up constraint. Commit `e3d4f1b` documents the option-(a)-rejected-because-X reasoning in-place at the Dockerfile level.
- **How to avoid:** When an audit/intake lists alternative resolutions, read the SURROUNDING code (entrypoint scripts, runtime config, existing comments) before picking one. The "stronger option" is not always compatible. Apply Rule #19 evidence-first to refactor recommendations, not just data-shape claims. If option (a) conflicts with an existing constraint, document the constraint AND the rejection rationale at the call site (Dockerfile-level comment, not just commit message — commit messages rot; in-tree comments don't).

### 2. Trusting intake counts without a width-canary (recurring across sessions)

- **What was done (anti-pattern shape):** M-3 intake said "7 lower-risk sites remain". Without a width-canary grep, I would have started designing the migration around 7 sites — possibly with a different commit-split shape if the count had been smaller, OR without checking the actual sites at all and missing one if the count had been LARGER. Both are real risks: an off-by-one is the difference between "1 commit" and "2 commits" per Rule #25, and an under-count silently leaves untouched sites.
- **Failure mode:** Intake counts age. Files get added/removed between the intake's authoring and the resolution. The recorded count rots; the actual count is whatever the grep returns RIGHT NOW.
- **Evidence:** Width-canary returned 6, not 7. Intake updated. This is now ~6 instances of intake-count drift across audit-2026-05-04 cleanup sessions (across multiple knowledge files). The pattern is so stable that Rule #31 was upgraded to a numbered rule from "occasional discipline."
- **How to avoid:** ALWAYS run the width-canary grep at intake-start, before designing the resolution. Cost: 1 second. Updates the design's commit-split, identifies hidden scope, and flags intake-rot for next-session feedback. The discipline is in CLAUDE.md Rule #31 — it's not a new rule, it's a reaffirmation that the rule applies to EVERY intake-derived task, not just "the obviously high-risk ones."

### 3. Healthy container + 200 OK ≠ "the new code is live" (Rule #26 not-quite-caught)

- **What was done (anti-pattern shape):** Standard Rule #26 verification is `docker compose ps frontend` → healthy AND `curl 127.0.0.1:3000` → 200. Both can be true while the container serves a STALE bundle from a previous build. The Rule #26 failure mode that triggered the rule originally (session 93a4948d) was: container healthy + 200 OK + sidebar `projects.map` runtime crash because the served bundle predated a backend response-shape change. Rebuild was due, but had not happened.
- **Failure mode:** "Healthy" is the runtime liveness check; it doesn't compare image content vs source content. Even with `docker compose up -d --build` issued, IF the BUILD step is no-op'd by Docker's layer cache (e.g. because the dockerfile's COPY commands haven't seen file changes yet — Vite rebuilds happen INSIDE the container build), the resulting image can be silently stale. The container starts cleanly off the stale image; the healthcheck passes; the user sees the bug at runtime.
- **Evidence:** This session avoided the failure mode by: (a) capturing bundle hash pre-rebuild, (b) capturing post-rebuild, (c) verifying the hashes differ, (d) listing assets/ inside the container and verifying the new chunk file (`useResponsiveListHeight-*.js`) is present. (a)–(d) caught the "image is stale" failure class that (healthy + 200) misses.
- **How to avoid:** For any frontend rebuild that adds a new chunk-eligible export (hook, component module, anything Vite code-splits), include the bundle-hash-changed check + chunk-content grep in the verification. Cost: 30 seconds. The harness has `auto-frontend-rebuild-not-restart` which catches the OPERATION (build vs restart); this addition catches the OUTCOME (image actually different vs identical). Both checks belong in the post-rebuild ritual.

### 4. Including pre-existing dirty state in this session's commits

- **What was done (anti-pattern shape):** Session started with `git status` showing modified files from prior sessions (frontend/src/api/*.ts from M-1 timeouts.ts work; .planning/telemetry/*.jsonl from various; .claude/circuit-breaker-state.json). When staging M-10a + M-10b + M-3 changes, was tempted to `git add -A` for convenience. That would have bundled OTHER sessions' work into this session's commits, scrambling git blame and making bisect non-trivial across the unrelated changes.
- **Failure mode:** Convenience-driven `git add -A` doesn't distinguish "this session's edits" from "in-progress work from prior sessions" — and the working tree has BOTH at session-start.
- **Evidence:** All 6 commits this session staged via explicit paths (`git add frontend/Dockerfile`, `git add backend/Dockerfile`, `git add frontend/src/components/.../BlobTable.tsx ... SecurityScanPage.tsx`, etc.). Pre-existing dirty state (api/*.ts, telemetry/*) remained out-of-tree throughout. Each commit's `--stat` shows ONLY this session's edits.
- **How to avoid:** ALWAYS use `git add <specific-paths>` when the working tree has uncommitted modifications you don't own. The mechanical insurance is one extra path argument per commit; the anti-pattern is the convenience of `git add -A`. Companion to Pattern #8 of `autopilot-quickwins-m8-m12-m2-m3-2026-05-05-patterns.md` ("Don't bundle accumulated unfinished work").

## Quality Rule Candidates

None. The patterns this session reaffirmed are already encoded:

- Rule #26 (frontend rebuild not restart) — harness rule `auto-frontend-rebuild-not-restart` already catches the operation. Bundle-hash verification is a verification discipline, not a rule-pattern.
- Rule #31 (width-canary) — this is a discipline rule, not a regex-detectable code pattern.
- Rule #19 (evidence-first) extended to refactor recommendations — also a discipline rule.

A regex-detectable rule for "Dockerfile USER directive added without checking the entrypoint's privilege requirements" is too narrow to be auto-flaggable without false positives on legitimate `USER wairz` placements (most non-docker-socket containers SHOULD have `USER`).
