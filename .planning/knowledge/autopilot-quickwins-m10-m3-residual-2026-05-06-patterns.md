# Patterns: Autopilot quick-wins sweep (M-10 + M-3 residual) — 2026-05-06

> Extracted: 2026-05-06
> Campaign: ad-hoc autopilot pass (no campaign file)
> Postmortem: none
> Commits: `578a4b8` (M-10a frontend non-root), `e3d4f1b` (M-10b backend doc block), `b8ff3e9` (M-10 progress), `88f3ed0` (M-3 hook), `ab86342` (M-3 6-site migration), `4764ce4` (M-3 progress)

## Successful Patterns

### 1. Probe the upstream image before designing the migration

- **Description:** Before swapping `nginx:alpine` → `nginxinc/nginx-unprivileged:alpine` for M-10a, ran a 5-second triage: `docker run --rm --entrypoint sh nginxinc/nginx-unprivileged:alpine -c "id; ls -la /usr/share/nginx/html /etc/nginx/templates 2>&1; cat /docker-entrypoint.d/20-envsubst-on-templates.sh | head -40"`. Output told us: (a) default user is uid 101 (nginx); (b) `/etc/nginx/templates` does NOT exist by default — COPY auto-creates, no extra mkdir; (c) `20-envsubst-on-templates.sh` is present and processes `*.template` → `/etc/nginx/conf.d/`; (d) default `/etc/nginx/conf.d/default.conf` listens on 8080 (will be overwritten by our envsubst output). Knowing all four facts BEFORE editing the Dockerfile eliminated the "does my template still get processed" and "do I need to create directories" risk classes.
- **Evidence:** Commit `578a4b8` Dockerfile diff is 2 lines (FROM swap + comment); rebuild + healthcheck flipped to healthy on first try. No iteration needed.
- **Applies when:** Switching base images for any non-trivial container. The probe set is `id` (user), `ls` (paths), `cat docker-entrypoint.d/*.sh` (entrypoint behavior). 5 seconds spent here saves 5+ minutes of rebuild-debug-rebuild cycles. Companion to Pattern #1 of `autopilot-quickwins-m8-m12-m2-m3-2026-05-05-patterns.md` (probe distroless images before designing healthchecks).

### 2. nginx-unprivileged swap is single-line when the listen port is already unprivileged

- **Description:** The standard advice "switch to nginxinc/nginx-unprivileged" usually requires port remapping (the upstream defaults to 8080 because non-root can't bind <1024). For wairz, the existing `nginx.conf.template` already declared `listen 3000;` (3000 is unprivileged), so the swap was a 1-line `FROM` change with NO `nginx.conf.template` edits, NO `docker-compose.yml` port remapping, NO healthcheck path change. Verified: container reports `USER nginx PID 1` (uid 101), `0.0.0.0:3000->3000/tcp` works, healthcheck `wget 127.0.0.1:3000` passes. The default port 8080 is also exposed by the image but no host binding to it, so it's invisible.
- **Evidence:** Commit `578a4b8` is `+4 -2` (one line changed, three lines of comment added). `docker compose ps frontend` post-rebuild shows healthy in <30s.
- **Applies when:** ANY frontend container hardening where the existing nginx config listens on an unprivileged port. The mechanical check is `grep -E "^\s+listen\s+[0-9]+" frontend/nginx.conf.template` — if the port is ≥1024, the swap is single-line; if <1024, it's a multi-step (port remap + compose edit + healthcheck).

### 3. Document-only resolution when option (a) is structurally incompatible

- **Description:** M-10b: audit-2026-05-04 finding F-H-01 listed two options — (a) add `USER wairz` directive at image level, (b) document the trade-off. Naïve reading is "always pick (a) — actual security improvement over comment-only." Reading the existing entrypoint.sh:1-13 reveals the constraint: PID 1 MUST run `groupmod -g <socket-gid> docker` + `usermod -aG docker wairz` to align the in-container `docker` group with the host's docker socket GID at runtime. Both calls require root (CAP_CHOWN/CAP_FOWNER + write to /etc/group). Therefore option (a) is incompatible with the existing GID fix-up; the right resolution is option (b). Lifted the entrypoint-level explanation up to a Dockerfile-level comment block immediately above `ENTRYPOINT`, citing the GID constraint, the `exec su` privilege drop after fix-up, and two future paths (privileged init container; build-time-only DOCKER_GID) for genuine non-root.
- **Evidence:** Commit `e3d4f1b` is `+19 -1` (pure comment addition). Audit's option (a) explicitly considered and ruled out IN the comment block.
- **Applies when:** Any audit recommendation that lists alternative resolutions. Don't blindly pick the "stronger" option without verifying it's compatible with the constraints in the surrounding code. Sometimes "documentation" IS the fix — when the alternative would break working behavior, a Dockerfile-level comment that surfaces the trade-off to the next reader is the appropriate close-out. Companion to Rule #19 (evidence-first) — but for refactor recommendations, not just data-shape claims.

### 4. Hook extraction at the third repetition (well past the "three similar lines" threshold)

- **Description:** SbomPage shipped a one-off `useRef + useState + useEffect + ResizeObserver` block in commit `baadedb` (M-3 highest-risk site). When 6 MORE sites needed the same pattern (M-3 residual), the right move was extracting `useResponsiveListHeight({maxHeight, minHeight, bottomMargin})` to `frontend/src/hooks/useResponsiveListHeight.ts` rather than copy-pasting the inline block 6 times. CLAUDE.md explicitly says "three similar lines beats a premature helper" — but at 7 sites and ~30 LOC of effect setup per site (~210 LOC of duplication), the helper is no longer premature. The hook returns `{ref, height}` so consumers attach `ref` to a wrapping div and pass `height` to the list's style. Same logic, six places, one declaration each.
- **Evidence:** Commit `88f3ed0` adds 56-line hook file; commit `ab86342` migrates 6 sites with `+97 -55` (net delta) and removes the per-site useEffect/ResizeObserver wiring. Compiled bundle splits the hook into its own chunk `useResponsiveListHeight-ggioeZq9.js` (537 bytes) — Vite's tree-shaker also confirms the hook is real shared code, not dead duplicates.
- **Applies when:** Any sweep migration with N≥4 identical patterns. The threshold for "extract" vs "copy" is when the per-site wiring exceeds ~10 LOC AND repeats N≥4 times. Below that, copy-paste; above, extract. The cost of NOT extracting at this scale is bigger blast radius for any future bug fix (find/fix in 6 places vs 1).

### 5. Hook contract preserves precedent's structural choices verbatim

- **Description:** `useResponsiveListHeight` closely mirrors SbomPage's inline pattern from commit `baadedb`: same `window.innerHeight - rect.top - bottomMargin` formula, same `Math.max(minHeight, Math.min(maxHeight, ...))` clamp, same parent ResizeObserver (because filter-row expansion grows ABOVE the list without changing the list's own size — observing the element directly wouldn't fire). The hook's docstring explicitly cites both `FindingsList.tsx:52` (sibling pattern) and `SbomPage.tsx:1168` (commit baadedb precedent) so future readers can compare. Adding ANY new behavior (e.g. a debounce, an option for top-anchored layouts) into the hook at extraction time would have introduced a "new behavior masquerading as refactor" risk; declined to add anything until a consumer needs it.
- **Evidence:** Commit `88f3ed0` body cites both predecessors. The hook's compiled bundle (`useResponsiveListHeight-ggioeZq9.js`) implements `getBoundingClientRect` + `window.innerHeight` + `ResizeObserver(parent)` — same shape as SbomPage's pre-extraction inline code.
- **Applies when:** Any hook/utility extraction from existing inline code. Resist the urge to "improve" during the extraction. The extraction itself is the value; combining it with a behavior tweak makes bisect harder if a regression appears, AND makes the rollback path "delete the hook + all consumers + restore inline" instead of just "delete the hook."

### 6. Two commits for "extract + migrate" — bisect-clean independence

- **Description:** M-3 residual could have been one omnibus commit (hook + 6 migrations) or 7 commits (hook + per-site). Chose 2: (a) hook addition (commit `88f3ed0`); (b) all 6 site migrations (commit `ab86342`). Reasoning: (a) is independently verifiable as "compiles + tsc passes + dead code (no consumer yet)"; (b) is independently verifiable as "all 6 sites typecheck + acceptance grep returns 0 hits + frontend rebuild healthy." Each commit's revert has clear semantics — revert (b) leaves the hook as dead code (still typechecks, still bundles, just unused); revert (a) breaks (b) loudly with a tsc import error pointing at the missing hook. Bisect lands on the right commit immediately.
- **Evidence:** `git log` shows the 2-commit shape; Rule #25 sub-task discipline applied. Per-file typecheck after each of the 6 site edits (Rule #22) caught zero issues incrementally.
- **Applies when:** Any "extract + migrate N consumers" refactor where N≥3. The split point is the extraction commit (infrastructure addition, no behavior change) vs the consumer commits (mechanical migration). 7 commits is overkill at this size; 1 commit obscures bisect; 2 is the natural split.

### 7. Width-canary catches intake count drift (Rule #31 reaffirmed)

- **Description:** M-3 intake said "7 lower-risk sites remain"; ran `grep -rnE "calc\(100vh\s*-\s*[0-9]+px\)" frontend/src/` and got 6 hits + 1 explanatory comment in SbomPage.tsx (already-fixed site, comment references the OLD pattern). Actual count: 6. Documented in the M-3 commit body and in the intake update. Cross-checked with broader regex `calc\(100vh\s*-` which returned 13 hits — the delta included page-level Tailwind class shells (`h-[calc(100vh-3.5rem)]` flex layouts) that are NOT virtualized lists and thus out of scope. The width-canary served two purposes: (a) verified the narrow regex caught the right scope, (b) corrected the intake's count.
- **Evidence:** Commit `ab86342` body cites both narrow (6) and broader (13) grep counts; intake row in `audit-quick-wins-bundle-2026-05-04.md` updated to "6 actual" with the Rule #31 instance noted.
- **Applies when:** ALWAYS at intake start. <1 second cost. This is now 6+ instances of intake-count drift across the audit-2026-05-04 cleanup work — the discipline is durable; the rule is correctly named in CLAUDE.md.

### 8. Bundle-hash + chunk-content verification beyond container-healthy

- **Description:** After Rule #26 frontend rebuild, the standard checks are (a) `docker compose ps frontend` shows healthy and (b) `curl 127.0.0.1:3000` returns 200. Added (c) verify the served bundle hash CHANGED (`index-CcXESlSg.js` → `index-DBw3f-j1.js`) — confirms Vite re-emitted assets, not stale cache; AND (d) verify the new code is actually IN the bundle (`docker compose exec frontend find /usr/share/nginx/html/assets -name '*.js'` showed `useResponsiveListHeight-*.js` chunk; `cat` confirmed `getBoundingClientRect` + `ResizeObserver` + `parentElement` are all present). Catches the "container restarted but image is stale" failure mode that (a)+(b) miss — the same failure mode that triggered the Rule #26 rule originally (session 93a4948d, sidebar `projects.map` crash).
- **Evidence:** This session's verification chain: bundle hash captured pre-rebuild and post-rebuild; assets/chunk listing post-rebuild shows the new hook chunk; chunk content grep shows the expected DOM API calls.
- **Applies when:** ANY frontend rebuild for a feature that adds a new chunk-eligible export (a hook, a component module, anything Vite would code-split). The 30-second verification is cheap insurance against the Rule #26 failure mode being ALMOST caught — a healthy container serving the WRONG bundle.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| nginx-unprivileged base swap (M-10a) | Listen port 3000 already unprivileged → 1-line FROM change with zero downstream effect | Shipped `578a4b8`; container healthy as `nginx` user (uid 101) |
| Doc-only resolution for M-10b | Audit option (a) `USER wairz` incompatible with runtime groupmod/usermod GID fix-up; option (b) is the right close-out | Shipped `e3d4f1b` as +19 lines of comment; no behavior change |
| Extract `useResponsiveListHeight` hook for M-3 residual | 6 sites × ~30 LOC inline = ~180 LOC duplication; threshold for extract crossed long ago | Shipped `88f3ed0` (hook) + `ab86342` (6 migrations); bundle hash changed; chunk verified |
| Hook contract preserves SbomPage precedent verbatim | Any "improvement" during extraction conflates refactor with behavior change | Shipped as pure extraction; future tweaks gated by consumer demand |
| 2 commits for M-3 (hook + migrations) not 1 omnibus or 7 per-site | Hook is infrastructure, migrations are consumers; each independently verifiable; bisect-clean | Both commits typecheck independently; revert semantics are clean either way |
| Width-canary verified intake's "7 sites" → actual 6 | Rule #31 instance; <1 second cost; documents the source of truth | M-3 row in intake updated with the corrected count and Rule #31 reference |
| Bundle-hash + chunk-content post-rebuild verification | Standard "healthy + 200 OK" misses the stale-bundle failure mode that triggered Rule #26 originally | All four tiers passed; high confidence the change is live |
