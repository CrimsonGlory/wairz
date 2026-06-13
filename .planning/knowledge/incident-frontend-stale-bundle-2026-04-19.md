# Incident: Frontend stale-bundle TypeError on `/projects` (2026-04-19)

> Session: 93a4948d
> Reporter: Dustin (Chrome HAR + DevTools console)
> Severity: user-blocking (ErrorBoundary "Something went wrong" on `/projects` load)
> Time-to-fix: ~15 min from HAR delivery to verified rebuild
> Code change: **zero** — fix was `docker compose up -d --build frontend` alone

## Symptom

Loading `http://localhost:3000/projects` after auth showed the generic ErrorBoundary fallback:

> Something went wrong
> An unexpected error occurred. You can try again or return home.

Console stack:

```
TypeError: i.map is not a function
    at RW (index-3kZyRoWG.js:667:13095)
    at Mx (index-3kZyRoWG.js:48:48775) [React render]
    ...
    at XMLHttpRequest.send
    at fetchProjects
```

HAR showed all 8 network requests returned 200 — no backend failure. Two identical `GET /api/v1/projects` fired at the exact same millisecond (distractor — see "Ruled out" below).

## Root cause

**The running frontend container image pre-dated the critical frontend fix.**

Backend Stream Beta (session 435cb5c2, Wave 1 of this morning) migrated list endpoints to a Page envelope:

```
GET /api/v1/projects →  { items: [...], total, offset, limit }
```

(Previously `[...]`.) This broke every frontend caller that did `data.map(...)` on the raw response.

Frontend Stream Zeta landed commit `3063283` (2026-04-19 17:14 UTC) adding an `unwrap` helper to `frontend/src/api/projects.ts`:

```ts
function unwrap<T>(data: PageEnvelope<T> | T[]): T[] {
  return Array.isArray(data) ? data : (data?.items ?? [])
}

export async function listProjects(): Promise<Project[]> {
  const { data } = await apiClient.get<PageEnvelope<Project> | Project[]>('/projects')
  return unwrap(data)
}
```

**But the frontend container image was built at 14:40 UTC — 2h 34m BEFORE `3063283` landed at 17:14 UTC — and was never rebuilt.** The shipped bundle (`/usr/share/nginx/html/assets/index-3kZyRoWG.js`) still contained the pre-fix version:

```js
async function _W(){
  const{data:e} = await Se.get("/projects");
  return e            // ← NO unwrap; returns raw envelope
}
```

So `projectStore.fetchProjects` received `{items:[...]}`, set `projects = {items:[...]}` in the store, and `Sidebar`'s line 69 (minified `RW`) called `i.map(...)` on the envelope object → TypeError.

## Fix

```bash
docker compose up -d --build frontend
```

No code changes. Post-rebuild verification:

```bash
curl -s http://127.0.0.1:3000/ | grep -oE '/assets/index-[A-Za-z0-9_-]+\.js'
# New hash: /assets/index-CgTNrfjK.js  (was /assets/index-3kZyRoWG.js)

curl -s http://127.0.0.1:3000/assets/index-CgTNrfjK.js \
  | grep -oE '.{0,20}Ce\.get\("/projects"\).{0,150}' | head -1
# const{data:a}=await Ce.get("/projects");return iR(a)   ← unwrap helper
```

User hard-reloads browser (Ctrl+Shift+R) to drop the cached old bundle.

## Ruled out (false leads)

- **Double-fetch on `/api/v1/projects` from HAR** — two components (`Sidebar.tsx:54`, `ProjectList.tsx:14`) both call `fetchProjects()` on mount. This is real (visible in HAR) but NOT the bug cause. It produces duplicate network traffic + a minor race, but both calls return identical 200 JSON; neither could produce a `.map is not a function` error by itself. Deferred as hygiene issue, not this incident.
- **React StrictMode double-invoke** — rejected: would show 4 requests if it were firing, not 2. The two requests come from genuinely different components.
- **Backend-side error** — rejected: all 8 HAR responses were 200 with identical 1360-byte bodies.
- **My session 93a4948d changes** — rejected: this session only modified backend files; frontend hadn't been touched since 3063283.

## Prevention (CLAUDE.md Rule #26)

Added Rule #26 to CLAUDE.md (companion to Rule #8 for backend+worker):

> When `frontend/src/**` changes, the frontend image must be rebuilt — `docker compose up -d --build frontend`, not `restart` and not `up -d` alone.

Mechanical tell:

```bash
docker compose images frontend --format '{{.CreatedAt}}'
git log --format='%ci' -1 -- frontend/
# If the git commit is NEWER than the image CreatedAt, rebuild.
```

Harness rule `auto-frontend-rebuild-not-restart` (harness.json qualityRules.custom #24) flags `docker compose restart frontend` in docs / knowledge / .mex files.

Fix verification regex (for any future incident):

```bash
BUNDLE=$(curl -s http://127.0.0.1:3000/ | grep -oE '/assets/index-[A-Za-z0-9_-]+\.js' | head -1)
curl -s "http://127.0.0.1:3000$BUNDLE" | grep -q 'Array\.isArray([a-z])?\w:([a-z]==null?void 0:[a-z]\.items'
# Exit 0 = unwrap shipped; non-zero = stale build, rebuild required.
```

## Why this wasn't caught sooner

1. **No integration test** on the Page-envelope migration's frontend unwrap — backend tests verified the schema, frontend tests mocked `listProjects` directly, no test hit the full HTTP boundary end-to-end against a real bundle.
2. **Zeta stream worked in a worktree** — the source was correct on main, but the stream's local build-artifact verification happened in `.worktrees/stream-zeta` (after it made one). When the worktree merged, no one ran `docker compose up -d --build frontend` against the main checkout's container.
3. **Session a90838f6 (Phase 7 close-out) did not rebuild frontend** — its scope was harness.json + CLAUDE.md + knowledge files, no frontend touches. No reason to rebuild. But also nothing flagged the drift.
4. **Session 93a4948d (this session, Phase 5 refactor)** — backend-only scope; didn't notice the frontend hadn't been rebuilt since Wave 2.

Fix: Rule #26 now makes the rebuild obligation explicit on any `frontend/src/` diff. Future sessions should check the frontend-image-vs-commit tell at session start (add to the campaign Verification Gate).
