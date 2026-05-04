---
title: "Frontend: Harden API Client (Auth, API_BASE, Bulk Ops)"
status: completed
priority: high
target: frontend/src/api/
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 435cb5c2 Stream Zeta +
> session 198243b8 (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` Phase 3/5
> history). Live audit verified:
> - **A1 + A2** axios interceptors — commit `bfbfa91`. Request interceptor at
>   `frontend/src/api/client.ts:37`; response interceptor at line 68 with toast-dedup
>   helper + 401/403/5xx handling.
> - **A3** `apiUrl()` helper at `frontend/src/api/config.ts:17` — consumed by
>   `api/files.ts`, `api/hardwareFirmware.ts`, `api/emulation.ts`, `api/documents.ts`
>   for all URL construction.
> - **A4** `bulkResolve` bounded via `p-limit`: commit `a01236f`. `pLimit` imported at
>   `frontend/src/stores/vulnerabilityStore.ts:2`, applied at line 152.
> - **Dependencies:** `frontend/package.json` declares `p-limit ^3.1.0` (line 26) and
>   `sonner ^1.7.4` (line 35).
> - **Wave-1 follow-ups** extended API timeouts across 6 endpoints (commits
>   `cb4530d` → `e3e0dc0`) and preserved real error messages (commits `b437095`,
>   `974a9f5`, `ad9f524`, `237422c`).
> This intake is retained for historical reference; further changes go in new intakes.

## Problem

Three issues in the frontend API layer.

### A1. No auth-failure handling

`frontend/src/api/client.ts:13-21` logs errors to console and re-rejects. No 401 redirect, no 403 toast, no retry for 5xx, no offline detection.

When the backend becomes unauthenticated (expired key, rotated key, backend restart with new key), the user sees cryptic axios errors in the console but no UI signal.

### A2. VITE_API_KEY read once at module load

`frontend/src/api/client.ts:8` reads `import.meta.env.VITE_API_KEY` at module init. If the user rotates the key in `.env` and the browser has the app cached, all subsequent calls fail silently with 401. Only a full page reload picks up the new key.

### A3. Inconsistent API_BASE usage

`useEventStream.ts:48` uses `${API_BASE}/api/v1/projects/...` with `API_BASE = import.meta.env.VITE_API_URL || ''`.

`SecurityScanPage.tsx:129` hard-codes `/api/v1/projects/${projectId}/events?types=vulhunt` without `API_BASE`.

If `VITE_API_URL` is ever set (deploy behind a different origin), vulhunt SSE breaks silently while other SSE works.

### A4. bulkResolve fires unbounded parallel requests

`vulnerabilityStore.ts:125-131`:
```typescript
await Promise.all(selectedIds.map(id => updateVulnerability(id, { ... })))
```

100+ selected vulnerabilities hammer the backend with 100 simultaneous PATCHes. Each request opens its own Postgres connection via the backend. Also: no error handling for partial failure.

## Approach

### Fix A1 + A2 — Axios interceptors

Refactor `frontend/src/api/client.ts`:

```typescript
import axios, { AxiosError } from 'axios'

const client = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  timeout: 30000,
})

// Request interceptor — reads env fresh each call (cheap)
client.interceptors.request.use((config) => {
  const key = import.meta.env.VITE_API_KEY
  if (key) {
    config.headers['X-API-Key'] = key
  }
  return config
})

// Response interceptor — global error handling
client.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (!error.response) {
      // Network error / offline
      showToast({ type: 'error', title: 'Network error', description: 'Could not reach the backend' })
    } else if (error.response.status === 401) {
      showToast({ type: 'error', title: 'Authentication failed', description: 'Check VITE_API_KEY and reload' })
    } else if (error.response.status === 403) {
      showToast({ type: 'error', title: 'Forbidden', description: 'You do not have access to this resource' })
    } else if (error.response.status >= 500) {
      showToast({ type: 'error', title: 'Server error', description: `HTTP ${error.response.status}` })
    }
    return Promise.reject(error)
  },
)

export default client
```

Add a lightweight toast system (shadcn/ui `sonner` or `useToast` hook).

For A2 — key rotation: the interceptor approach re-reads the env each request, so the key is always fresh for new requests. Existing in-flight requests will complete with the old key; that's acceptable.

### Fix A3 — API_BASE everywhere

Introduce `frontend/src/api/config.ts`:

```typescript
export const API_BASE = import.meta.env.VITE_API_URL || ''

export function apiUrl(path: string): string {
  // Always include API_BASE; callers pass only the relative path
  return `${API_BASE}${path.startsWith('/') ? path : '/' + path}`
}
```

Audit every EventSource / raw URL construction:
```bash
grep -rn 'new EventSource(' frontend/src
grep -rn 'fetch(' frontend/src
grep -rn '/api/v1/' frontend/src/hooks frontend/src/pages frontend/src/api
```

Migrate each to use `apiUrl()`.

### Fix A4 — Chunk bulkResolve

In `vulnerabilityStore.ts:125-131`:

```typescript
import pLimit from 'p-limit'

const bulkResolve: ... = async (...) => {
  const limit = pLimit(5)
  const results = await Promise.allSettled(
    selectedIds.map(id => limit(() => updateVulnerability(id, { ... })))
  )
  const failed = results.filter(r => r.status === 'rejected')
  if (failed.length > 0) {
    showToast({ 
      type: 'warning', 
      title: `Updated ${results.length - failed.length} of ${results.length}`,
      description: `${failed.length} failed — see console`,
    })
  }
}
```

Add `p-limit` dependency.

Better long-term: add a batch endpoint `POST /api/v1/projects/{id}/sbom/vulnerabilities/bulk-update` that accepts `{ ids: string[], status: string, justification?: string }` and does one DB transaction.

## Files

- `frontend/src/api/client.ts` (interceptors)
- `frontend/src/api/config.ts` (new)
- `frontend/src/hooks/useEventStream.ts` (already uses API_BASE — verify)
- `frontend/src/pages/SecurityScanPage.tsx` (fix hard-coded `/api/v1/...`)
- `frontend/src/stores/vulnerabilityStore.ts` (bulkResolve chunking)
- `frontend/package.json` (p-limit, sonner)
- `frontend/src/components/Toaster.tsx` (new — wrap shadcn Toaster or sonner)

## Acceptance Criteria

- [ ] Disabling the backend (`docker compose stop backend`) and attempting an API call shows a "Network error" toast (not a console error)
- [ ] Rotating `VITE_API_KEY` in the env and making new requests uses the new key without reload
- [ ] `grep -rn 'new EventSource(' frontend/src` shows only calls that prefix with `API_BASE` or `apiUrl()`
- [ ] `grep -rn "Promise\.all(" frontend/src/stores` — any remaining uses are bounded (< 10 concurrent) or have an explicit comment
- [ ] `bulkResolve(100 items)` doesn't open 100 concurrent requests (verify in browser devtools Network tab)
- [ ] Existing tests pass

## Risks

- Toast spam on 401 — dedupe toasts: show at most 1 auth-failed toast per 10 seconds
- `sonner` + shadcn already has `<Toaster />`; check current setup before adding
- `p-limit` is ESM-only — confirm Vite config supports it (should by default)

## References

- Frontend review C5, H9, H14, H15
