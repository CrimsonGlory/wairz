---
title: "Frontend: Extract useFirmwareList Hook, Eliminate 9 Duplicate Fetches"
status: completed
completed_at: 2026-04-18
completed_in: session 59045370 autopilot wave-2 (commit 97c7c7a)
note: Migrated 10 pages (intake said 9 — HardwareFirmwarePage also had the pattern).
priority: high
target: frontend/src/hooks/, frontend/src/pages/
---

## Problem

`listFirmware(projectId)` is called from 9 separate pages, each maintaining its own `useState<FirmwareDetail[]>`:

- `SecurityScanPage`
- `ProjectDetailPage`
- `ComparisonPage`
- `ExplorePage`
- `SbomPage`
- `EmulationPage`
- `FuzzingPage`
- `ComponentMapPage`
- `FindingsPage`

Every route transition re-fetches, even when navigating between pages of the same project within a second. For projects with many firmware versions, this generates visible lag and wastes backend request capacity.

## Approach

### Option A — Shared Zustand store (minimal, consistent with existing pattern)

Add to `projectStore.ts`:

```typescript
interface ProjectState {
  // ...existing...
  firmwareList: FirmwareDetail[]
  firmwareListProjectId: string | null  // invalidation key
  loadFirmwareList: (projectId: string) => Promise<void>
}

export const useProjectStore = create<ProjectState>((set, get) => ({
  // ...existing...
  firmwareList: [],
  firmwareListProjectId: null,
  loadFirmwareList: async (projectId: string) => {
    if (get().firmwareListProjectId === projectId && get().firmwareList.length > 0) {
      return  // cache hit
    }
    const list = await listFirmware(projectId)
    set({ firmwareList: list, firmwareListProjectId: projectId })
  },
}))
```

Create `frontend/src/hooks/useFirmwareList.ts`:

```typescript
import { useEffect } from 'react'
import { useProjectStore } from '@/stores/projectStore'

export function useFirmwareList(projectId: string | undefined) {
  const firmwareList = useProjectStore((s) => s.firmwareList)
  const listProjectId = useProjectStore((s) => s.firmwareListProjectId)
  const load = useProjectStore((s) => s.loadFirmwareList)

  useEffect(() => {
    if (projectId) load(projectId)
  }, [projectId, load])

  return {
    firmwareList: listProjectId === projectId ? firmwareList : [],
    loading: listProjectId !== projectId,
  }
}
```

### Option B — TanStack Query (recommended long-term)

Introduce TanStack Query to handle ALL server-derived state with proper `staleTime`, `gcTime`, and invalidation. But this is larger scope — treat as its own intake (`frontend-state-invalidation.md` later).

**For this intake, do Option A.** Migrate to TanStack Query later if it's adopted project-wide.

### Step 2 — Migrate all 9 pages

For each page:
```typescript
// Before
const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
useEffect(() => {
  if (projectId) {
    listFirmware(projectId).then(setFirmwareList).catch(() => {})
  }
}, [projectId])

// After
const { firmwareList } = useFirmwareList(projectId)
```

### Step 3 — Invalidation hooks

When firmware is uploaded, deleted, or renamed, invalidate the cache:

```typescript
// projectStore.ts
invalidateFirmwareList: () => {
  set({ firmwareListProjectId: null, firmwareList: [] })
},
```

Call `invalidateFirmwareList()` from:
- Firmware upload success handler
- Firmware delete success handler
- Firmware rename / version label change

### Step 4 — SSE invalidation

When a firmware SSE event (`firmware.upload.complete`, `firmware.deleted`) fires for the current project, call `invalidateFirmwareList()` so other pages pick up the change.

## Files

- `frontend/src/stores/projectStore.ts` (add fields + actions)
- `frontend/src/hooks/useFirmwareList.ts` (new)
- `frontend/src/pages/SecurityScanPage.tsx`
- `frontend/src/pages/ProjectDetailPage.tsx`
- `frontend/src/pages/ComparisonPage.tsx`
- `frontend/src/pages/ExplorePage.tsx`
- `frontend/src/pages/SbomPage.tsx`
- `frontend/src/pages/EmulationPage.tsx`
- `frontend/src/pages/FuzzingPage.tsx`
- `frontend/src/pages/ComponentMapPage.tsx`
- `frontend/src/pages/FindingsPage.tsx`

## Acceptance Criteria

- [ ] `grep -rn 'listFirmware(' frontend/src/pages/` returns zero hits (or only in obsolete code)
- [ ] `grep -rn 'useFirmwareList' frontend/src/pages/` returns 9 hits
- [ ] Switching between pages A→B→A within 1 second issues only 1 `listFirmware` network request (verify in browser devtools)
- [ ] Firmware upload → SecurityScanPage auto-updates the list
- [ ] Firmware delete → other open pages reflect the deletion

## Risks

- Stale data if the Zustand cache isn't invalidated on firmware changes — the invalidation hooks in Step 3 are essential
- SSE events may arrive out of order — just invalidate, don't try to merge

## References

- Frontend review H8
- Related future work: `frontend-state-invalidation.md` (adopt TanStack Query)
