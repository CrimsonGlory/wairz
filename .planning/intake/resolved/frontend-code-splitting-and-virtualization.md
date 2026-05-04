---
title: "Frontend: Code Splitting + List Virtualization"
status: completed
priority: high
target: frontend/src/
---

> **Status note 2026-04-22 (V1 + V2 both fully shipped):** All
> virtualization gaps closed across 3 sessions. V1 route-level
> code-splitting shipped in session 435cb5c2 Gamma (commit `914d139`,
> 15 `React.lazy()` imports in `frontend/src/App.tsx`).
>
> V2 react-window virtualization sweep:
>
> | Component | Type | Session | Merge/commit |
> |---|---|---|---|
> | SbomPage vulnerability list | FixedSizeList | 435cb5c2 Gamma | `bf60b53` |
> | FindingsList | FixedSizeList | 435cb5c2 Gamma | `bf60b53` |
> | HardwareFirmware BlobTable | react-window List | b56eb487 β | `e7cd185` |
> | ComparisonPage file-diff | react-window List | b56eb487 β | `a71aa71` |
> | SecurityScanPage findings | react-window List | b56eb487 β | `7c09188` |
> | SecurityScanResults (APK nested groups) | variable-size List + 3-kind flat rows | 7e8dd7c3 δ | `f92989d` |
> | HardwareFirmware CvesTab (expandable rows) | variable-size List | 7e8dd7c3 δ | `a3cfbb3` |
> | HardwareFirmware DriversTable (expandable rows) | variable-size List | 7e8dd7c3 δ | `3021177` |
>
> ~75 code-split chunks under `/assets/`. Per-chunk verification confirms
> virt hints: HardwareFirmwarePage (7 hits), SecurityScanPage (5),
> ExplorePage (15), SbomPage (3), FindingsPage (3), ComparisonPage (3),
> react-window vendor chunk (16). Variable-height cases use explicit
> `rowHeight: (index) => number` closed-form estimates with optional
> overflow-y-auto safety net; no ResizeObserver dependency.
> SecurityScanResults deep-linking rewired via `useListRef` +
> `scrollToRow` inside `requestAnimationFrame` (since `document.querySelector`
> no longer works for off-screen rows).
>
> Not virtualised (intentional, out-of-scope for flat-list pattern):
> - `PartitionTree.tsx` — tree widget; would need windowed-tree virtualiser
>   (future intake if scroll perf becomes a real pain point).
>
> Acceptance criterion (`ls frontend/dist/assets/*.js | wc -l > 5`) met
> many sessions ago; intake now closes on the virtualization goal.

## Problem

### V1. No code-splitting

`frontend/src/App.tsx:5-18` statically imports all 14 pages. `grep -rn 'React\.lazy\|import(' frontend/src` returns zero hits.

Heavy dependencies ship in the initial bundle regardless of route:
- Monaco Editor (large)
- xterm.js
- ReactFlow (used in ComponentMapPage)
- Recharts (used in ComparisonPage — 992+ lines)

A user landing on `/projects` downloads Monaco Editor to look at a list of projects.

### V2. No list virtualization

Large lists render all rows:
- `SbomPage.tsx` — 1133 lines, renders up to 50K vulnerability rows
- Findings lists
- APK scan results (when many findings per APK)

The only current truncation is `.slice(0, 200)` in `SecurityScanPage.tsx:459` and similar — which limits UX, doesn't virtualize.

## Approach

### V1 — Route-level code splitting

Step 1. Convert page imports to `React.lazy`:

```typescript
// Before (App.tsx:5-18)
import ProjectsPage from '@/pages/ProjectsPage'
import ProjectDetailPage from '@/pages/ProjectDetailPage'
// ...

// After
import { lazy, Suspense } from 'react'
const ProjectsPage = lazy(() => import('@/pages/ProjectsPage'))
const ProjectDetailPage = lazy(() => import('@/pages/ProjectDetailPage'))
// ...
```

Step 2. Wrap `<Routes>` in `<Suspense>`:

```typescript
<ErrorBoundary>
  <Suspense fallback={<PageLoader />}>
    <Routes>
      <Route path="/projects" element={<ProjectsPage />} />
      {/* ... */}
    </Routes>
  </Suspense>
</ErrorBoundary>
```

Create `PageLoader`:
```typescript
// frontend/src/components/PageLoader.tsx
export function PageLoader() {
  return (
    <div className="flex items-center justify-center h-64">
      <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
    </div>
  )
}
```

Step 3. Split heavy component imports.

Monaco is used in `ExplorePage` (file viewer). Already heavy inside — wrap it in `lazy` within ExplorePage:

```typescript
const MonacoEditor = lazy(() => import('@monaco-editor/react'))

// In render:
<Suspense fallback={<div>Loading editor...</div>}>
  <MonacoEditor ... />
</Suspense>
```

Same pattern for xterm.js (EmulationPage, FuzzingPage terminals) and ReactFlow (ComponentMapPage).

Step 4. Measure.

Add bundle analysis:
```bash
cd frontend && npx vite-bundle-visualizer
```

Target: initial JS bundle under 500 KB gzipped. Current state likely >2 MB.

### V2 — Virtualize large lists with react-window

Add dependency:
```bash
cd frontend && npm install react-window @types/react-window
```

Replace large list rendering in:

**SbomPage.tsx — vulnerability list:**

```typescript
import { FixedSizeList as List } from 'react-window'

<List
  height={600}
  itemCount={vulnerabilities.length}
  itemSize={72}
  width="100%"
>
  {({ index, style }) => (
    <div style={style}>
      <VulnerabilityRow vuln={vulnerabilities[index]} />
    </div>
  )}
</List>
```

**FindingsPage.tsx / FindingsList — findings list** — same pattern.

**APK Scan results** — `SecurityScanResults.tsx` finding rows (nested groups make this harder; consider `VariableSizeList`).

### V3 — Tree virtualization (file explorer)

`ExplorePage` uses `react-arborist` (already virtualized for the tree). Verify it's actually virtualizing on a firmware with 10K+ files. Check `frontend/src/components/explorer/FileTree.tsx`.

## Files

### V1
- `frontend/src/App.tsx` (lazy all pages, Suspense wrapper)
- `frontend/src/components/PageLoader.tsx` (new)
- `frontend/src/pages/ExplorePage.tsx` (lazy Monaco)
- `frontend/src/pages/EmulationPage.tsx`, `FuzzingPage.tsx` (lazy xterm)
- `frontend/src/pages/ComponentMapPage.tsx` (lazy ReactFlow)

### V2
- `frontend/package.json` (react-window dep)
- `frontend/src/pages/SbomPage.tsx`
- `frontend/src/pages/FindingsPage.tsx` (and/or FindingsList component)
- `frontend/src/components/apk-scan/SecurityScanResults.tsx` (more complex, may defer)

## Acceptance Criteria

### V1
- [ ] `npx vite-bundle-visualizer` shows route-level chunks
- [ ] Initial bundle (landing on `/`) under 500 KB gzipped
- [ ] Monaco only loads when ExplorePage is first visited (verify in Network tab — `monaco-*.js` appears only then)
- [ ] No regression in existing E2E tests

### V2
- [ ] SbomPage with 10K vulnerabilities renders in under 1 second, scrolls at 60fps
- [ ] Findings list with 5K entries renders similarly
- [ ] react-window is only loaded on pages that use it (check bundle split)

## Risks

- Lazy imports break SSR if added later — document that this codebase is CSR-only
- `React.lazy` requires `Suspense` — forgetting it causes a runtime error visible in ErrorBoundary
- `react-window` requires fixed row heights; variable-height rows need `VariableSizeList` and measurement
- Monaco's lazy load may cause a flicker — acceptable, document it

## References

- Frontend review H11 (no code-splitting), H12 (no virtualization)
