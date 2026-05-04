---
name: layout-containment
description: Reusable contracts for split-pane pages, sidebar form controls, long content, and floating actions — prevents children bleeding across pane boundaries or overlaying scrollable content.
triggers:
  - "layout overlap"
  - "panel bleeds"
  - "selector overflows"
  - "split pane"
  - "two-pane"
  - "h-[calc(100vh"
  - "FirmwareSelector"
  - "absolute bottom"
  - "floating button"
  - "min-w-0"
  - "min-h-0"
edges:
  - target: context/conventions.md
    condition: for the Verify Checklist mirror entries (Rule #9 Record exhaustive, Rule #26 frontend rebuild)
  - target: patterns/add-frontend-page.md
    condition: when adding a new page with split-pane layout
last_updated: 2026-05-04
---

# Layout Containment

## Context

Wairz uses 4 recurring layout shapes that share the same containment hazards:

1. **Split-pane pages** with `<div className="-m-6 flex h-[calc(100vh-3.5rem)]">` root — Findings, Explore, Component Map, Fuzzing. `-m-6` escapes the `<main className="flex-1 overflow-auto p-6">` (`AppLayout.tsx:14`) padding to occupy the full content area; `h-[calc(100vh-3.5rem)]` claims the area below the 56px top bar.

2. **Sidebar form controls** containing variable-width content — `FirmwareSelector` (used 8 places), file tree headers, status filter chips. Long firmware names like `RespArray_1.05.00.17.zip` are 24+ characters; `<select>` controls without an explicit width-cap take their longest-option natural width, which can exceed the sidebar pane and bleed into the adjacent main pane.

3. **Long intrinsic-width content** — file paths, Evidence `<pre>` blocks with hex/binary dumps, function signatures, CVE IDs. Without `min-w-0` propagation through the flex ancestry, default `min-width: auto` on flex children prevents shrinking and the content widens its parent.

4. **Floating action buttons** rendered with `absolute bottom-* left-* z-*` over scrollable content — historically the Terminal toggle (`ExplorePage.tsx`), file-tree-collapsed-show button, minimap legend. These obscure data and require either docking into a layout-participating toolbar OR reserving safe-area padding in the scroll container.

Sources of failure observed in session 2026-05-04 (commits `bc013fe` Findings + this pattern's source commit Explore/etc): Findings firmware selector overlapped detail title; Explore Terminal button covered hex viewer rows; Explore selector bled across the divider; missed `overflow-hidden` on outer flex roots allowed horizontal page-level scroll on long content.

## Contract 1 — Split-pane page root

```tsx
// Outer page wrapper — escapes main's p-6, claims viewport, contains everything
<div className="-m-6 flex h-[calc(100vh-3.5rem)] overflow-hidden">
  {/* Sidebar pane — fixed width, contains its own children */}
  <div className="flex w-72 shrink-0 flex-col overflow-hidden border-r border-border">
    {/* sidebar content */}
  </div>

  {/* Main pane — fills remaining width, contains its own children */}
  <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
    {/* docked toolbar (header tabs, action bar) */}
    <div className="flex shrink-0 items-center gap-1 border-b border-border px-2">{/* tabs / actions */}</div>

    {/* scrollable content body — needs min-h-0 + min-w-0 + flex-1 + overflow */}
    <div className="min-h-0 min-w-0 flex-1 overflow-hidden">
      {/* component renders here, typically uses h-full internally */}
    </div>

    {/* docked footer / drag handle / sub-panel — shrink-0, no overlay */}
  </div>
</div>
```

**Rules:**
- `overflow-hidden` on EVERY pane wrapper that must contain its children
- `min-w-0` on the main pane (the flex-1 sibling) so it can shrink instead of overflowing horizontally
- `shrink-0` on fixed-width sidebars and docked toolbars
- `min-h-0 min-w-0 flex-1` on the inner scroll body
- Children that need to scroll use `overflow-y-auto` (or `-x-auto` for code blocks) on themselves, NOT on the pane wrapper

**Anti-patterns:**
- Outer flex root without `overflow-hidden` → horizontal page scroll when any child overflows
- Sidebar without `overflow-hidden` → controls bleed across the divider into the main pane (the actual user-reported bug)
- `relative` on the main pane only because some absolute child needs it — re-dock the child instead (Contract 4)

## Contract 2 — Sidebar form controls (FirmwareSelector pattern)

```tsx
// FirmwareSelector wrapper — flex with min-w-0 so wrapper can shrink
<div className={`flex min-w-0 items-center gap-2 ${className ?? ''}`}>
  <label className="shrink-0 text-xs font-medium text-muted-foreground">Firmware:</label>
  <select className="min-w-0 flex-1 truncate rounded-md border bg-background px-2 py-1 text-sm" title={fullName}>
    {/* options */}
  </select>
</div>
```

**Per-usage className:**

| Context | className | Rationale |
|---|---|---|
| Sidebar pane (Findings, Explore left) | `w-full` | Fill the fixed-width pane (288–384px) |
| Centered top row (ComponentMap) | `w-full max-w-md` | Fill width up to a reasonable cap |
| Inline with sibling button (Hardware, Emulation, Fuzzing) | `min-w-0 max-w-xs` | Cap at 320px; allow shrinking when squeezed |
| Standalone above tabs (SecurityScan, Sbom) | `max-w-md` | Sized cap, no flex-context constraints |

**Rules:**
- Wrapper baseline `flex min-w-0 items-center gap-2` — the `min-w-0` is what allows the select to be SMALLER than its longest option text
- Select inside has `min-w-0 flex-1 truncate` — `truncate` triggers `text-overflow: ellipsis` on the visible text of the closed select; the browser handles this natively for `<select>` once a width is set
- `title={selectedOption.text}` provides full text on hover for accessibility
- The label is `shrink-0` so it never collapses to ellipsis; if the label is too long, shorten the label, don't shrink it
- Stack vertically (label row above control row) when the pane is narrow AND the label is long — see `FindingsPage.tsx`'s 2-row header where row 1 is title + Export button, row 2 is the full-width selector

**Anti-pattern:**
- `<div>` wrapper with no `min-w-0` AND no flex semantics — the `<select>` takes natural width = longest option text width, blowing past the sidebar boundary

## Contract 3 — Long content (paths, hex dumps, code blocks)

```tsx
// File path / long identifier — break-all wraps inside the button
<div className="flex min-w-0 items-start gap-2">
  <FileText className="mt-0.5 h-4 w-4 shrink-0 text-muted-foreground" />
  <button className="min-w-0 flex-1 break-all text-left text-sm font-mono text-primary hover:underline">
    {filePath}{lineNumber != null && `:${lineNumber}`}
    <ExternalLink className="ml-1 inline h-3 w-3" />
  </button>
</div>

// Truncate-with-ellipsis (when you'd rather hide the prefix than wrap)
<span className="min-w-0 flex-1 truncate font-mono">{filePath}</span>

// Preformatted block (hex, binary, JSON) — local horizontal scroll only
<pre className="max-h-80 w-full max-w-full overflow-auto whitespace-pre rounded-md bg-muted p-3 text-xs">
  {content}
</pre>
```

**Rules:**
- Every flex parent in the chain leading to a long-content child needs `min-w-0` — propagate it from the page root through every intermediate flex
- `break-all` for paths in the detail pane (full text visible, multi-line wrap)
- `truncate` for paths in tight list rows (single line + ellipsis); pair with `min-w-0 flex-1` so the truncate context has a defined width
- `whitespace-pre` (NOT `whitespace-pre-wrap`) on preformatted blocks where vertical wrap would scramble alignment; rely on `overflow-x-auto` for long lines
- Icons inside long-content rows are `shrink-0` so they never participate in compression

**Anti-pattern:**
- `<pre className="overflow-auto">` without `w-full max-w-full` — long unbroken lines push the parent wider, defeating the parent's `min-w-0`

## Contract 4 — Floating actions (or NOT)

**Prefer docked over absolute.** Re-architect the floating action into a layout-participating element:
- A header/tabs row toolbar (preferred when there's existing chrome at the top of a pane)
- A footer toolbar (when there's a natural bottom strip; e.g. status indicators below scroll content)
- An action group on the right side of the page header

```tsx
// PREFERRED — docked Terminal toggle in the tabs row
<div className="flex shrink-0 items-center gap-1 border-b border-border px-2">
  <button onClick={() => setViewMode('files')}>...</button>
  <button onClick={() => setViewMode('uefi')}>...</button>
  <button className="ml-auto" onClick={() => setTerminalOpen(!terminalOpen)}>
    <TerminalSquare /> Terminal
  </button>
</div>
```

**If overlay IS necessary** (e.g. the action depends on scroll position; or only appears transiently): reserve safe-area padding in the scroll container so the LAST rows are still readable:

```tsx
<div className="overflow-y-auto pb-16">{/* +64px bottom padding reserves space for the floating button */}
  {/* scrollable content */}
</div>
```

**Rules:**
- Default to docked actions in headers/footers/toolbars
- Only use `absolute` when the action is layered (e.g. zoom controls on a graph viewport, minimap)
- Z-index NEVER fixes a containment bug — if you reach for `z-`, the layout is wrong
- Floating actions over scrollable data ALWAYS need either re-docking OR reserved padding — never both unspecified

**Anti-pattern:**
- `absolute bottom-4 left-4 z-10` over a scrollable file viewer with no bottom padding — the last rows are silently obscured

## Verify

- [ ] **Bundle grep** after frontend rebuild: `docker compose exec -T frontend sh -c "grep -c 'absolute bottom\\|absolute top' /usr/share/nginx/html/assets/<Page>-*.js"` should match the count of legitimate overlay uses (modals, minimap, etc.). Any new `absolute` over scrollable data is a regression.
- [ ] **Manual narrow-viewport test:** narrow the browser window to 1024px, open the page; sidebars must clip cleanly at the divider; no horizontal page scrollbar.
- [ ] **Long-content test:** verify with a long firmware name (e.g. `RespArray_1.05.00.17.zip`), a deeply nested file path (`zip_extract/target/zImage-restore.tar.xz_extract/...`), and a long hex line — none should expand the page width.
- [ ] **Rule #24 typecheck canary** before trusting "0 errors": `echo 'const x: number = "nope"; export default x;' > frontend/src/__canary.ts && (cd frontend && npx tsc -b --force); rm frontend/src/__canary.ts` — expect non-zero.
- [ ] **Rule #26 frontend rebuild** after any layout change: `docker compose up -d --build frontend`, then bundle grep for the new constraint classes (`min-w-0`, `overflow-hidden`, `break-all`, `whitespace-pre`, `ResizeObserver`).

## Debug

- **"Selector overflows the pane":** the wrapper or one of its flex ancestors lacks `min-w-0`. Walk from the overflowing child up to the page root; every flex parent in the chain needs `min-w-0`. Also verify the pane itself has `overflow-hidden` so even a too-wide child gets clipped at the divider.
- **"Page has horizontal scroll":** the outer `-m-6 flex h-[calc(100vh-3.5rem)]` root lacks `overflow-hidden`. Add it; the `<main>` parent's `overflow-auto` will then have nothing to scroll horizontally.
- **"Last rows of scroll content hidden":** a floating absolute child sits over the scroll container without bottom padding. Either re-dock the child (preferred) or add `pb-16` (or sized to the floating element) to the scroll container.
- **"`<select>` doesn't truncate":** the select needs an explicit width via `min-w-0 flex-1` inside a constrained wrapper; without that, the select takes its natural longest-option width regardless of `truncate`. The closed-select text truncation is browser-native once the select itself has a sized width.
- **"react-window list height drifts when header layout changes":** replace the fragile `style={{ height: 'calc(100vh - <magic-number>px)' }}` with a `useRef + ResizeObserver` on a `min-h-0 flex-1` parent (`FindingsList.tsx` reference). Measured height adjusts automatically when the surrounding chrome resizes.

## Source commits

- `bc013fe` 2026-05-04 — FindingsPage two-row header + ResizeObserver list height + FirmwareSelector min-w-0 wrapper + FindingDetail break-all path + evidence whitespace-pre
- (this pattern's source commit) 2026-05-04 — ExplorePage overflow-hidden + Terminal docked in tabs row + ComponentMapPage overflow-hidden + Hardware/Emulation/Fuzzing/SecurityScan/Sbom FirmwareSelector max-w-* caps
