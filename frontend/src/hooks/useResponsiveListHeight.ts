import { useEffect, useRef, useState } from 'react'

/**
 * Viewport-relative list-height measurement.  Sites that previously hard-coded
 * `style={{ height: 'min(Xpx, calc(100vh - Ypx))' }}` measure available space
 * at runtime instead — the calc()'s `-Ypx` chrome assumption breaks whenever
 * filter rows wrap, banners are added, or the viewport changes.
 *
 * Returns a ref to attach to the list's wrapping element and the computed
 * height in pixels.  Re-measures on viewport resize AND on parent layout
 * shifts (filter expansion, expand/collapse panels above the list).
 *
 * Mirrors `FindingsList.tsx:52` and `SbomPage.tsx:1168` (commit baadedb).
 * Audit-2026-05-04 finding F-E-03 / quick-wins M-3.
 */
export interface UseResponsiveListHeightOptions {
  /** Upper cap, e.g. 640.  Matches the legacy `min(Npx, …)` ceiling. */
  maxHeight: number
  /** Floor when the viewport is too short.  Matches legacy `minHeight`. */
  minHeight?: number
  /** Pixels to leave between the list bottom and the viewport bottom. */
  bottomMargin?: number
}

export function useResponsiveListHeight({
  maxHeight,
  minHeight = 240,
  bottomMargin = 32,
}: UseResponsiveListHeightOptions) {
  const ref = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState(maxHeight)

  useEffect(() => {
    const el = ref.current
    if (!el) return
    const update = () => {
      const rect = el.getBoundingClientRect()
      const available = window.innerHeight - rect.top - bottomMargin
      setHeight(Math.max(minHeight, Math.min(maxHeight, available)))
    }
    update()
    window.addEventListener('resize', update)
    // Observe the parent so layout shifts ABOVE the list (filter expansion,
    // accordion toggle) re-measure even though the list element's own size
    // hasn't changed yet.  Matches the SbomPage precedent.
    const parent = el.parentElement
    const ro = parent ? new ResizeObserver(update) : null
    if (parent && ro) ro.observe(parent)
    return () => {
      window.removeEventListener('resize', update)
      ro?.disconnect()
    }
  }, [maxHeight, minHeight, bottomMargin])

  return { ref, height }
}
