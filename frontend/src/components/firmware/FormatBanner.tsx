import { Info } from 'lucide-react'

/**
 * Shared format-detection banner — renders a per-capability message
 * when the backend has classified an upload but the operator's current
 * page (SbomPage / VulnScanPage / FindingsPage / etc.) needs to
 * surface the unknown-format graceful-degrade affordance.
 *
 * Extracted from `components/projects/FirmwareUpload.tsx` (Session 2b
 * Scout D adaptability polish, 2026-05-21). The inline banner that
 * shipped in Session 2a's SbomPage is now replaced by this shared
 * component so VulnScan + Findings pages can adopt the same affordance
 * without duplicating the styling/copy.
 *
 * Operator's Rule #52 mandate: "we won't be the only ones ingesting
 * files into the tool". The banner is the operator-visible signal
 * that wairz has classified an upload but doesn't have a strategy
 * for its detected_format. Per Scout D + W2-α convergence, the right
 * affordance is an explicit advisory (NOT an empty results page) +
 * a forward-pointer to the Rule #52 closed-grammar extensibility
 * surface.
 *
 * Props:
 *   - extraction_capability: 'full' | 'partial' | 'none' | string | null
 *     'full' = no banner (standard flow proceeds without UX nudge)
 *     'partial' = blue tone, "Partial extraction" header
 *     'none' = amber tone, "No native extractor" header
 *     other / null = no banner (unknown/uninitialized state)
 *   - detected_format: e.g. 'android_ota' / 'zip_archive' / 'unknown_blob' / null
 *   - capability_note: free-form copy from backend's CAPABILITY_NOTES
 *     in app/services/format_detection.py
 *   - sbom_supported_for_format: optional; when explicitly False adds
 *     a forward-pointer to the Rule #52 YAML extensibility surface
 *
 * Cross-refs:
 * - Original inline banner: FirmwareUpload.tsx::FormatBanner (lines 309-335)
 * - Session 2a inline minimal banner: SbomPage.tsx
 * - Scout D mandatory UX bundle per Session 2 W2-α convergence
 */
export interface FormatBannerProps {
  extraction_capability: string | null
  detected_format: string | null
  capability_note?: string | null
  sbom_supported_for_format?: boolean | null
}

export function FormatBanner({
  extraction_capability,
  detected_format,
  capability_note,
  sbom_supported_for_format,
}: FormatBannerProps) {
  // 'full' capability: standard flow — no banner needed.
  // Null/unknown capability shapes: no banner (operator hasn't reached
  // the post-classify state yet OR the backend didn't populate the field).
  if (!extraction_capability || extraction_capability === 'full') {
    return null
  }

  const isNone = extraction_capability === 'none'
  const tone = isNone
    ? 'border-amber-500/50 bg-amber-500/5 text-amber-900 dark:text-amber-200'
    : 'border-blue-500/50 bg-blue-500/5 text-blue-900 dark:text-blue-200'
  const label = isNone ? 'No native extractor' : 'Partial extraction'

  return (
    <div
      className={`flex items-start gap-2 rounded-md border px-3 py-2 text-sm ${tone}`}
      role="status"
    >
      <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
      <div className="space-y-1">
        <p className="font-medium">
          {label}
          {detected_format && (
            <>
              {' — detected format: '}
              <code>{detected_format}</code>
            </>
          )}
        </p>
        {capability_note && <p className="text-muted-foreground">{capability_note}</p>}
        {sbom_supported_for_format === false && (
          <p className="text-muted-foreground">
            wairz doesn't have an SBOM strategy for this format yet. Per
            Rule #52 closed-grammar extensibility, operators can ship YAML
            extending the file-format catalog without code changes; the
            extraction-strategy catalog surface ships in Session 3.
          </p>
        )}
      </div>
    </div>
  )
}

export default FormatBanner
