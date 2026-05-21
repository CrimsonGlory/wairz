import { useEffect } from 'react'

/**
 * Polling-backoff hook for 202+polling state-machine endpoints.
 *
 * Replaces hardcoded `setInterval(tick, 2000)` polling loops with an
 * exponential-backoff schedule per W2-β §SC5-NEW-SBOM-λ (Session 2b
 * 2026-05-21): start at 2 s; double to 4/8/16/32 s when the polled
 * status doesn't change; RESET to 2 s on (a) any state transition OR
 * (b) `document.visibilitychange` tab-becomes-visible event.
 *
 * Bounds per-operator DB load during long-running runs (e.g. a 60-min
 * Syft pass at fixed 2 s polling = 1800 GETs → ~120 with backoff).
 *
 * Shape — self-rescheduling setTimeout (NOT setInterval):
 * - setInterval would fire stacked ticks if a slow GET took longer
 *   than the interval; self-rescheduling waits for each tick to
 *   complete before scheduling the next.
 * - visibilitychange listener stomps the pending timeout + immediately
 *   re-ticks so an operator returning to the tab sees fresh state
 *   instead of waiting up to 32 s.
 *
 * Usage:
 *
 *     usePollingBackoff({
 *       enabled: scanning,
 *       fetchStatus: () => getVulnerabilityScanStatus(projectId, fwId),
 *       onStatus: (status) => {
 *         if (status.status === 'completed') { ... }
 *       },
 *     })
 *
 * The hook is responsible for: scheduling, cancellation on unmount,
 * visibilitychange listener, and state-transition detection. The
 * caller is responsible for: the actual fetch + the terminal-state
 * handling (set internal state to stop polling by toggling `enabled`).
 *
 * Cross-refs:
 * - CLAUDE.md Rule #29 (frontend timeout × backend ceiling — partner)
 * - CLAUDE.md Rule #33 (202+polling state machine — partner)
 * - CLAUDE.md Rule #51 §SC5-NEW-SBOM-λ (polling-cadence trips own
 *   30/hour budget — backoff is the mitigation)
 * - Session 2b SbomPage.tsx::handleGenerate polling effect (the
 *   inline pattern this hook extracts from)
 */
export interface PollingBackoffOptions<TStatus extends { status: string }> {
  /** Whether polling is active. Toggle false in `onStatus` to terminate. */
  enabled: boolean
  /** Per-tick fetcher. Must reject on transient errors so the hook
   * can swallow + reschedule without tearing down. */
  fetchStatus: () => Promise<TStatus>
  /** Called after every successful fetch (including the immediate
   * first tick). Use this to stash the status in caller state, run
   * completion callbacks, and toggle `enabled` false on terminal
   * statuses. */
  onStatus: (status: TStatus) => void | Promise<void>
  /** Optional initial interval (default 2000 ms). */
  initialIntervalMs?: number
  /** Optional max interval (default 32000 ms). */
  maxIntervalMs?: number
  /** Re-trigger when these deps change. Mirrors useEffect deps. */
  deps?: ReadonlyArray<unknown>
}

export function usePollingBackoff<TStatus extends { status: string }>(
  options: PollingBackoffOptions<TStatus>,
): void {
  const {
    enabled,
    fetchStatus,
    onStatus,
    initialIntervalMs = 2000,
    maxIntervalMs = 32000,
    deps = [],
  } = options

  useEffect(() => {
    if (!enabled) return
    let cancelled = false
    let intervalMs = initialIntervalMs
    let lastStatus: string | null = null
    let timeoutId: number | null = null

    const scheduleNext = () => {
      if (cancelled) return
      timeoutId = window.setTimeout(() => { void tick() }, intervalMs)
    }

    const tick = async () => {
      if (cancelled) return
      try {
        const status = await fetchStatus()
        if (cancelled) return
        const changed = lastStatus !== null && lastStatus !== status.status
        lastStatus = status.status
        await onStatus(status)
        if (cancelled) return
        // Caller toggles `enabled` false on terminal status; re-evaluate
        // via the useEffect dep that wraps this hook. Until then, back
        // off when status is unchanged; reset on state transition.
        if (changed) {
          intervalMs = initialIntervalMs
        } else {
          intervalMs = Math.min(intervalMs * 2, maxIntervalMs)
        }
        scheduleNext()
      } catch (err) {
        // Transient errors should not kill the polling loop. Schedule
        // the next tick + log for diagnostic visibility.
        console.warn('usePollingBackoff: transient fetch error:', err)
        scheduleNext()
      }
    }

    const onVisibility = () => {
      if (document.visibilityState === 'visible' && !cancelled) {
        intervalMs = initialIntervalMs
        if (timeoutId !== null) {
          window.clearTimeout(timeoutId)
          timeoutId = null
        }
        void tick()
      }
    }
    document.addEventListener('visibilitychange', onVisibility)

    void tick()  // immediate first poll

    return () => {
      cancelled = true
      if (timeoutId !== null) window.clearTimeout(timeoutId)
      document.removeEventListener('visibilitychange', onVisibility)
    }
    // The dependency list intentionally consumes `deps` (caller-provided)
    // rather than `fetchStatus`/`onStatus` directly — the caller is
    // responsible for memoising those (or accepting re-mount cost).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, ...deps])
}
