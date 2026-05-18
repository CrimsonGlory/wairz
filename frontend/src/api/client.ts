import axios, { AxiosError } from 'axios'
import { toast } from 'sonner'

const apiClient = axios.create({
  baseURL: '/api/v1',
  timeout: 30_000,
})

// API key sources, in priority order:
//   1. localStorage.setItem('wairz.apiKey', '<key>') — runtime override
//   2. VITE_API_KEY — build-time default (CI / packaged deploy)
// Re-read on every request via the interceptor below so localStorage
// rotation picks up without a page reload.
export function getApiKey(): string | null {
  if (typeof window !== 'undefined') {
    const fromStorage = window.localStorage.getItem('wairz.apiKey')
    if (fromStorage) return fromStorage
  }
  const fromEnv = import.meta.env.VITE_API_KEY as string | undefined
  return fromEnv || null
}

// Append ?api_key=<key> to a URL. Used for WebSocket URLs where the
// browser can't set custom headers (Sec-WebSocket-* is kernel-controlled).
// Prefer the X-API-Key header for HTTP — query-param path leaks the key
// into uvicorn access logs.
export function appendApiKey(url: string): string {
  const key = getApiKey()
  if (!key) return url
  const sep = url.includes('?') ? '&' : '?'
  return `${url}${sep}api_key=${encodeURIComponent(key)}`
}

// Per-request interceptor so key resolution happens at the latest
// possible moment (picks up localStorage changes without a page reload,
// and guarantees no module-load race).
apiClient.interceptors.request.use((config) => {
  const key = getApiKey()
  if (key && !config.headers.has('X-API-Key')) {
    config.headers.set('X-API-Key', key)
  }
  return config
})

// ─── Response error handling with toast dedupe ────────────────────────
//
// Show at most one toast per category every 10 seconds.  A 100-item
// bulk operation that fails every request would otherwise stack 100
// identical "Authentication failed" toasts — cosmetically bad and
// drowns out any useful signal from the first one.
//
// Keys: 'network' | 'auth' | 'forbidden' | 'server' | 'rateLimit'.
const TOAST_DEDUPE_WINDOW_MS = 10_000
const lastToastAt: Record<string, number> = {}

function toastOnce(
  key: 'network' | 'auth' | 'forbidden' | 'server' | 'rateLimit',
  title: string,
  description: string,
): void {
  const now = Date.now()
  const last = lastToastAt[key] ?? 0
  if (now - last < TOAST_DEDUPE_WINDOW_MS) return
  lastToastAt[key] = now
  toast.error(title, { description })
}

// Module-scope "we're rate-limited until X" cooldown so per-page handlers
// can short-circuit a redundant POST before it leaves the browser. Reads
// the standard `Retry-After` header (slowapi sets seconds-since-now) and
// gates by epoch-ms. Pages don't have to call this — the axios interceptor
// updates it on every 429; pages can OPT IN by importing `rateLimitedUntil`.
let _rateLimitedUntilMs = 0
export function rateLimitedUntil(): number {
  return _rateLimitedUntilMs
}
export function isRateLimited(): boolean {
  return Date.now() < _rateLimitedUntilMs
}
export function rateLimitRemainingMs(): number {
  return Math.max(0, _rateLimitedUntilMs - Date.now())
}

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    // Axios attaches `response` only when the server answered.  A
    // missing `response` means network failure, CORS block, timeout,
    // DNS error, or backend down.
    if (!error.response) {
      const isTimeout = error.code === 'ECONNABORTED'
      toastOnce(
        'network',
        isTimeout ? 'Request timed out' : 'Network error',
        isTimeout
          ? 'The backend did not respond within 30s'
          : 'Could not reach the backend. Check your connection or try again.',
      )
    } else {
      const status = error.response.status
      if (status === 401) {
        toastOnce(
          'auth',
          'Authentication failed',
          'Check your API key in Settings → API Key (or VITE_API_KEY) and reload.',
        )
      } else if (status === 403) {
        toastOnce('forbidden', 'Forbidden', 'You do not have access to this resource.')
      } else if (status === 429) {
        // SlowAPI sets Retry-After as integer seconds. Fallback to 60s if
        // the header is missing or unparseable (defensive — the upstream
        // contract IS to set the header, but axios headers are stringly).
        const retryAfterHeader = error.response.headers?.['retry-after']
        const retryAfterRaw = typeof retryAfterHeader === 'string' ? parseInt(retryAfterHeader, 10) : NaN
        const retryAfterSec = Number.isFinite(retryAfterRaw) && retryAfterRaw > 0 ? retryAfterRaw : 60
        _rateLimitedUntilMs = Date.now() + retryAfterSec * 1000
        // The custom handler in backend/app/main.py sets data.hint to an
        // operator-friendly string; data.error is slowapi's raw form.
        const data = error.response.data as { hint?: string; error?: string; tier?: string } | undefined
        const description =
          data?.hint
          ?? data?.error
          ?? `Rate limit exceeded. Try again in ~${retryAfterSec}s.`
        toastOnce('rateLimit', 'Rate limit reached', description)
      } else if (status >= 500) {
        toastOnce('server', 'Server error', `HTTP ${status} — check backend logs.`)
      }
    }
    // Keep the console breadcrumb for devtools debugging.
    const data = error.response?.data as { detail?: unknown; error?: unknown; hint?: unknown } | undefined
    const detail = typeof data?.detail === 'string' ? data.detail : undefined
    const errMsg = typeof data?.error === 'string' ? data.error : undefined
    const hint = typeof data?.hint === 'string' ? data.hint : undefined
    const message = hint ?? detail ?? errMsg ?? error.message ?? 'An error occurred'
    console.error('[API Error]', message)
    return Promise.reject(error)
  },
)

export default apiClient
