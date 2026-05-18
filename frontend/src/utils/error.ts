// Extract a human-readable error message from an axios / fetch / generic error.
//
// Backend body shapes handled, in priority order:
//   1. FastAPI HTTPException                → { detail: "..." }
//   2. SlowAPI RateLimitExceeded (429)      → { error: "Rate limit exceeded: ..." }
//      (per backend/app/main.py custom_rate_limit_exceeded_handler, the
//       structured body also includes `tier`, `retry_after_seconds`, `hint` —
//       this helper returns just the human string; callers needing the
//       structured fields read err.response.data themselves)
//
// Falls back to err.message for non-HTTP errors, then to the caller's fallback.
export function extractErrorMessage(err: unknown, fallback = "An error occurred"): string {
  if (typeof err === "object" && err !== null && "response" in err) {
    const resp = (err as { response?: { data?: { detail?: string; error?: string; hint?: string } } }).response;
    // SlowAPI 429: prefer the `hint` (operator-friendly) when present, then the raw `error`.
    if (resp?.data?.hint) return resp.data.hint;
    if (resp?.data?.detail) return resp.data.detail;
    if (resp?.data?.error) return resp.data.error;
  }
  if (err instanceof Error) return err.message;
  return fallback;
}
