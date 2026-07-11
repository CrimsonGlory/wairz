// Runtime auth config. The SPA is built once and served from S3/CloudFront, so
// OIDC settings can't be baked in at build time — they're fetched from
// /config.json at startup. Local dev (and any deploy without auth) ships
// { "authEnabled": false }, so the app stays open and skips login entirely.

export interface OidcConfig {
  authority: string // OIDC issuer, e.g. https://cognito-idp.<region>.amazonaws.com/<pool-id>
  clientId: string
  scope?: string // default "openid email profile"
  cognitoDomain?: string // hosted-UI domain, for logout
}

export interface RuntimeConfig {
  authEnabled: boolean
  oidc?: OidcConfig
}

let cached: RuntimeConfig | null = null

export async function loadRuntimeConfig(): Promise<RuntimeConfig> {
  if (cached) return cached
  try {
    const res = await fetch('/config.json', { cache: 'no-store' })
    if (res.ok) {
      const data = (await res.json()) as RuntimeConfig
      cached = data.authEnabled && data.oidc ? data : { authEnabled: false }
      return cached
    }
  } catch {
    // missing/unreachable config.json (e.g. local dev) → auth disabled
  }
  cached = { authEnabled: false }
  return cached
}

export function getCachedConfig(): RuntimeConfig {
  return cached ?? { authEnabled: false }
}
