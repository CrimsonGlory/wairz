// OIDC Authorization Code + PKCE login via a singleton UserManager
// (oidc-client-ts). The SPA redirects to the Cognito hosted UI, which — once an
// operator federates an external IdP (JumpCloud/Okta/…) into the Cognito pool —
// transparently brokers to that IdP. No app change needed for SSO.
//
// Kept outside React so the axios interceptor (also outside React) can read the
// current access token. Only constructed when runtime config enables auth.

import { UserManager, WebStorageStateStore, type User } from 'oidc-client-ts'

import { getCachedConfig } from './runtimeConfig'

let manager: UserManager | null = null

export function getUserManager(): UserManager | null {
  const cfg = getCachedConfig()
  if (!cfg.authEnabled || !cfg.oidc) return null
  if (!manager) {
    manager = new UserManager({
      authority: cfg.oidc.authority,
      client_id: cfg.oidc.clientId,
      redirect_uri: `${window.location.origin}/callback`,
      post_logout_redirect_uri: window.location.origin,
      response_type: 'code', // Authorization Code + PKCE
      scope: cfg.oidc.scope ?? 'openid email profile',
      userStore: new WebStorageStateStore({ store: window.localStorage }),
      automaticSilentRenew: true,
    })
  }
  return manager
}

export async function getAccessToken(): Promise<string | null> {
  const um = getUserManager()
  if (!um) return null
  const user = await um.getUser()
  return user && !user.expired ? user.access_token : null
}

export async function login(returnTo?: string): Promise<void> {
  const um = getUserManager()
  if (um) await um.signinRedirect({ state: returnTo ?? window.location.pathname })
}

export async function handleCallback(): Promise<User | null> {
  const um = getUserManager()
  if (!um) return null
  return um.signinRedirectCallback()
}

export async function logout(): Promise<void> {
  const um = getUserManager()
  const cfg = getCachedConfig()
  if (!um || !cfg.oidc) return
  // Cognito's logout endpoint clears its session, then returns to the SPA.
  await um.removeUser()
  if (cfg.oidc.cognitoDomain) {
    const params = new URLSearchParams({
      client_id: cfg.oidc.clientId,
      logout_uri: window.location.origin,
    })
    window.location.href = `${cfg.oidc.cognitoDomain}/logout?${params.toString()}`
  }
}
