import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App'
import { loadRuntimeConfig } from '@/auth/runtimeConfig'
import { getUserManager, handleCallback } from '@/auth/userManager'

// Bootstrap: load runtime auth config, complete any OIDC login, and require a
// session before rendering — but only when auth is enabled. With auth disabled
// (local dev / config.json authEnabled=false) this is a straight render, so the
// existing local workflow is unchanged.
async function bootstrap() {
  const cfg = await loadRuntimeConfig()

  if (cfg.authEnabled) {
    const um = getUserManager()
    if (um) {
      if (window.location.pathname === '/callback') {
        try {
          await handleCallback()
        } catch (err) {
          console.error('[auth] callback failed', err)
        }
        // Drop the code/state from the URL.
        window.history.replaceState({}, '', '/')
      }
      const user = await um.getUser()
      if (!user || user.expired) {
        await um.signinRedirect({ state: window.location.pathname })
        return // browser navigates to the IdP; nothing to render
      }
    }
  }

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

void bootstrap()
