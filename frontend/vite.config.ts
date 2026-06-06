import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import path from 'path'

const escapeHtml = (s: string) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')

const ALWAYS_ALLOWED = new Set(['localhost', '127.0.0.1'])
const extraAllowedHosts = (process.env.EXTRA_ALLOWED_HOSTS ?? '')
  .split(',')
  .map((h) => h.trim())
  .filter(Boolean)
const ALLOWED = new Set([...ALWAYS_ALLOWED, ...extraAllowedHosts])

function hostGuardPlugin(): Plugin {
  return {
    name: 'wairz-host-guard',
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const host = (req.headers.host ?? '').split(':')[0]
        if (ALLOWED.has(host)) return next()
        const safeHost = escapeHtml(host)
        res.statusCode = 403
        res.setHeader('Content-Type', 'text/html; charset=utf-8')
        res.end(`<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Host not allowed — Wairz</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 640px; margin: 4rem auto; padding: 0 1.5rem; color: #111; line-height: 1.6; }
    code { background: #f3f4f6; padding: .15em .4em; border-radius: 4px; font-size: .875em; }
    ol { padding-left: 1.5rem; } li { margin: .4rem 0; }
    .host { color: #dc2626; font-weight: 600; }
  </style>
</head>
<body>
  <h2>Host not allowed</h2>
  <p>The hostname <span class="host">${safeHost}</span> is not in the Wairz allowlist.</p>
  <ol>
    <li>Open <code>.env</code> and add <code>${safeHost}</code> to <code>EXTRA_ALLOWED_HOSTS</code> (comma-separated).</li>
    <li>Delete and re-create the backend:<br><code>docker compose rm -sf backend &amp;&amp; docker compose up -d backend</code></li>
    <li>Re-create the frontend:<br><code>docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d frontend</code></li>
  </ol>
</body>
</html>`)
      })
    },
  }
}

export default defineConfig({
  plugins: [react(), tailwindcss(), hostGuardPlugin()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    allowedHosts: true, // host blocking is handled by hostGuardPlugin with a custom message
    proxy: {
      '/api': {
        target: process.env.VITE_BACKEND_URL ?? 'http://localhost:8000',
        changeOrigin: true,
        ws: true,
      },
    },
  },
})
