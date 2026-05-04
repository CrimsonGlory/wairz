---
title: "Security B.1: Pure-ASGI Auth Middleware (HTTP + WebSocket scopes)"
status: completed
priority: critical
parent: security-auth-hardening.md
target: backend/app/middleware/, backend/app/routers/terminal.py, backend/app/routers/emulation.py, backend/app/main.py, backend/app/config.py, frontend/src/api/terminal.ts, frontend/src/hooks/useTerminalWebSocket.ts, frontend/src/components/emulation/EmulationTerminal.tsx
estimated: 2-3 hours
completed_at: 2026-04-19
completed_in: session 69f004fe phase 1
shipped_commits:
  - 3d8aa10  # feat(security): B.1 pure-ASGI auth middleware — http + websocket scopes
  - de3f6bd  # feat(security): B.1.a/b — startup auth guard + slowapi rate limiting
closed_by: wave3-stream-gamma (Rule-19 status-bump)
---

## Scope vs parent intake

Parent `security-auth-hardening.md` bundles four concerns (ASGI middleware, require-api-key, rate limiting, streaming upload size). This file carves out **only B.1** — the ASGI middleware fix — so it can ship in one focused session and unblock flipping the LAN bind (docker-compose.override.yml) back to `127.0.0.1` safely.

Remaining concerns stay in the parent and become B.1.a / B.1.b / B.1.c follow-ons.

## Why this first

Right now `docker-compose.override.yml` exposes backend:8000 + frontend:3000 on 0.0.0.0 so the user can reach the app from their workstation. The `/ws` + `/{session_id}/terminal` WebSocket endpoints are unauthenticated (current `BaseHTTPMiddleware` only intercepts HTTP scope). Any LAN host can open them and get a shell in the backend container — which has the Docker socket mounted. B.1 is the code-layer fix that makes LAN exposure safe; A.1 (loopback bind) was the network-layer band-aid.

## Current state (verified 2026-04-19)

- `backend/app/middleware/auth.py:21` — `class APIKeyMiddleware(BaseHTTPMiddleware)` — only runs on HTTP.
- `backend/app/main.py:73` — `app.add_middleware(APIKeyMiddleware)` stacked after CORS.
- `backend/app/config.py:87` — `api_key: str = ""`.
- Two WebSocket endpoints skipping auth:
  - `backend/app/routers/terminal.py:87` — `@router.websocket("/ws")` spawns Alpine container + `/bin/sh` attach.
  - `backend/app/routers/emulation.py:634` — `@router.websocket("/{session_id}/terminal")` — WS-to-TCP proxy into emulation containers.
- Frontend WS builders:
  - `frontend/src/api/terminal.ts` — `buildTerminalWebSocketURL(projectId)`.
  - `frontend/src/hooks/useTerminalWebSocket.ts:29` — consumes the URL builder.
  - `frontend/src/components/emulation/EmulationTerminal.tsx:80` — builds its own URL inline; needs updating.
- Frontend HTTP already sends `X-API-Key`: `frontend/src/api/client.ts:10`.

## Execution steps

### Step 1 — New ASGI middleware

Create `backend/app/middleware/asgi_auth.py`:

```python
"""Pure-ASGI API-key middleware — covers http + websocket scopes.

Replaces the BaseHTTPMiddleware in auth.py, which only intercepts HTTP.
For WebSockets: reads X-API-Key header OR api_key query param BEFORE
accept(), closes with code 4401 on auth failure.
"""

import secrets
from urllib.parse import parse_qs

from starlette.types import ASGIApp, Receive, Scope, Send

from app.config import get_settings

_EXEMPT_HTTP_PATHS: set[str] = {"/health", "/health/deep", "/api/v1/health"}


class APIKeyASGIMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        settings = get_settings()
        expected = settings.api_key

        # Auth disabled — pass through.
        if not expected:
            await self.app(scope, receive, send)
            return

        scope_type = scope.get("type")

        if scope_type == "http":
            # CORS preflight + health exemptions.
            if scope.get("method") == "OPTIONS" or scope.get("path") in _EXEMPT_HTTP_PATHS:
                await self.app(scope, receive, send)
                return
            if not _check_key(scope, expected):
                await _http_401(send)
                return
            await self.app(scope, receive, send)
            return

        if scope_type == "websocket":
            if not _check_key(scope, expected):
                await _ws_close_4401(send)
                return
            await self.app(scope, receive, send)
            return

        # lifespan / unknown scopes — pass through.
        await self.app(scope, receive, send)


def _check_key(scope: Scope, expected: str) -> bool:
    # Header pass: starlette headers list is list[tuple[bytes, bytes]], lowercase keys.
    headers = dict(scope.get("headers") or [])
    provided = headers.get(b"x-api-key", b"").decode("latin-1") or None

    # Query-param fallback (mainly for browser WebSocket clients that can't
    # set arbitrary headers).
    if not provided:
        qs = scope.get("query_string", b"").decode("latin-1")
        if qs:
            params = parse_qs(qs)
            candidates = params.get("api_key", [])
            if candidates:
                provided = candidates[0]

    if not provided:
        return False
    return secrets.compare_digest(provided, expected)


async def _http_401(send: Send) -> None:
    await send({
        "type": "http.response.start",
        "status": 401,
        "headers": [(b"content-type", b"application/json")],
    })
    await send({
        "type": "http.response.body",
        "body": b'{"detail":"Missing or invalid API key"}',
    })


async def _ws_close_4401(send: Send) -> None:
    # Send close BEFORE accept — browser sees the close cleanly.
    await send({"type": "websocket.close", "code": 4401, "reason": "unauthenticated"})
```

### Step 2 — Swap middleware in main.py

`backend/app/main.py:73`:
```diff
-from app.middleware.auth import APIKeyMiddleware
+from app.middleware.asgi_auth import APIKeyASGIMiddleware
...
-app.add_middleware(APIKeyMiddleware)
+app.add_middleware(APIKeyASGIMiddleware)
```

Delete `backend/app/middleware/auth.py` OR reduce to a re-export shim for one release: `from app.middleware.asgi_auth import APIKeyASGIMiddleware as APIKeyMiddleware`. Prefer delete — no external callers per grep.

### Step 3 — Config type fix

`backend/app/config.py:87`:
```diff
-    api_key: str = ""
+    api_key: str | None = None
```

Keeps the falsy semantics (`if not settings.api_key`) but makes "unset" explicit. Pairs with the future B.1.b require-api-key check.

**CLAUDE.md rule 20 applies here** — this is a `BaseSettings` field shape change, so `docker cp` alone won't apply it. Plan for `docker compose up -d --build backend worker`.

### Step 4 — Frontend WS URL includes api_key

`frontend/src/api/terminal.ts`: update `buildTerminalWebSocketURL` to append `?api_key=<key>` from the same source as the axios `X-API-Key` header (`frontend/src/api/client.ts:10`). Suggest exposing a getter alongside `setApiKey`.

`frontend/src/components/emulation/EmulationTerminal.tsx:80`: same treatment — parameterize.

Consider: also append the key to the normal axios-tracked header on WS if browsers allow it (they don't; Sec-WebSocket-* headers are kernel-controlled). Query param is the only browser-side option — flag in code comment as "query-param fallback is browser-constrained; CLI clients should use X-API-Key header."

### Step 5 — Terminal WS close code cleanup

`backend/app/routers/terminal.py` — the existing `await websocket.close(code=4004)` calls are "not found" style (project/firmware/extracted dir missing). These stay. Add a comment at top of the file noting "auth check happens in APIKeyASGIMiddleware before this handler runs; 4401 is the auth-failure code."

No router-level auth decorator needed — the middleware catches it before `websocket.accept()` is called.

## Acceptance tests (run before commit)

**Backend (docker compose up -d --build backend worker; set `API_KEY=test-key` in .env or via `docker compose exec backend env | grep API_KEY`):**

```bash
# 1. HTTP without key → 401
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/api/v1/projects
# expect: 401

# 2. HTTP with key → 200 (or 404 — anything but 401)
curl -sS -o /dev/null -w "%{http_code}\n" -H "X-API-Key: test-key" http://127.0.0.1:8000/api/v1/projects
# expect: 200

# 3. Health always passes
curl -sS -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/health
# expect: 200

# 4. WS without key → close frame with 4401
# Install wscat: docker run --rm -it node:20 npx wscat -c "ws://10.54.8.152:8000/ws?project_id=<uuid>"
# expect: "Disconnected (code: 4401, reason: unauthenticated)"

# 5. WS with key → opens, project-not-found → 4004
wscat -c "ws://10.54.8.152:8000/ws?project_id=<uuid>&api_key=test-key"
# expect: accept → 4004 close after project lookup fails (or shell if project+firmware valid)

# 6. Auth disabled with empty key preserves dev ergonomics
# (unset API_KEY in .env, restart backend, repeat test 1 → 200)
```

**Frontend (curl-probe, then browser):**
- Set `localStorage.apiKey = "test-key"` in browser devtools, reload.
- Open a firmware project, click Terminal, WS should connect + show prompt.
- Remove localStorage key, reload, open Terminal → WS should close with 4401 + visible error message.

**CI grep guard (optional; add to `.github/workflows/lint.yml`):**
```bash
# Ensure nobody re-introduces BaseHTTPMiddleware for auth.
grep -rn 'BaseHTTPMiddleware' backend/app/middleware/ && exit 1 || exit 0
```

## Deferred follow-ons (not in this plan)

- **B.1.a — require API_KEY unless `WAIRZ_ALLOW_NO_AUTH=true`** (parent intake step 2). Requires `.env` edit, which is hook-blocked in this session — human touch needed.
- **B.1.b — slowapi rate limiting** (parent intake step 3). Separate dep + wiring; ship independently so WS fix isn't blocked.
- **B.1.c — streaming upload-size check** (parent intake step 4). Unrelated code path; separate commit.

## After B.1 lands

Flip `docker-compose.override.yml` back to loopback OR delete it:
```bash
rm docker-compose.override.yml
docker compose up -d backend frontend
```
Then verify LAN refusal matches the A.1 post-condition. Re-exposure via `BACKEND_HOST_BIND=0.0.0.0` env var remains an operator opt-in, but now with auth coverage on both scopes.

## Risks

- **Middleware order:** pure ASGI middleware added via `app.add_middleware()` stacks in the same LIFO order as Starlette's BaseHTTPMiddleware. CORS still runs before auth (`main.py:63` → `main.py:73`). Verify with a cross-origin preflight test if CORS is load-bearing.
- **Query-param leak in access logs:** uvicorn logs include the query string. If the api_key is in `?api_key=...`, it lands in stdout logs. Mitigation: document that production clients MUST use the `X-API-Key` header; query-param path is for browser WebSockets only. Consider a log filter that redacts `api_key=` values in a later pass.
- **Frontend key source-of-truth:** currently lives in localStorage + axios default header. Adding a WS query-param path means two consumers of the same value — ensure a single getter so they don't drift. Small refactor in `src/api/client.ts` to expose `getApiKey()`.
- **Existing sessions drop:** flipping middleware recreates backend; open WS terminals disconnect. Acceptable — single-user dev.

## References

- Parent intake: `.planning/intake/security-auth-hardening.md`
- Handoff: `.planning/knowledge/handoff-2026-04-18-session-59045370-end.md` (open threads §1.B.1)
- Network-layer predecessor: commit `10872d6` (A.1 loopback bind)
- Current override: `docker-compose.override.yml` (git-ignored; re-exposes LAN for access pending B.1)
- CLAUDE.md rule 20 — pydantic BaseSettings field change requires full rebuild, not docker cp.
