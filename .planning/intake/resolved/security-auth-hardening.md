---
title: "Security: Authentication Hardening"
status: completed
priority: critical
target: backend/app/middleware/, backend/app/routers/terminal.py, backend/app/main.py, backend/app/config.py
completed_at: 2026-04-19
completed_in: session 69f004fe phase 1
shipped_commits:
  - 3d8aa10  # feat(security): B.1 pure-ASGI auth middleware — http + websocket scopes
  - de3f6bd  # feat(security): B.1.a/b — startup auth guard + slowapi rate limiting
  - ab09e1c  # feat(security): safe_extract_zip — zipslip + bomb + symlink defences
  - bac49ea  # feat(security): narrow Docker access via socket proxy (D.1)
  - e443def  # fix(security): eliminate double-shell injection at 4 sites in services
closed_by: wave3-stream-gamma (Rule-19 status-bump)
---

## Problem

The authentication model has three compounding defects that make any deployment beyond `127.0.0.1` dangerous:

1. **WebSocket endpoints bypass auth entirely.** `backend/app/middleware/auth.py:21` extends `starlette.middleware.base.BaseHTTPMiddleware`, which only intercepts HTTP. WebSocket scope (`scope["type"] == "websocket"`) routes around it. Affected endpoints:
   - `backend/app/routers/terminal.py:87` — `@router.websocket("/ws")` spawns an Alpine container with a read-only firmware mount and attaches `/bin/sh`
   - `backend/app/routers/terminal.py:307` — `websocket_tcp_proxy` forwards arbitrary bytes into ports on system-emulation containers

2. **Default config disables auth.** `backend/app/config.py:74` → `api_key: str = ""`. Middleware short-circuits on empty key (`middleware/auth.py:26-27`). Fresh deploys or missing `.env` = open backend.

3. **No rate limiting.** Single leaked API key is unbounded. Upload endpoints have no concurrent-connection cap.

## Root Cause

`BaseHTTPMiddleware` + optional-by-default auth + no rate limit.

## Approach

**Step 1 — Replace HTTP middleware with pure ASGI middleware covering WebSockets.**

Create `backend/app/middleware/asgi_auth.py` as a pure ASGI middleware (signature `async def __call__(self, scope, receive, send)`). Handle both `http` and `websocket` scopes. For WebSockets, read `X-API-Key` from headers OR `api_key` from query params BEFORE calling `websocket.accept()`. Close with code 4401 on auth failure.

Replace `app.add_middleware(APIKeyMiddleware)` in `main.py:73` with the new middleware.

**Step 2 — Require `api_key` unless explicitly bypassed.**

In `config.py`:
```python
api_key: str | None = None
allow_no_auth: bool = False  # WAIRZ_ALLOW_NO_AUTH env var
```

In `main.py` lifespan (`main.py:17-48`), after Redis connect, assert:
```python
if not settings.api_key and not settings.allow_no_auth:
    import sys
    print("ERROR: api_key is required. Set API_KEY in .env or set WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.", file=sys.stderr)
    sys.exit(1)
```

**Step 3 — Add rate limiting via slowapi.**

```bash
uv add slowapi
```

In `main.py`, add `Limiter(key_func=get_remote_address)`. Default: `"100/minute"`. Apply stricter limits on auth endpoint, upload endpoint, and SSE subscription:
- `/api/v1/projects/{id}/firmware/upload` → `"5/minute"`
- `/api/v1/projects/{id}/events` → `"10/minute"`
- Rest → `"100/minute"`

**Step 4 — Stream-check upload size.**

In `backend/app/services/firmware_service.py` upload path, after each chunk:
```python
file_size += len(chunk)
if file_size > max_bytes:
    raise HTTPException(413, "Upload exceeds MAX_UPLOAD_SIZE_MB")
```

## Files

- `backend/app/middleware/asgi_auth.py` (new)
- `backend/app/middleware/auth.py` (delete or reduce to import shim)
- `backend/app/main.py`
- `backend/app/config.py`
- `backend/app/services/firmware_service.py`
- `backend/pyproject.toml` (slowapi dep)
- `.env.example` (document API_KEY requirement)

## Acceptance Criteria

- [ ] WebSocket `/terminal/ws` returns 4401 close code when API key is absent or wrong
- [ ] Backend refuses to start without `API_KEY` set, unless `WAIRZ_ALLOW_NO_AUTH=true`
- [ ] Rate limiter returns 429 when exceeded on upload endpoint (test with loop)
- [ ] `curl` against `/api/v1/*` without header → 401
- [ ] Existing E2E tests pass (set `API_KEY=test-key` in workflow env)
- [ ] Streaming upload aborts mid-transfer when size exceeds cap

## Risks

- Existing frontend/MCP clients may send the key via cookie or wrong header — audit `frontend/src/api/client.ts` and MCP spawner to confirm `X-API-Key` usage
- WebSocket query-param auth leaks key into access logs — prefer headers; document the query-param fallback as "local dev only"
- slowapi requires Redis to be reachable for distributed rate-limit state — use in-memory backend for now

## References

- Security review C1, C2; Infrastructure review C2, H3
- Related: learned rule auto-review-no-shell-interpolation
