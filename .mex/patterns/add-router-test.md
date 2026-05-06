---
name: add-router-test
description: Add a router-level test file (HTTP-layer + Rule #35b live-canary) for a new or existing FastAPI router under backend/app/routers/.
triggers:
  - "add router test"
  - "test new router"
  - "router coverage"
  - "live canary"
  - "Rule #35b"
edges:
  - target: context/conventions.md
    condition: for the router-level-test mandate + Rule #35b discipline
  - target: patterns/add-rest-endpoint.md
    condition: when adding the router itself — ship the test in the same PR
  - target: patterns/add-jsonb-column.md
    condition: when the router writes a JSONB column whose round-trip needs canary
last_updated: 2026-05-06
---

# Add Router Test

## Context

Every new file under `backend/app/routers/` MUST ship with a matching
`backend/tests/test_<router>.py` in the same PR. CLAUDE.md "Testing
and Validation Policy" (audit-2026-05-04 F-G-03 + F-A-06) makes this
mandatory because:

- 24/27 routers were untested at the HTTP layer when the audit ran;
  a single regression in one of them shipped silently.
- Mock-only tests verify dispatch shape (`mock_db.add.call_count == 1`)
  but structurally cannot catch value-flow bugs like the F-A-06
  confidence-bypass — only a real ORM SELECT against the persisted
  row catches them. This is the Rule #35b "live canary" discipline.

**Exemplar to mirror:** `backend/tests/test_hardware_firmware_router.py`
(sandbox + 200/404/403 fixtures + dependency overrides). The Phase 1
backfill set (`test_security_audit_router.py`, `test_firmware_router.py`,
`test_terminal_router.py`, `test_vulnerability_service.py`,
`test_ghidra_service.py`) shipped 2026-05-06 demonstrates the live-canary
shape for HTTP, WebSocket, and service-layer surfaces.

## Steps

1. **Create the test file** at `backend/tests/test_<router>.py`. Mirror
   the exemplar's imports + fixtures:

   ```python
   from __future__ import annotations
   import uuid
   from unittest.mock import AsyncMock, MagicMock, patch
   import pytest
   from httpx import ASGITransport, AsyncClient
   from sqlalchemy import select

   from app.database import get_db
   from app.main import app
   from app.models.<resource> import <Resource>
   from app.rate_limit import limiter

   from tests._live_db import make_live_db  # for the Rule #35b canary
   ```

2. **Disable auth + rate-limit for the test scope** via autouse fixtures.
   The auth layer has its own dedicated coverage in
   `test_terminal_router.py` (3 layers — middleware unit tests,
   WebSocket smoke, live canary); router-logic tests should not also
   exercise the auth gate.

   ```python
   @pytest.fixture(autouse=True)
   def _disable_api_key_auth(monkeypatch):
       from app.middleware import asgi_auth as _auth_mod
       fake = MagicMock()
       fake.api_key = ""
       monkeypatch.setattr(_auth_mod, "get_settings", lambda: fake)

   @pytest.fixture(autouse=True)
   def _disable_rate_limit():
       prior = limiter.enabled
       limiter.enabled = False
       limiter.reset()
       try: yield
       finally: limiter.enabled = prior

   @pytest.fixture(autouse=True)
   def _cleanup_overrides():
       yield
       app.dependency_overrides.clear()
   ```

3. **Cover the validation branches** with mocked `get_db` and
   service overrides — at minimum the 404/400/409 paths plus one
   happy-path response-schema assertion. Use `app.dependency_overrides`
   for `get_db` and `Depends(<service_factory>)` rather than patching
   the router module.

   ```python
   @pytest.mark.asyncio
   async def test_project_missing_returns_404(client, project_id):
       db = AsyncMock()
       result = MagicMock()
       result.scalar_one_or_none.return_value = None
       db.execute = AsyncMock(return_value=result)
       app.dependency_overrides[get_db] = lambda: db

       resp = await client.post(f"/api/v1/projects/{project_id}/<resource>")
       assert resp.status_code == 404
   ```

4. **Add ≥1 Rule #35b live-canary** that uses `tests._live_db.make_live_db`
   for a real SQLite-backed session, seeds Project + Firmware + any
   referenced rows, runs the actual handler, then SELECTs the persisted
   row and asserts every field the service explicitly sets. `_live_db.py`
   already shims `JSONB` / `ARRAY` / `UUID` PG-only types to
   SQLite-compatible equivalents.

   ```python
   @pytest.mark.asyncio
   async def test_endpoint_persists_row_with_correct_fields(client):
       async for db in make_live_db():
           pid = uuid.uuid4()
           project = Project(id=pid, name="canary", status="ready")
           db.add(project); await db.flush()
           # ... seed the rest of the row graph ...

           app.dependency_overrides[get_db] = lambda: db
           resp = await client.post(f"/api/v1/projects/{pid}/<endpoint>", json=...)
           assert resp.status_code == 200

           # Real SELECT — Rule #35b. Mock tests structurally cannot fail
           # on value-flow bugs (F-A-06 confidence-bypass shape); this can.
           row = (await db.execute(select(<Model>).where(...))).scalar_one()
           assert row.<field> == <expected>
           # ... assert every field the service explicitly sets ...
           break
   ```

5. **Patch lazy-imported symbols at the SOURCE module** (Rule #30). If
   the router does `from app.services.X import Y` INSIDE a function
   body, patching `app.routers.<router>.Y` is a silent no-op. Mechanical
   check before each `patch(...)`:

   ```bash
   grep -n "^from [^#]*import.*\bY\b\|^import .*\bY\b" backend/app/routers/<router>.py
   ```

   If the match is indented (function-body), patch the source:
   `patch("app.services.X.Y", new=AsyncMock(return_value=...))`.

6. **For WebSocket endpoints**, use `starlette.testclient.TestClient`
   WITHOUT the `with` context — the FastAPI lifespan does production-DB
   writes (orphan-row reaper) that race against the test fixture. See
   `test_terminal_router.py::test_websocket_terminal_rejects_missing_key`
   for the canonical shape.

7. **Run the file in the running container** for fast iteration:

   ```bash
   docker cp backend/tests/test_<router>.py wairz-backend-1:/app/tests/
   docker compose exec -T -w /app -e PYTHONPATH=/app backend bash -c \
       "/app/.venv/bin/python -m pytest tests/test_<router>.py -v --tb=short --no-header > /tmp/out.txt 2>&1; cat /tmp/out.txt | tail -50"
   ```

   The redirect-to-tmpfile-then-cat dance is necessary because long
   pytest output streamed via `docker compose exec -T` is truncated
   mid-stream by the wrapper layer (observed across multiple sessions).

## Gotchas

- **Mock patch silently no-ops.** Per Rule #30, `patch("app.routers.X.Y")`
  fails closed when `Y` is lazy-imported inside a function body.
  Symptom: the test calls the real function instead of the mock,
  produces a downstream `FileNotFoundError` or a shape mismatch that
  looks like a service bug. Patch the SOURCE module instead.
- **slowapi rate-limit bleeds across tests.** `POST /audit` is 5/hour;
  `POST /firmware` is 5/minute. Without `_disable_rate_limit`, the
  fourth test in the suite returns 429. The fixture also calls
  `limiter.reset()` to clear in-memory state from prior runs.
- **Lifespan races against test fixture.** `TestClient(app)` inside
  `with` triggers FastAPI lifespan startup, which does
  `update(Firmware).where(cve_match_status='queued').values(status='failed')`
  against the production DB pool. Two concurrent uses surface as
  `cannot perform operation: another operation is in progress`. Use
  `client = TestClient(app)` without `with` for non-lifespan tests.
- **Duplicate index in Firmware model.** `Firmware.project_id` has BOTH
  `index=True` on the column AND `Index("ix_firmware_project_id", ...)`
  in `__table_args__`. PG dedupes silently; SQLite raises
  `index already exists`. `_live_db._dedup_indexes` strips the dupe at
  fixture-setup time so this is invisible to test authors.
- **`@compiles` shim must register before `Base.metadata.create_all`.**
  `tests/_live_db.py` registers JSONB→JSON / ARRAY→JSON / UUID→VARCHAR
  shims at module import; importing the helper anywhere in the test
  module is enough to activate them.
- **Mocking `get_db` doesn't override `async_session_factory`.** Routers
  using `async_session_factory()` directly (terminal.py:97 — its own
  session, not `Depends(get_db)`) are not intercepted by
  `app.dependency_overrides[get_db] = ...`. Patch the factory directly:
  `terminal_mod.async_session_factory = lambda: _fake_factory()`.

## Verify

- [ ] Test file imports `from app.routers.<name>` (not just patches it).
- [ ] At least one validation-branch test per error code the router
      can return (404 / 400 / 409 / 410 etc.).
- [ ] At least one happy-path test asserting the response-schema fields.
- [ ] At least one Rule #35b live-canary using `make_live_db()`.
- [ ] All `patch()` targets verified against Rule #30 (no lazy-import
      silent no-ops).
- [ ] Autouse fixtures: `_disable_api_key_auth`, `_disable_rate_limit`,
      `_cleanup_overrides`.
- [ ] Tests pass: `pytest backend/tests/test_<router>.py -v`.
- [ ] Per-file commit per Rule #25 — one commit per new test file.

## Debug

- **`AttributeError: <module> does not have the attribute 'Y'`:** the
  patch target is wrong because `Y` is lazy-imported. Patch the source
  module per Rule #30.
- **`429 Too Many Requests`:** `_disable_rate_limit` fixture missing
  or `limiter.reset()` not called.
- **`cannot perform operation: another operation is in progress`:**
  TestClient inside `with` triggered the lifespan + production-pool
  race. Drop the `with` for non-lifespan tests.
- **Test passes with mocked dispatch but real bug ships:** mock-only
  test missing the Rule #35b live canary. Add a `make_live_db()` test
  that SELECTs the persisted row.
- **Pytest output truncated mid-traceback in `docker compose exec`:**
  redirect to a tmpfile inside the container, then `cat` it back.
  See step 7.

## Update Scaffold

- [ ] Update `tests/_live_db.py::_dedup_indexes` if your new model
      declares duplicate indexes.
- [ ] If the router exposes a new external-input surface, mention it
      in `.mex/ROUTER.md` "Current Project State" so future agents
      check the test file before edits.
