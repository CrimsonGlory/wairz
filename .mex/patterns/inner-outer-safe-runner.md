---
name: inner-outer-safe-runner
description: Author a Rule #33 .a state-machine background runner as three functions — INNER (`_do_<op>_run`, pure-logic, takes db, tier-1 testable), OUTER (`run_<op>_background`, owns state machine), and SAFE (`auto_<op>_firmware_safe`, unpack hook). Codified as CLAUDE.md Rule #39 after Rule-of-Three across γ.4 + δ.5 + ε.1.b.3.
triggers:
  - "background runner"
  - "rule 39"
  - "rule #39"
  - "inner outer safe"
  - "auto walk hook"
  - "202 polling background"
  - "state machine runner"
  - "async_session_factory"
edges:
  - target: context/conventions.md
    condition: for the Verify Checklist that lists Rule #39
  - target: patterns/add-jsonb-column.md
    condition: for the result-aggregate stamp helper (Rule #35c) that the inner runner returns
  - target: patterns/docker-rebuild-backend-worker.md
    condition: after the new triplet lands (Rule #8 + Rule #11 import smoke for all three exports)
last_updated: 2026-05-10
---

# Inner / Outer / Safe Runner Triplet

## Context

CLAUDE.md Rule #39. Any background runner that owns a Rule #33 .a 5-state column (`idle → queued → running → completed | failed`) ships as exactly three functions per service module:

| Function | Caller | Session | Status mutation | Exception semantics |
|----------|--------|---------|-----------------|----------------------|
| `_do_<op>_run(db, firmware_id) -> dict` | tier-1 tests + outer wrapper | accepts `db` (caller-owned) | none | propagates |
| `run_<op>_background(firmware_id) -> None` | router endpoint via `asyncio.create_task` or arq | owns `async_session_factory()` | full 5-state transitions | outer guard catches; failure persistence on fresh session |
| `auto_<op>_firmware_safe(firmware_id) -> None` | unpack post-detection hook | owns own session | none (leaves `idle`) | swallowed silently (`logger.exception` + return) |

The pattern is durable beyond the rule-of-three bar — three independent applications across three windows-coverage phases, each with the same shape, each with the same failure-recovery semantics. ζ.1 (Amcache) is the natural 4th application.

**Why three functions, not one or two:**
- **Tier-1 testability** — the inner runner takes `db` as a parameter, so `make_live_db()` can supply a real ORM session inside a pytest fixture. Tier-1 tests run on the dev host without Docker; they can't open `async_session_factory()` (Docker DNS unreachable). Without the inner/outer split, tier-1 must mock the entire session factory, which lies about value flow (Rule #35b). Splitting saves the lie.
- **State-machine ownership separation** — the outer wrapper is the single place that mutates `row.status`. The inner is pure logic; the safe is fire-and-forget. This makes the state machine grep-able: `grep "row.status =" backend/app/services/<svc>.py` should return only the outer wrapper.
- **Auto-walk vs operator-trigger semantics** — the safe wrapper runs from `unpack.py` after detection roots compute. It must NOT mutate `row.status` because that would create a 409 on the operator's later manual `trigger_<op>_walk` MCP call. The triplet shape encodes this constraint structurally.

## Steps

### 1. Inner — `_do_<op>_run`

```python
import logging
import uuid
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.firmware import Firmware
from app.services.firmware_paths import get_detection_roots
from app.services.jsonb_normalizers import _stamp_firmware_<op>_result

logger = logging.getLogger(__name__)


async def _do_<op>_run(db: AsyncSession, firmware_id: uuid.UUID) -> dict:
    """Pure-logic <op> orchestrator. Accepts caller-owned db. Returns
    UNSTAMPED result dict — caller stamps via _stamp_firmware_<op>_result()
    if persisting.
    """
    firmware = (await db.execute(select(Firmware).where(Firmware.id == firmware_id))).scalar_one_or_none()
    if firmware is None:
        return {"errors": [f"firmware {firmware_id} not found"], "by_provider": {}, "evtx_count": 0}

    roots = get_detection_roots(firmware)  # Rule #16
    result = {"errors": [], "by_provider": {}, "evtx_count": 0, "per_file": []}

    for root in roots:
        for evtx_path in walk_<op>_files(root):
            try:
                parsed = parse_<op>_file(evtx_path)
                # Aggregate into result dict — implementation-specific
                result["evtx_count"] += 1
                # ... walk + accumulate ...
            except Exception as exc:
                result["errors"].append(f"{evtx_path}: {exc}")

    return result
```

**Key rules:**
- Takes `db` parameter; caller owns the session.
- Resolves detection roots via `get_detection_roots(firmware)` per Rule #16.
- Returns UNSTAMPED dict (caller calls `_stamp_firmware_<op>_result(...)` per Rule #35c if persisting).
- Does NOT mutate `firmware.status` — outer owns that.
- Does NOT call `db.commit()` — outer owns the transaction.
- Pure synchronous logic + I/O; no `async_session_factory()` calls inside.

### 2. Outer — `run_<op>_background`

```python
import asyncio
import datetime
import traceback

from app.database import async_session_factory


async def run_<op>_background(firmware_id: uuid.UUID) -> None:
    """OUTER state-machine wrapper. Owns Rule #33 .a transitions.
    Failure persistence on fresh session (inner rolled back the original)."""
    try:
        async with async_session_factory() as db:
            firmware = (await db.execute(select(Firmware).where(Firmware.id == firmware_id))).scalar_one_or_none()
            if firmware is None:
                return

            firmware.<op>_walk_status = "running"
            firmware.<op>_walk_started_at = datetime.datetime.utcnow()
            await db.commit()

            try:
                result = await _do_<op>_run(db, firmware_id)
                firmware.<op>_walk_status = "completed"
                firmware.<op>_walk_finished_at = datetime.datetime.utcnow()
                firmware.<op>_walk_result = _stamp_firmware_<op>_result(result)  # Rule #35c
                await db.commit()
            except Exception as exc:
                await db.rollback()
                err = "\n".join(traceback.format_exception(type(exc), exc, exc.__traceback__))[-2000:]
                async with async_session_factory() as fail_db:
                    fail_row = (await fail_db.execute(select(Firmware).where(Firmware.id == firmware_id))).scalar_one_or_none()
                    if fail_row is not None:
                        fail_row.<op>_walk_status = "failed"
                        fail_row.<op>_walk_error = err
                        fail_row.<op>_walk_finished_at = datetime.datetime.utcnow()
                        await fail_db.commit()
                logger.exception("<op> walk failed for firmware %s", firmware_id)
    except Exception:
        logger.exception("unrecoverable error in run_<op>_background firmware=%s", firmware_id)
```

**Key rules:**
- Opens session via `async_session_factory()`. NEVER takes db parameter.
- Idempotent — Router endpoint should already check `if status in ("queued", "running"): raise 409` before invoking (Rule #33 .a). This wrapper trusts that.
- Owns the 5-state transitions (idle → queued → running → completed | failed). NO other function in the codebase mutates these columns.
- Failure persistence uses a FRESH session (`fail_db`) because `db` rolled back on the exception.
- Outer guard catches anything that escapes the inner try (defense-in-depth; should never fire in practice).

### 3. Safe — `auto_<op>_firmware_safe`

```python
async def auto_<op>_firmware_safe(firmware_id: uuid.UUID) -> None:
    """UNPACK-POST-DETECTION HOOK. Fire-and-forget; logs only.
    Stamps result aggregate but does NOT mutate status (leaves `idle` so
    operator's manual trigger works without 409)."""
    try:
        async with async_session_factory() as db:
            result = await _do_<op>_run(db, firmware_id)
            firmware = (await db.execute(select(Firmware).where(Firmware.id == firmware_id))).scalar_one_or_none()
            if firmware is not None:
                firmware.<op>_walk_result = _stamp_firmware_<op>_result(result)
                await db.commit()
    except Exception:
        logger.exception("auto_<op>_firmware_safe failed firmware=%s (suppressed)", firmware_id)
```

**Key rules:**
- Owns own session via `async_session_factory()`.
- Calls inner `_do_<op>_run` (NOT outer — would create 409 conflict).
- Stamps result aggregate so operators see the walk happened.
- DOES NOT mutate `<op>_walk_status` — leaves it `idle` so manual re-trigger works.
- Swallows ALL exceptions silently. Unpack worker MUST NOT block on this.

### 4. Wire the safe hook into `unpack.py`

In `backend/app/workers/unpack.py`, after detection roots are computed:

```python
from app.services.<op>_service import auto_<op>_firmware_safe

# ... after extraction + detection_roots are populated ...
await auto_<op>_firmware_safe(firmware.id)  # fire-and-forget; never blocks
```

### 5. Wire the outer runner into the router

In `backend/app/routers/<resource>.py`:

```python
@router.post("/{firmware_id}/<op>/trigger", response_model=<Op>WalkStatusResponse, status_code=202)
async def trigger_<op>_walk(firmware_id: uuid.UUID, db: AsyncSession = Depends(get_db)) -> <Op>WalkStatusResponse:
    firmware = (await db.execute(select(Firmware).where(Firmware.id == firmware_id))).scalar_one_or_none()
    if firmware is None:
        raise HTTPException(404, "firmware not found")
    if firmware.<op>_walk_status in ("queued", "running"):
        raise HTTPException(409, f"<op> walk already {firmware.<op>_walk_status}")  # Rule #33 .a

    firmware.<op>_walk_status = "queued"
    firmware.<op>_walk_started_at = None
    firmware.<op>_walk_finished_at = None
    firmware.<op>_walk_error = None
    firmware.<op>_walk_result = None
    await db.commit()  # background task's fresh session must see this

    asyncio.create_task(run_<op>_background(firmware.id))  # Rule #33 .d rubric
    return _row_to_status(firmware)
```

### 6. Tier-1 test against the INNER runner

In `backend/tests/test_<op>_service.py`:

```python
import pytest
from tests._live_db import make_live_db
from app.services.<op>_service import _do_<op>_run

@pytest.mark.asyncio
async def test_inner_runner_emits_expected_aggregate(tmp_path):
    """Tier-1 live canary against the INNER runner. Uses real ORM via
    make_live_db(); never opens async_session_factory()."""
    async with make_live_db() as db:
        firmware = await _create_firmware_with_synthetic_<op>_files(db, tmp_path)

        result = await _do_<op>_run(db, firmware.id)

        assert result["errors"] == []
        assert result["evtx_count"] >= 1
        # Live canary: SELECT the persisted row to verify value flow (Rule #35b)
        # If the inner runner stamps a column, the test should refetch + assert.
```

**DO NOT call `run_<op>_background` from tier-1 tests.** It opens `async_session_factory()` which fails with `socket.gaierror` on dev host (Docker DNS not resolvable). Use the inner runner.

## Gotchas

1. **`socket.gaierror` from outer wrapper in tier-1.** First-time authors call `run_<op>_background` from a pytest test, hit the gaierror, debug for 10 minutes. Fix: call `_do_<op>_run` instead. Mechanical tell: any pytest error containing `socket.gaierror` or `Name or service not known` traces back to a test calling the outer wrapper.

2. **Auto-hook mutating status causes 409 on operator trigger.** If `auto_<op>_firmware_safe` sets status to `completed` after auto-walking, the operator's later `POST /trigger` returns 409 even though they want to RE-walk. The safe wrapper MUST leave status `idle`. Operator triggers move it through queued → running → completed.

3. **Inner calling commit().** The inner runner is called from BOTH the outer wrapper AND tier-1 tests AND the safe wrapper. If it calls `db.commit()`, it locks the caller's transaction. Tests will fail with "session already committed" or similar.

4. **Forgetting `_stamp_firmware_<op>_result`.** The inner returns UNSTAMPED dict; the outer + safe stamp via the `_stamp_*` helper from `jsonb_normalizers.py`. Forgetting the stamp produces a JSONB column with no `schema_version`, breaking Rule #35c forward-discipline. Mechanical tell: `SELECT firmware_id, jsonb_typeof(<op>_walk_result), <op>_walk_result->'schema_version' FROM firmware WHERE <op>_walk_result IS NOT NULL` — every row should show `schema_version=1` (or current).

5. **Outer wrapper without outer guard.** If `run_<op>_background` doesn't have a top-level `try/except`, an exception during the initial `async_session_factory()` setup escapes and the asyncio event loop reports an unhandled task. Wrap the entire body. The outer guard is defense-in-depth; the inner try handles the expected case.

6. **Failure persistence on the same session.** When the inner raises, `db` rolled back. Any attempt to write `firmware.<op>_walk_status = "failed"` on the SAME session fails because the session is in a rolled-back state. ALWAYS open a fresh `async_session_factory()` for failure persistence.

## Verify

- [ ] Three functions present in the service module: `_do_<op>_run`, `run_<op>_background`, `auto_<op>_firmware_safe`.
- [ ] Inner takes `db: AsyncSession` parameter; outer + safe do NOT.
- [ ] Inner does NOT call `db.commit()` (grep `def _do_<op>_run` body for `db.commit`).
- [ ] Outer owns 5-state transitions (grep `<op>_walk_status =` — only matches inside `run_<op>_background`).
- [ ] Safe hook wired into `app/workers/unpack.py` post-detection.
- [ ] Router endpoint checks `if status in ("queued", "running"): raise 409` before mutating.
- [ ] Tier-1 test calls inner runner via `async with make_live_db() as db` — never the outer.
- [ ] After Rule #8 rebuild, Rule #11 import smoke verifies all three exports: `docker compose exec -T backend python -c "from app.services.<op>_service import _do_<op>_run, run_<op>_background, auto_<op>_firmware_safe"`.
- [ ] Result aggregate JSONB column gets stamped with `schema_version=1` per Rule #35c (`_stamp_firmware_<op>_result(result)` called in outer + safe).

## Debug

| Symptom | Likely cause | Fix |
|---------|--------------|------|
| Tier-1 test fails with `socket.gaierror` | Test called outer wrapper instead of inner | Change to `_do_<op>_run(db, firmware_id)` with `make_live_db()` session |
| Status stuck in `queued` | `asyncio.create_task` failed silently — outer wrapper crashed before first commit | Add log to top of outer wrapper; check for missing import or session-factory error |
| Status stuck in `running` | Outer wrapper crashed mid-flight; outer guard caught + logged but failure persistence path failed | Check logs for "<op> walk failed" — outer guard message; if absent, the unrecoverable path fired (look for "unrecoverable error in run_<op>_background") |
| Auto-hook fires twice per firmware | Unpack worker race; idempotency missing | Wrap auto-walk in a "skip if walked" guard, OR rely on row.<op>_walk_result null-check |
| Operator's `POST /trigger` returns 409 immediately after upload | Auto-hook set status to non-`idle` | Verify `auto_<op>_firmware_safe` leaves `<op>_walk_status` untouched |
| `Finding` rows missing `confidence` field | Inner runner constructs Finding via FindingService — check the constructor args (Rule #35b: mocks won't catch this; live canary will) | Use ε.1.b's pattern: SELECT the persisted row after canary, inspect every field the service explicitly sets |

## References

- **CLAUDE.md Rule #39** — canonical rule statement.
- **CLAUDE.md Rule #33 .a** — state-machine ownership; idempotent POST + 409.
- **CLAUDE.md Rule #35b** — live canaries against the inner runner.
- **CLAUDE.md Rule #35c** — JSONB stamp + normaliser for the result aggregate.
- **CLAUDE.md Rule #16** — `get_detection_roots(firmware)` inside the inner runner.
- **CLAUDE.md Rule #11** — post-rebuild import smoke for all three exports.
- **Precedent files:**
  - `backend/app/services/registry_hive_walker.py` (γ.4 — implicit)
  - `backend/app/services/windows_update_diff_service.py` (δ.5 — first explicit)
  - `backend/app/services/evtx_service.py` (ε.1.b.3 — second explicit)
- **Recipe sibling:** `.mex/patterns/add-jsonb-column.md` (Rule #35c stamp helper).
