---
title: "Infra: Cleanup Scheduler + Migration Race Fix + Observability"
status: completed
priority: high
target: backend/app/workers/, docker-compose.yml, backend/app/main.py, backend/entrypoint.sh
---

> **Status note 2026-04-21 (Rule-19 audit):** Shipped via session 435cb5c2 Stream Delta
> across 7 commits (see `.planning/campaigns/wairz-intake-sweep-2026-04-19.md` Phase 4
> history). Live audit verified:
> - **O1** arq cron jobs for cleanup — commits `0f3e87a` (FuzzingService.cleanup_orphans
>   DB↔container reconciliation) and `e8548fd` (arq cron jobs). Seven cron entries now
>   registered in `backend/app/workers/arq_worker.py:687-693`:
>   `sync_kernel_vulns`, `cleanup_emulation_expired`, `cleanup_fuzzing_orphans`,
>   `check_storage_quota`, `cleanup_tmp_dumps`, `reconcile_firmware_storage`,
>   `cleanup_analysis_cache`.
> - **O2** migration race fixed via one-shot `migrator` service: commit `b8b9bd9`.
>   `docker-compose.yml:16` defines the service; lines 211 and 269 show
>   `migrator: condition: service_completed_successfully` gating on backend + worker.
> - **O3** observability —
>   - structlog + prometheus-fastapi-instrumentator deps + JSON logging config: commit
>     `a4e9eb8` (`backend/app/logging_config.py` exists, 3346 bytes).
>   - `/ready` + `/metrics` via health router extraction: commit `566637a`.
>   - `backend/app/main.py:147-151` wires the `Instrumentator().instrument(app)
>     .expose(app, endpoint="/metrics", include_in_schema=False)` pipeline.
>   - JSON logging fixups: commits `3a167ae` and `daa7ecf`.
> This intake is retained for historical reference; further changes go in new intakes.

## Problem

Three independent operational gaps bundled because they share the same subsystems.

### O1. `cleanup_expired()` is never scheduled

`backend/app/services/emulation_service.py:1585` defines `cleanup_expired()` for reaping orphaned emulation containers, but grep for `cleanup_expired` outside the defining file and MCP tool wrapper finds **no caller**. No cron. No arq task. No lifespan task. Emulation containers that outlive their 30-min timeout are never reaped.

Same gap for fuzzing containers (`fuzzing_service.py`). When the backend crashes mid-campaign, the DB row remains `running` and the container is orphaned.

Over time: exhausts memory and pids on the Docker host.

### O2. Migration race between backend and worker

Both backend (`backend/entrypoint.sh:17`) and worker (`docker-compose.yml:136`) run `alembic upgrade head && ...` at startup. On fresh bring-up both race. Alembic's advisory lock partially protects, but:
- One wins, the other's failure logs look like real errors
- If a migration fails, the backend restart loop obscures the cause

### O3. Observability is near-zero

- Bare Python logging: `logging.getLogger(__name__)` with default format (`main.py:28`, `arq_worker.py:21`)
- No structured logs
- No Prometheus endpoint
- `/health` returns `{"status":"ok"}` only (`main.py:106-108`) — doesn't check DB, Redis, or Docker
- No request tracing
- No per-service metrics (cache hit rate, subprocess timings, queue depth)

## Approach

### Fix O1 — arq cron for cleanup

Add cron jobs to `backend/app/workers/arq_worker.py`:

```python
from arq.cron import cron
from app.services.emulation_service import EmulationService
from app.services.fuzzing_service import FuzzingService
from app.services._cache import cleanup_older_than
from app.database import async_session_factory

async def cleanup_emulation_expired(ctx: dict) -> dict:
    async with async_session_factory() as db:
        svc = EmulationService(db)
        reaped = await svc.cleanup_expired()
        await db.commit()
    return {"reaped": reaped}

async def cleanup_fuzzing_orphans(ctx: dict) -> dict:
    async with async_session_factory() as db:
        svc = FuzzingService(db)
        reaped = await svc.cleanup_orphans()  # may need to implement
        await db.commit()
    return {"reaped": reaped}

async def cleanup_stale_cache(ctx: dict) -> dict:
    async with async_session_factory() as db:
        deleted = await cleanup_older_than(db, days=30)
        await db.commit()
    return {"deleted": deleted}


class WorkerSettings:
    # ...existing...
    cron_jobs = [
        cron(cleanup_emulation_expired, minute=5),      # every hour at :05
        cron(cleanup_fuzzing_orphans,   minute=10),     # every hour at :10
        cron(cleanup_stale_cache,       hour=3, minute=0),  # daily 03:00
    ]
```

Implement `FuzzingService.cleanup_orphans()`:
- List all `client.containers.list(filters={"label": "wairz.type=fuzzing"})`
- Cross-reference with `fuzzing_campaigns` DB rows where `status='running'`
- For each mismatch (container exists but DB is stopped, or DB running but container gone), reconcile

### Fix O2 — Single-shot migrator container

Replace the race with a dedicated one-shot service:

```yaml
services:
  migrator:
    build:
      context: ./backend
      dockerfile: Dockerfile
    command: ["alembic", "upgrade", "head"]
    depends_on:
      postgres:
        condition: service_healthy
    env_file: .env
    restart: "no"
  
  backend:
    # ...existing...
    depends_on:
      migrator:
        condition: service_completed_successfully
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
  
  worker:
    # ...existing...
    depends_on:
      migrator:
        condition: service_completed_successfully
      # ...
```

Strip `alembic upgrade head && ` from backend/entrypoint.sh:17 and worker entrypoint.

### Fix O3 — Structured logging + Prometheus + deep health

**Structured logs.** Add `structlog`:

```python
# backend/app/logging_config.py
import structlog
import logging

def configure_logging(level: str = "INFO") -> None:
    logging.basicConfig(level=level, format="%(message)s")
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.stdlib.add_log_level,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
```

Use `structlog.get_logger()` consistently. Grep usage of `logging.getLogger` — keep for compat, but new code uses structlog.

**Prometheus metrics.** Add `prometheus-fastapi-instrumentator`:

```python
# backend/app/main.py
from prometheus_fastapi_instrumentator import Instrumentator

Instrumentator().instrument(app).expose(app, endpoint="/metrics")
```

This gives out-of-the-box:
- Request counts by path / method / status
- Request latency histograms
- In-flight request gauge

Add custom metrics for:
- Cache hit/miss count (`cache_hits_total{service="ghidra"}`)
- Subprocess timing (`subprocess_duration_seconds{tool="ghidra"}`)
- Queue depth (arq queue length — emit from worker cron)

**Deep /health.**

```python
# backend/app/routers/health.py
from fastapi import APIRouter, HTTPException
import asyncio
from app.database import async_session_factory
from app.services.event_service import event_service
import docker

router = APIRouter()

@router.get("/health")
async def health():
    """Shallow liveness probe — doesn't check dependencies."""
    return {"status": "ok"}

@router.get("/ready")
async def ready():
    """Deep readiness probe — checks DB, Redis, Docker."""
    checks = {}
    
    # DB
    try:
        async with async_session_factory() as db:
            await db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception as e:
        checks["db"] = f"fail: {e}"
    
    # Redis
    try:
        await event_service.ping()
        checks["redis"] = "ok"
    except Exception as e:
        checks["redis"] = f"fail: {e}"
    
    # Docker
    try:
        client = docker.from_env()
        await asyncio.get_running_loop().run_in_executor(None, client.ping)
        checks["docker"] = "ok"
    except Exception as e:
        checks["docker"] = f"fail: {e}"
    
    all_ok = all(v == "ok" for v in checks.values())
    if not all_ok:
        raise HTTPException(503, detail=checks)
    return {"status": "ready", "checks": checks}
```

Update Docker healthcheck in `docker-compose.yml:95` to hit `/ready` instead of `/health`.

## Files

### O1
- `backend/app/workers/arq_worker.py` (cron jobs)
- `backend/app/services/fuzzing_service.py` (add cleanup_orphans if missing)
- `backend/app/services/emulation_service.py` (ensure cleanup_expired is robust)

### O2
- `docker-compose.yml` (add migrator service, update depends_on)
- `backend/entrypoint.sh` (remove migration step)

### O3
- `backend/pyproject.toml` (add structlog, prometheus-fastapi-instrumentator)
- `backend/app/logging_config.py` (new)
- `backend/app/main.py` (configure logging, instrument metrics)
- `backend/app/routers/health.py` (new — /health shallow, /ready deep)
- Remove old `/health` from `main.py`
- `docker-compose.yml` (healthcheck uses /ready)

## Acceptance Criteria

### O1
- [ ] Kill an emulation container's DB row while the container runs — cron should reconcile within the hour
- [ ] `docker ps` after running tests shows no stale `wairz-emulation-*` containers older than 1 hour
- [ ] arq logs show successful cron runs

### O2
- [ ] `docker compose up -d` on a fresh DB runs migrations exactly once (check `alembic_version` table has one row)
- [ ] `docker ps` shows `migrator` in `Exited (0)` state after startup
- [ ] Backend and worker start after migrator completes (verify via log timestamps)

### O3
- [ ] `curl http://localhost:8000/metrics` returns Prometheus text format with `http_requests_total`, etc.
- [ ] `curl http://localhost:8000/ready` returns 200 when all deps healthy, 503 when DB or Redis down
- [ ] Logs are valid JSON: `docker compose logs backend | head -5 | jq .` succeeds
- [ ] Custom cache-hit metric increments when running a Ghidra scan

## Risks

- Structured logging changes log format — downstream log aggregators (if any) may need config tweaks
- Prometheus `/metrics` endpoint is typically kept behind auth in production — consider enforcing API key on it, OR bind it to a separate internal-only port
- Single-shot migrator: if it fails, backend AND worker fail to start — clearer error but blocks the whole stack; document the failure-recovery path

## References

- Infrastructure review C6 (no scheduler), C7 (fuzzing orphans), C8 (migration race), H3 (observability), H4-H5 (health checks)
- Related: `backend-cache-module-extraction-and-ttl.md` (provides the cleanup_older_than function)
