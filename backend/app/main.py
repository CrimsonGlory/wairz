import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request

from app.config import get_settings
from app.logging_config import configure_logging
from app.middleware.asgi_auth import APIKeyASGIMiddleware

# Structured JSON logging (Phase 3 / O3) — configure at module import so
# uvicorn's own startup lines (``Waiting for application startup``, ``Uvicorn
# running on ...``) are also emitted as JSON. The lifespan hook is too late:
# uvicorn emits its boot lines before ASGI lifespan starts.
configure_logging(level=os.environ.get("LOG_LEVEL", "INFO"))
from app.rate_limit import limiter  # shared rate-limiter instance (B.1.b)
from app.routers import analysis, apk_scan, attack_surface, comparison, compliance, component_map, cra_compliance, device, documents, emulation, events, export_import, files, findings, firmware, fuzzing, hardware_firmware, health, kernels, projects, sbom, security_audit, terminal, tools, uart
from app.routers.terminal import system_ws_router as _system_ws_router
from app.services.event_service import event_service
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    import sys
    settings = get_settings()

    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)

    # Refuse to start if auth is not configured (B.1.a).
    # Set API_KEY in .env (or environment) for production.
    # Set WAIRZ_ALLOW_NO_AUTH=true only for local-only single-user deployments.
    if not settings.api_key and not settings.allow_no_auth:
        print(
            "ERROR: api_key is required. Set API_KEY in .env or "
            "WAIRZ_ALLOW_NO_AUTH=true for local-only deployments.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Connect Redis event bus
    try:
        await event_service.connect()
        app.state.event_service = event_service
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "Redis unavailable — SSE event bus disabled. "
            "Polling fallback will continue to work."
        )

    # Start loading CPE dictionary in background (non-blocking)
    try:
        from app.services.cpe_dictionary_service import get_cpe_dictionary_service
        cpe_svc = get_cpe_dictionary_service()
        await cpe_svc.ensure_loaded()
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "CPE dictionary background load failed — fuzzy matching will use local map only"
        )

    # Reap orphan device-dump rows. After a backend crash a row stuck in
    # 'queued'/'running' would block POST /dumps with a 409 forever (the
    # runner asyncio task that owned it is gone). Flip them to 'failed'
    # so the next dump attempt isn't blocked by a phantom. Companion to
    # the F-A-01 Rule #33 refactor (audit-2026-05-04).
    try:
        from datetime import datetime, timezone
        from sqlalchemy import update
        from app.database import async_session_factory
        from app.models.device_dump import DeviceDumpSession

        async with async_session_factory() as db:
            res = await db.execute(
                update(DeviceDumpSession)
                .where(DeviceDumpSession.status.in_(("queued", "running")))
                .values(
                    status="failed",
                    error="Backend restarted; runner state lost",
                    finished_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            if res.rowcount:
                import logging
                logging.getLogger(__name__).info(
                    "Reaped %d orphan device-dump row(s) on startup", res.rowcount,
                )
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "Device-dump orphan reaper failed — phantom rows may block new dumps "
            "until the next startup",
            exc_info=True,
        )

    # Reap orphan cve-match firmware rows. Same shape as the device-dump
    # reaper above: POST /cve-match's idempotency check (Rule #33a)
    # returns 409 while ``cve_match_status`` sits in 'queued'/'running',
    # and after a crash the asyncio runner that owned the row is gone.
    # Flip stuck rows to 'failed' so the next run isn't blocked. Like
    # device dumps the runner is in-process only (no Docker container
    # side), so STARTUP cleanup is sufficient — no cron needed.
    try:
        from datetime import datetime, timezone
        from sqlalchemy import update
        from app.database import async_session_factory
        from app.models.firmware import Firmware

        async with async_session_factory() as db:
            res = await db.execute(
                update(Firmware)
                .where(Firmware.cve_match_status.in_(("queued", "running")))
                .values(
                    cve_match_status="failed",
                    cve_match_error="Backend restarted; runner state lost",
                    cve_match_finished_at=datetime.now(timezone.utc),
                )
            )
            await db.commit()
            if res.rowcount:
                import logging
                logging.getLogger(__name__).info(
                    "Reaped %d orphan cve-match firmware row(s) on startup",
                    res.rowcount,
                )
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "cve-match orphan reaper failed — phantom rows may block new "
            "cve-match runs until the next startup",
            exc_info=True,
        )

    # Probe the offline UEFI Secure Boot DBX bundle (Phase β.10 / Rule #37
    # candidate). The bundle is baked into the image at build time
    # (backend/Dockerfile + backend/ms-anchors/dbxupdate.bin); the worker's
    # match_dbx_revocation reads via $DBX_BUNDLE_PATH. Logging presence +
    # size + mtime at boot lets operators confirm the bundle survived the
    # build and the cron-refresh schedule held. Anything other than
    # "bundle present, size > 0" silently degrades dbx_revoked → False
    # for every PE — surface the state so it's not invisible.
    try:
        import logging
        from datetime import datetime, timezone
        from pathlib import Path
        bundle_path_str = os.environ.get(
            "DBX_BUNDLE_PATH", "/opt/wairz/dbxupdate.bin",
        )
        bundle_path = Path(bundle_path_str)
        log = logging.getLogger(__name__)
        if bundle_path.is_file():
            stat = bundle_path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            log.info(
                "DBX bundle ready: path=%s size=%d mtime=%s",
                bundle_path_str, stat.st_size, mtime.isoformat(),
            )
        else:
            log.warning(
                "DBX bundle NOT FOUND at path=%s — every PE will report "
                "dbx_revoked=False (no offline revocation data). Rebuild "
                "the worker image (CLAUDE.md Rule #8) or run "
                "scripts/refresh-ms-roots.sh.",
                bundle_path_str,
            )
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "DBX bundle probe failed unexpectedly", exc_info=True,
        )

    yield

    # Shutdown Redis
    await event_service.disconnect()


app = FastAPI(
    title="Wairz",
    description="AI-Assisted Firmware Reverse Engineering & Security Assessment",
    version="0.1.0",
    lifespan=lifespan,
)

# Attach rate limiter state, 429 handler, and SlowAPI middleware (B.1.b).
# SlowAPIMiddleware intercepts requests and checks @limiter.limit() decorators.
# The exception handler converts RateLimitExceeded → HTTP 429 JSON response.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

_cors_origins = (
    get_settings().cors_origins.split(",")
    if get_settings().cors_origins
    else ["http://localhost:3000", "http://127.0.0.1:3000"]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)

# API key auth — pure-ASGI middleware covers both http and websocket
# scopes. The prior BaseHTTPMiddleware-based APIKeyMiddleware only
# intercepted HTTP, leaving /ws terminal and /{session}/terminal ws-to-tcp
# proxy endpoints unauthenticated.
app.add_middleware(APIKeyASGIMiddleware)

app.include_router(health.router)
app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(component_map.router)
app.include_router(hardware_firmware.router)
app.include_router(findings.router)
app.include_router(documents.router)
app.include_router(sbom.router)
app.include_router(terminal.router)
app.include_router(emulation.router)
app.include_router(fuzzing.router)
app.include_router(kernels.router)
app.include_router(comparison.router)
app.include_router(export_import.router)
app.include_router(uart.router)
app.include_router(device.router)
app.include_router(security_audit.router)
app.include_router(compliance.router)
app.include_router(cra_compliance.router)
app.include_router(attack_surface.router)
app.include_router(apk_scan.router)
app.include_router(tools.router)
app.include_router(events.router)
app.include_router(_system_ws_router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


# Prometheus /metrics — auth-exempt per ``asgi_auth._EXEMPT_HTTP_PATHS``.
# Instrumentator is configured AFTER all routers so it picks up every route;
# ``include_in_schema=False`` keeps /metrics out of the OpenAPI spec.
# Operators exposing /metrics beyond the host should gate it at the ingress
# layer — scraper convention is unauthenticated, not public.
Instrumentator(
    should_group_status_codes=True,
    should_ignore_untemplated=True,
    should_respect_env_var=False,
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
