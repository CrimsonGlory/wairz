import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from prometheus_fastapi_instrumentator import Instrumentator
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
from datetime import UTC

from app.rate_limit import custom_rate_limit_exceeded_handler, limiter  # shared rate-limiter instance (B.1.b)
from app.routers import (
    analysis,
    apk_scan,
    attack_surface,
    bare_metal,
    comparison,
    compliance,
    component_map,
    cra_compliance,
    device,
    documents,
    emulation,
    events,
    export_import,
    files,
    findings,
    firmware,
    fuzzing,
    hardware_firmware,
    health,
    kernels,
    projects,
    sbom,
    security_audit,
    terminal,
    tools,
    uart,
)
from app.routers.terminal import system_ws_router as _system_ws_router
from app.services.event_service import event_service
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)

    # Auth gate removed 2026-05-21 per operator direction (backlog
    # `auth-gate-removal-2026-05-21`). The B.1.a refuse-to-start check
    # at this point (pre-fix it raised sys.exit(EX_CONFIG) when the
    # api_key + allow_no_auth pair were both falsy) forced operators
    # to either set an API_KEY OR explicitly opt into
    # WAIRZ_ALLOW_NO_AUTH=true. Wairz's single-
    # operator firmware-RE deployment shape (local-only,
    # BACKEND_HOST_BIND defaults 127.0.0.1) made the gate friction
    # without a security gain — the asgi_auth.py middleware already
    # no-ops cleanly on falsy api_key (per its module docstring:
    # "Auth is disabled entirely when settings.api_key is falsy"), so
    # the lifespan gate was strictly redundant with that pre-existing
    # behaviour. Operators who want multi-user enforcement set
    # API_KEY in .env and the middleware enforces; operators who don't
    # leave it unset and the middleware no-ops. The Settings.allow_no_auth
    # default is also flipped to True in app/config.py for the same
    # reason — env-var override no longer required for single-operator
    # deployments.
    #
    # The Rule #46 META-CANARY at
    # tests/test_main_lifespan_auth_gate.py asserts the gate is gone
    # so a future commit can't silently re-introduce it.

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

    # P3.2.c: register bundled file-format catalog plugins (RTOS detection)
    # then freeze the registry post-startup (W2-β attack I closure).
    # Idempotent — safe under uvicorn workers reloading the module.
    try:
        from app.services.file_format_catalog.plugins import (
            register_default_plugins,
        )
        register_default_plugins(freeze=True)
        import logging

        from app.services.file_format_catalog import PLUGIN_REGISTRY
        logging.getLogger(__name__).info(
            "file-format catalog: registered %d plugin(s); registry frozen",
            len(PLUGIN_REGISTRY),
        )
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "file-format plugin registration failed — rtos_check signals "
            "will return False; by_rtos_family dispatch falls through to "
            "manifest.dispatch.default",
            exc_info=True,
        )

    # Reap orphan device-dump rows. After a backend crash a row stuck in
    # 'queued'/'running' would block POST /dumps with a 409 forever (the
    # runner asyncio task that owned it is gone). Flip them to 'failed'
    # so the next dump attempt isn't blocked by a phantom. Companion to
    # the F-A-01 Rule #33 refactor (audit-2026-05-04).
    try:
        from datetime import datetime

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
                    finished_at=datetime.now(UTC),
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

    # Data-driven orphan-reaper sweep (Session 2b Fix #11). Replaces the
    # 6 hardcoded per-column reaper blocks that previously lived inline
    # here — each was ~30 LOC of identical-shape Try/SQL/Except. The
    # sweep iterates two registries declared in
    # `app/workers/walker_registry.py`:
    #
    # - STATE_MACHINE_REAPER_CONFIGS (9 entries): explicit Rule #33 .a
    #   state-machine columns (cve_match / vuln_scan / sbom /
    #   bare_metal_audit / authenticode_chain / dotnet_decompile /
    #   windows_update_diff / upload_stage / ics_protocol_walk).
    #   upload_stage carries a 15-min grace window per W2-β
    #   §SC5-NEW-SBOM-ε; all others have None grace (in-process work;
    #   the runner sets started_at AFTER acquiring its own session).
    #   ics_protocol_walk DUAL-REGISTERS into WALKER_REAPER_CONFIGS
    #   below because it carries the ``_walk_status`` suffix the
    #   introspection cross-check enforces.
    #
    # - WALKER_REAPER_CONFIGS (26 entries): every *_walk_status column
    #   on the Firmware model. Operator-trigger-MCP runs flip rows
    #   idle → queued → running → completed | failed; auto-fire from
    #   walker_registry.WALKER_AUTO_TRIGGERS leaves status='idle' per
    #   Rule #39 .safe contract.
    #
    # Per W2-β §SC5-NEW-SBOM-S2-SEAM-B mandate: BOTH dicts ship in the
    # same commit as the refactor (even if STATE_MACHINE side were
    # mostly empty — it's actually 8 entries today). The Rule #46
    # META-CANARY in tests/test_main_lifespan_reapers.py size-locks
    # each dict + cross-checks WALKER_REAPER_CONFIGS membership against
    # the Firmware model's *_walk_status column set.
    #
    # The device-dump session reaper above stays inline (different
    # table: DeviceDumpSession; one-off, doesn't need the dict shape).
    try:
        from datetime import datetime, timedelta

        from sqlalchemy import update

        from app.database import async_session_factory
        from app.models.firmware import Firmware
        from app.workers.walker_registry import (
            STATE_MACHINE_REAPER_CONFIGS,
            WALKER_REAPER_CONFIGS,
            WalkerReaperConfig,
        )

        async def _reap_one_config(config: WalkerReaperConfig) -> None:
            """Apply one reaper sweep entry against the Firmware table.

            Logs the rowcount on a non-zero reap; logs the exception on
            failure but does NOT cascade — one bad reaper does not
            block lifespan startup.
            """
            try:
                now = datetime.now(UTC)
                col = getattr(Firmware, config.column_name)
                where_clauses = [col.in_(config.in_progress_states)]
                if config.grace_minutes is not None and config.started_at_column:
                    started_col = getattr(Firmware, config.started_at_column)
                    cutoff = now - timedelta(minutes=config.grace_minutes)
                    where_clauses.append(started_col.is_not(None))
                    where_clauses.append(started_col < cutoff)

                values: dict[str, object] = {config.column_name: "failed"}
                if config.error_column:
                    values[config.error_column] = config.failure_message
                if config.finished_at_column:
                    values[config.finished_at_column] = now

                async with async_session_factory() as db:
                    res = await db.execute(
                        update(Firmware).where(*where_clauses).values(**values)
                    )
                    await db.commit()
                    if res.rowcount:
                        import logging
                        logging.getLogger(__name__).info(
                            "Reaped %d orphan %s firmware row(s) on startup",
                            res.rowcount, config.column_name,
                        )
            except Exception:
                import logging
                logging.getLogger(__name__).warning(
                    "orphan reaper for %s failed — phantom rows may block "
                    "new runs until the next startup",
                    config.column_name,
                    exc_info=True,
                )

        # STATE_MACHINE first (more operator-visible — 202+polling pages
        # rely on these flipping out of 'running' on restart). Then
        # walker columns (operator-triggered re-walks).
        for config in STATE_MACHINE_REAPER_CONFIGS.values():
            await _reap_one_config(config)
        for config in WALKER_REAPER_CONFIGS.values():
            await _reap_one_config(config)
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "two-axis orphan-reaper sweep failed — falling back to "
            "no-reap (phantom rows may block 202+polling endpoints + "
            "operator walker triggers until next startup)",
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
        from datetime import datetime
        from pathlib import Path
        bundle_path_str = os.environ.get(
            "DBX_BUNDLE_PATH", "/opt/wairz/dbxupdate.bin",
        )
        bundle_path = Path(bundle_path_str)
        log = logging.getLogger(__name__)
        if bundle_path.is_file():  # noqa: ASYNC240 — one-shot lifespan startup probe; not on a request hot path
            stat = bundle_path.stat()  # noqa: ASYNC240 — one-shot lifespan startup probe; not on a request hot path
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
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

    # Probe the offline LOLDrivers BYOVD bundle (Phase η.D / Rule #37).
    # The bundle is baked into the image at build time (backend/Dockerfile
    # + backend/ms-anchors/loldrivers.json); the worker's
    # loldrivers_lookup_service reads via $LOLDRIVERS_BUNDLE_PATH. Logging
    # presence + size + mtime + indexed-entry count at boot lets operators
    # confirm the bundle survived the build and the cron-refresh schedule
    # held. Anything other than "bundle present, entries > 0" silently
    # degrades every BYOVD lookup to None — surface the state so it's not
    # invisible.
    try:
        import logging
        from datetime import datetime
        from pathlib import Path

        from app.services.loldrivers_lookup_service import is_loldrivers_available
        bundle_path_str = os.environ.get(
            "LOLDRIVERS_BUNDLE_PATH", "/opt/wairz/loldrivers.json",
        )
        bundle_path = Path(bundle_path_str)
        log = logging.getLogger(__name__)
        if bundle_path.is_file():  # noqa: ASYNC240 — one-shot lifespan startup probe; not on a request hot path
            stat = bundle_path.stat()  # noqa: ASYNC240 — one-shot lifespan startup probe; not on a request hot path
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=UTC)
            available = is_loldrivers_available(bundle_path_str)
            log.info(
                "LOLDrivers bundle ready: path=%s size=%d mtime=%s available=%s",
                bundle_path_str, stat.st_size, mtime.isoformat(), available,
            )
        else:
            log.warning(
                "LOLDrivers bundle NOT FOUND at path=%s — every BYOVD "
                "lookup will return None (no fingerprinting data). "
                "Rebuild the worker image (CLAUDE.md Rule #8) or run "
                "scripts/refresh-loldrivers.sh.",
                bundle_path_str,
            )
    except Exception:
        import logging
        logging.getLogger(__name__).warning(
            "LOLDrivers bundle probe failed unexpectedly", exc_info=True,
        )

    # CLAUDE.md Rule #52 instance #3 / Phase 4 — ICS protocol catalog
    # plugin registration + freeze (W2-β §SC5-NEW-ICS-S2-α HARDENED).
    # AFTER any catalog mtime-cache warmup AND BEFORE the FastAPI yield
    # so the freeze sentinel is locked before any incoming request can
    # reach a register_matcher() call. Closes the
    # Session 1 W2-β §SC5-NEW-ICS-7 hot-reload × plugin attack vector.
    try:
        from app.services.ics_protocol_catalog.plugins import (
            register_default_plugins,
        )

        register_default_plugins(freeze=True)
    except Exception:
        import logging
        logging.getLogger(__name__).exception(
            "ics_protocol_catalog: bundled plugin registration failed at "
            "lifespan startup — walker will operate WITHOUT plugin "
            "matchers; closed-grammar YAML detection still works",
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
# custom_rate_limit_exceeded_handler wraps slowapi's default with structured
# JSON body (tier name + retry_after_seconds + operator-friendly hint) and a
# structured log event so operators don't need to read backend stdout to
# diagnose a frontend "Rate limit reached" toast.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)
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
app.include_router(bare_metal.router)
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
