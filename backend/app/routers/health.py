"""Health + readiness probes + shallow liveness.

Three endpoints:

- ``GET /health`` — shallow liveness. 200 OK as long as the process is
  listening. No dependency checks. Used by docker-compose container
  healthcheck and external liveness probes.
- ``GET /health/deep`` — deep readiness probe. 200 when DB + Redis + Docker
  daemon + storage root are all reachable; 503 with per-component detail
  otherwise. Historic shape — predates ``/ready`` and is kept for back-compat
  with the Phase 1 verification battery and any external monitoring already
  wired to it.
- ``GET /ready`` — identical to ``/health/deep``, exposed at the canonical
  k8s-style path for future orchestrator migrations. Prefer this in new
  probes; ``/health/deep`` will eventually be a soft-deprecation alias.

All three are auth-exempt via ``app.middleware.asgi_auth._EXEMPT_HTTP_PATHS``.
``/metrics`` (added by prometheus-fastapi-instrumentator) is also auth-exempt.
"""

from __future__ import annotations

import asyncio
import os

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from sqlalchemy import text as _sql_text

from app.config import get_settings
from app.database import async_session_factory
from app.services.event_service import event_service
from app.utils.docker_client import get_docker_client

router = APIRouter(tags=["health"])


@router.get("/health")
async def health() -> dict:
    """Shallow liveness probe — process is up, no dependency checks."""
    settings = get_settings()
    loop = asyncio.get_running_loop()
    storage_root_exists = await loop.run_in_executor(
        None, os.path.isdir, settings.storage_root,
    )
    return {
        "status": "ok",
        "version": "0.1.0",
        "storage_root_exists": storage_root_exists,
    }


async def _run_deep_checks() -> tuple[int, dict]:
    """Core deep-health probe — shared by ``/health/deep`` and ``/ready``.

    Returns a tuple ``(http_status, body_dict)`` so the endpoint handler just
    wraps it in a ``JSONResponse``.
    """
    settings = get_settings()
    checks: dict[str, dict] = {}

    # DB — SELECT 1 round-trip
    try:
        async with async_session_factory() as db:
            await db.execute(_sql_text("SELECT 1"))
        checks["db"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        checks["db"] = {"ok": False, "error": str(exc)[:200]}

    # Redis — PING via the already-connected event_service
    try:
        r = getattr(event_service, "_redis", None)
        if r is None:
            checks["redis"] = {"ok": False, "error": "not connected"}
        else:
            await r.ping()
            checks["redis"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        checks["redis"] = {"ok": False, "error": str(exc)[:200]}

    # Docker daemon — read-only containers.list via socket proxy.
    # Proxy allowlist: CONTAINERS=1. Do NOT switch to client.ping() — the
    # proxy's PING endpoint is uncertain under the current env allowlist.
    # See: .planning/knowledge/wairz-intake-sweep-phase-1-antipatterns.md #2.
    try:
        client = get_docker_client()
        client.containers.list(limit=1)
        checks["docker"] = {"ok": True}
    except Exception as exc:  # noqa: BLE001
        checks["docker"] = {"ok": False, "error": str(exc)[:200]}

    # Storage root
    loop = asyncio.get_running_loop()
    storage_ok = await loop.run_in_executor(
        None, os.path.isdir, settings.storage_root,
    )
    checks["storage"] = {
        "ok": storage_ok,
        "path": settings.storage_root,
    }

    all_ok = all(c["ok"] for c in checks.values())
    status_code = 200 if all_ok else 503
    body = {"status": "ok" if all_ok else "degraded", "checks": checks}
    return status_code, body


@router.get("/health/deep")
async def health_deep() -> JSONResponse:
    """Deep readiness probe — DB, Redis, Docker daemon, storage root.

    Kept at this path for back-compat with the Phase 1 verification battery
    and external monitors already wired to it. New probes should use
    ``/ready``.
    """
    status_code, body = await _run_deep_checks()
    return JSONResponse(status_code=status_code, content=body)


@router.get("/ready")
async def ready() -> JSONResponse:
    """Canonical readiness probe — same checks as ``/health/deep``.

    Prefer this endpoint in new orchestrator configs. It is functionally
    identical to ``/health/deep`` but lives at the k8s-convention path.
    """
    status_code, body = await _run_deep_checks()
    return JSONResponse(status_code=status_code, content=body)
