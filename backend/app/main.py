import ipaddress
import os
from contextlib import asynccontextmanager
from urllib.parse import urlsplit

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.requests import Request

from app.auth.oidc import auth_guard
from app.config import get_settings
from app.routers import analysis, comparison, component_map, documents, emulation, export_import, files, findings, firmware, fuzzing, kernels, projects, reports, sbom, terminal, uart
from app.services.carving_service import CarvingService
from app.utils.sandbox import PathTraversalError


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    os.makedirs(settings.storage_root, exist_ok=True)
    os.makedirs(settings.emulation_kernel_dir, exist_ok=True)
    # Reap any carving sandboxes left running by a previous backend process
    # so we don't accumulate orphans across restarts.
    CarvingService.cleanup_orphans()
    yield


app = FastAPI(
    title="Wairz",
    description="AI-Assisted Firmware Reverse Engineering & Security Assessment",
    version="0.1.0",
    lifespan=lifespan,
)

ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:8000",
    "http://127.0.0.1:8000",
]
ALLOWED_HOSTS = {
    "localhost", "localhost:3000", "localhost:8000",
    "127.0.0.1", "127.0.0.1:3000", "127.0.0.1:8000",
}

# Behind a proxy (ALB/CloudFront) the Host/Origin vary, so allow extending the
# localhost defaults via settings. "*" disables a check entirely. Empty (the
# default) preserves the original localhost-only behavior for the local deploy.
_guard_settings = get_settings()


def _csv(value: str) -> list[str]:
    return [item.strip() for item in value.split(",") if item.strip()]


_HOST_WILDCARD = "*" in _csv(_guard_settings.allowed_hosts)
_ORIGIN_WILDCARD = "*" in _csv(_guard_settings.allowed_origins)
_TRUST_PRIVATE = _guard_settings.guard_trust_private_network
ALLOWED_HOSTS |= {h for h in _csv(_guard_settings.allowed_hosts) if h != "*"}
ALLOWED_ORIGINS.extend(o for o in _csv(_guard_settings.allowed_origins) if o != "*")


def _hostname_ip(hostname: str):
    """Parse a bare hostname (no port, no brackets) into an ip_address, or None
    if it isn't a literal IP (e.g. a DNS name)."""
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        return None


def _split_authority(authority: str) -> str:
    """Return the host portion of a `host[:port]` / `[v6]:port` authority,
    lowercased and without brackets."""
    authority = authority.strip().lower()
    if authority.startswith("["):  # bracketed IPv6 literal, maybe with :port
        end = authority.find("]")
        return authority[1:end] if end != -1 else authority[1:]
    if authority.count(":") == 1:  # host:port (IPv4 or DNS name)
        return authority.rsplit(":", 1)[0]
    return authority  # bare host, or a bare (unbracketed) IPv6 literal


def _is_private_authority(authority: str) -> bool:
    """True when the host of a Host header / Origin authority is a private,
    loopback, or link-local IP address. DNS names never match (they can't be
    rebound to a fixed private target without also passing the Origin check)."""
    ip = _hostname_ip(_split_authority(authority))
    return ip is not None and (ip.is_private or ip.is_loopback or ip.is_link_local)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def origin_host_guard(request: Request, call_next):
    # CSRF + DNS-rebinding guard for the localhost-bound backend. Behind a proxy
    # the Host/Origin vary; a "*" in allowed_hosts/allowed_origins disables the
    # respective check. /health is always exempt so load-balancer probes (which
    # send the target IP as Host) pass regardless of configuration.
    if request.url.path == "/health":
        return await call_next(request)
    host = request.headers.get("host", "")
    host_ok = _HOST_WILDCARD or host in ALLOWED_HOSTS or (
        _TRUST_PRIVATE and _is_private_authority(host)
    )
    if not host_ok:
        return JSONResponse(status_code=403, content={"detail": "host not allowed"})
    origin = request.headers.get("origin")
    if origin:
        origin_ok = _ORIGIN_WILDCARD or origin in ALLOWED_ORIGINS or (
            _TRUST_PRIVATE and _is_private_authority(urlsplit(origin).netloc)
        )
        if not origin_ok:
            return JSONResponse(status_code=403, content={"detail": "origin not allowed"})
    return await call_next(request)


# Bearer-token auth on the HTTP API. No-op when settings.auth_enabled is false
# (the local default), so docker-compose stays open. Registered after the host
# guard; both run per request.
app.middleware("http")(auth_guard)

app.include_router(projects.router)
app.include_router(firmware.router)
app.include_router(files.router)
app.include_router(analysis.router)
app.include_router(component_map.router)
app.include_router(findings.router)
app.include_router(reports.router)
app.include_router(documents.router)
app.include_router(sbom.router)
app.include_router(terminal.router)
app.include_router(emulation.router)
app.include_router(fuzzing.router)
app.include_router(kernels.router)
app.include_router(comparison.router)
app.include_router(export_import.router)
app.include_router(uart.router)


@app.exception_handler(PathTraversalError)
async def path_traversal_handler(request: Request, exc: PathTraversalError):
    return JSONResponse(status_code=403, content={"detail": str(exc)})


@app.get("/health")
async def health():
    return {"status": "ok"}
