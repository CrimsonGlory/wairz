"""Shared rate-limiter instance (B.1.b).

Import the `limiter` object from here in routers that need per-endpoint limits.
The FastAPI app in ``main.py`` attaches this limiter to ``app.state`` and
registers the 429 exception handler so all responses are consistent.

Usage in a router::

    from app.rate_limit import limiter, TIER_A_HEAVY
    from starlette.requests import Request

    @router.post("/expensive")
    @limiter.limit(TIER_A_HEAVY)
    async def my_endpoint(request: Request, ...):
        ...

The ``request: Request`` parameter is **required** by slowapi — it must be the
first positional parameter of the endpoint function (or present by name).

Tiered limits derived from CLAUDE.md Rule #29 backend-ceiling discipline +
audit-2026-05-04 stream B finding F-B-07.  Per-IP keying via
`get_remote_address` (NOT per-API-key — wairz uses a single global key, so
"per API key" would collapse to "per system" and starve multi-client
deployments).  Defaults remain `100/minute` for unlisted endpoints (the
SlowAPIMiddleware applies it to every route).

- TIER_A_HEAVY: ~10-minute jobs that saturate uvicorn workers (security
  audit pipeline, SBOM generate, Ghidra decompile cascades, CVE match).
- TIER_B_DOCKER: Docker-spawn jobs that allocate kernel resources (QEMU
  emulation, AFL++ fuzzing, system-emulation FirmAE).  These are
  202+polling per Rule #33 so the *ack* is fast, but spawning N=20+
  containers/hour starves the pool.
- TIER_C_DEFAULT is the existing implicit `100/minute` from Limiter's
  `default_limits`; included here as a documented constant so future
  tiers slot in naturally.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

# In-memory storage is fine for single-instance deployments.
# To enable distributed rate limiting across multiple replicas, pass:
#   storage_uri="redis://redis:6379/1"
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# Per-endpoint tier constants — see module docstring for derivation.
TIER_A_HEAVY = "5/hour"
TIER_B_DOCKER = "20/hour"
TIER_C_DEFAULT = "100/minute"
