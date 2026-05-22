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

- TIER_A_HEAVY (5/hour): SYNCHRONOUS or genuinely-long jobs that hold the
  uvicorn worker (or a single event-loop slot) for minutes.  Currently
  applied to:
    * POST /security/audit         — synchronous, 2-10 min (blocks HTTP)
    * POST /hardware-firmware/cve-match — 202+polling but 7-min peak on
      Yocto-sized corpora; bulk SQL inserts pin the single event loop
      hard enough that concurrent runs starve other tasks.
    * POST /compare/decompilation  — 2× cold-cache Ghidra calls = ~10 min
      worst-case event-loop time (executor-bound but uvicorn awaits).
    * POST /apk-scan/{manifest,bytecode,sast} + /attack-surface/scan
      — CPU-bound sync, executor-bound, multi-minute on large APKs /
      firmware.
  5/hour × ~10 min ≈ 50 min/hour of saturation — the original F-B-07
  envelope.  Heuristic, not a measurement.

- TIER_A_LIGHT_ACK (30/hour): EVENT-LOOP-FREE work bounded ≤2 min.  Covers
  two shapes with the same server-saturation profile:
    (a) 202+polling — sub-second ACK + detached background task (arq job
        or `asyncio.create_task`).  The rate limit bounds how fast an
        operator (or runaway script) can SPAWN N concurrent background
        tasks — NOT to protect uvicorn workers from a long-held HTTP
        request (Rule #33 decoupled that already).
    (b) Sync `run_in_executor` — request handler awaits an executor for
        ≤2 min.  Event loop is FREE during the executor work; the threat
        is threadpool starvation if 30+ concurrent calls land, not event-
        loop pinning.
  Currently applied to:
    * POST /sbom/generate                    — Syft, 30-120 s            (a)
    * POST /sbom/vulnerabilities/scan        — Grype offline DB, 15-45 s (a)
    * POST /hardware-firmware/authenticode-chain — PE-walk, 1-3 min      (a)
    * POST /firmware/{id}/unpack             — arq job, sub-sec ack       (a)
    * POST /device/dumps                     — detached runner, sub-sec   (a)
    * POST /compare/firmware                 — executor filesystem diff   (b)
    * POST /compare/binary                   — executor LIEF binary diff  (b)
    * POST /bare-metal-hint                  — sub-sec ack + walker fire  (a)
  Derivation: vuln-scan ~30 s typical × 30 = 15 min/hour CPU budget on a
  single-uvicorn-process backend with an 8 GB memory cap (post-2026-05-22
  bump) — safe.  Still rejects runaway scripts (a stuck `while True:
  requests.post(...)` hits 30 in <1 min and fails fast).  1-per-2-min is
  comfortable for iterative research workflow.

  Pre-2026-05-22, /firmware/{id}/unpack, /device/dumps, /compare/firmware,
  /compare/binary all rode TIER_A_HEAVY based on a "background work runs
  >2 min on large input" envelope — but the Rule #33 framework prescribes
  classification by event-loop pinning, not detached-work duration.  The
  over-constraint-sweep-2026-05-22 corrects this; see
  `.planning/postmortems/postmortem-over-constraint-sweep-2026-05-22.md`.

- TIER_B_DOCKER (20/hour): Docker-spawn jobs that allocate kernel resources
  (QEMU emulation, AFL++ fuzzing, system-emulation FirmAE).  These are
  202+polling per Rule #33 so the *ack* is fast, but spawning N=20+
  containers/hour starves the pool.

- TIER_C_DEFAULT is the existing implicit `100/minute` from Limiter's
  `default_limits`; included here as a documented constant so future
  tiers slot in naturally.  Suitable for sub-second sync endpoints:
    * POST /compare/text         — pure-Python text diff, milliseconds.
    * POST /compare/instructions — Capstone disassembly diff, μs-to-ms.
"""

import logging

from fastapi.responses import JSONResponse
from limits import parse as _parse_limit
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.requests import Request

# In-memory storage is fine for single-instance deployments.
# To enable distributed rate limiting across multiple replicas, pass:
#   storage_uri="redis://redis:6379/1"
limiter = Limiter(key_func=get_remote_address, default_limits=["100/minute"])

# Per-endpoint tier constants — see module docstring for derivation.
TIER_A_HEAVY = "5/hour"
TIER_A_LIGHT_ACK = "30/hour"
TIER_B_DOCKER = "20/hour"
TIER_C_DEFAULT = "100/minute"

# Reverse map for the custom 429 handler so an operator sees the tier NAME
# (not just the limit string) in the response body + log event. Includes
# BOTH the input form ("5/hour") AND slowapi's parsed-canonical form
# ("5 per 1 hour" via str(limits.parse(...))) because slowapi's
# RateLimitExceeded carries the parsed form in `exc.detail`. Without the
# parsed form, the live canary showed tier="unknown" on every 429 even
# though the limit was correctly attributed.
def _build_tier_reverse_map() -> dict[str, str]:
    pairs = (
        (TIER_A_HEAVY, "TIER_A_HEAVY"),
        (TIER_A_LIGHT_ACK, "TIER_A_LIGHT_ACK"),
        (TIER_B_DOCKER, "TIER_B_DOCKER"),
        (TIER_C_DEFAULT, "TIER_C_DEFAULT"),
    )
    m: dict[str, str] = {}
    for limit_str, tier_name in pairs:
        m[limit_str] = tier_name
        try:
            m[str(_parse_limit(limit_str))] = tier_name
        except Exception:
            # Defensive: if limits.parse ever fails for an exotic tier, the
            # input-form key still covers the legitimate decorator-set value.
            pass
    return m


_TIER_BY_LIMIT_STRING: dict[str, str] = _build_tier_reverse_map()

_log = logging.getLogger("app.rate_limit")


def custom_rate_limit_exceeded_handler(
    request: Request, exc: RateLimitExceeded,
) -> JSONResponse:
    """Custom 429 handler — augments slowapi's default with structured fields.

    Wraps :func:`slowapi._rate_limit_exceeded_handler` so all standard
    headers (``Retry-After``, ``X-RateLimit-Limit``, ``X-RateLimit-Remaining``,
    ``X-RateLimit-Reset``) are preserved unchanged. Replaces the JSON body
    so frontends + log scrapers + operator tooling have a stable shape with
    semantic fields, not a free-form string.

    Body shape::

        {
          "detail": "Rate limit reached: <limit_string> on <path>. Try again in ~Ns.",
          "error":  "Rate limit exceeded: <limit_string>",  # slowapi compat
          "tier":   "TIER_A_HEAVY" | "TIER_A_LIGHT_ACK" | ... | "unknown",
          "retry_after_seconds": <int>,
          "hint":   <same string as detail, for the frontend's hint-first lookup>
        }

    The ``detail`` key keeps FastAPI/HTTPException-compat client code working
    (``extractErrorMessage`` in the frontend reads ``data.detail`` first).
    The ``hint`` key is what ``frontend/src/utils/error.ts`` reads in priority
    order (commit ``69ed1dd``).

    Also emits a structured log line at WARNING level so operators have a
    queryable event without parsing slowapi's stdlib log format. The
    structured log replaces having to ``docker compose logs backend`` to
    diagnose a frontend "rate limit reached" toast.

    Sync function (matches slowapi's default signature; FastAPI dispatches
    sync exception handlers in a threadpool).
    """
    # Get slowapi's canonical response — handles X-RateLimit-* via the
    # existing _inject_headers private method. Reusing it means we don't
    # have to know which slowapi version exposes which header. Note:
    # slowapi's default does NOT set Retry-After (verified 2026-05-18 via
    # live canary on POST /firmware/{id}/unpack — no Retry-After header
    # on the response); we compute and add it manually below.
    base = _rate_limit_exceeded_handler(request, exc)

    # Compute Retry-After. Prefer slowapi's header if it's there (some
    # versions / configs DO set it); else derive from the limit's window
    # size via the parsed `limits.RateLimitItem.get_expiry()`. This is an
    # OVER-estimate (the real wait is time-until-oldest-request-in-window
    # leaves the window, not the full window size), but slightly-too-long
    # is the safe direction — the operator will retry slightly later than
    # they could have, never sooner.
    retry_after_header = base.headers.get("Retry-After")
    retry_after_seconds = 60  # default if everything below fails
    if retry_after_header:
        try:
            retry_after_seconds = int(retry_after_header)
        except (TypeError, ValueError):
            pass
    else:
        # exc.limit is a slowapi Limit wrapper; its .limit attribute is the
        # underlying limits.RateLimitItem with get_expiry().
        try:
            underlying = getattr(exc.limit, "limit", None) or exc.limit
            expiry = underlying.get_expiry()
            if isinstance(expiry, int) and expiry > 0:
                retry_after_seconds = expiry
        except Exception:
            pass  # keep 60s default

    limit_str = str(exc.detail)
    tier_name = _TIER_BY_LIMIT_STRING.get(limit_str, "unknown")
    path = request.url.path
    hint = (
        f"Rate limit reached: {limit_str} on {path}. "
        f"Try again in ~{retry_after_seconds}s."
    )

    # Structured log — lets operators grep with ``event_type:rate_limit_exceeded``
    # in their log shipper. The ``extra`` dict survives through structlog's
    # stdlib processor (configured in logging_config.py).
    client_ip = request.client.host if request.client else "unknown"
    _log.warning(
        "rate_limit_exceeded endpoint=%s tier=%s limit=%s retry_after=%ds ip=%s",
        path, tier_name, limit_str, retry_after_seconds, client_ip,
        extra={
            "event_type": "rate_limit_exceeded",
            "endpoint": path,
            "tier": tier_name,
            "limit": limit_str,
            "retry_after_seconds": retry_after_seconds,
            "client_ip": client_ip,
        },
    )

    body = {
        "detail": hint,
        "error": f"Rate limit exceeded: {limit_str}",
        "tier": tier_name,
        "retry_after_seconds": retry_after_seconds,
        "hint": hint,
    }
    response = JSONResponse(status_code=429, content=body)
    # Carry forward every header slowapi set (X-RateLimit-*). Skip
    # content-* because the new JSONResponse computes its own.
    for header_name, header_value in base.headers.items():
        if header_name.lower() in ("content-type", "content-length"):
            continue
        response.headers[header_name] = header_value
    # Always set Retry-After. slowapi's default _rate_limit_exceeded_handler
    # does NOT set this header (verified empirically); we add it here per
    # RFC 7231 §7.1.3 so HTTP-compliant clients + reverse proxies can act
    # on it without parsing the JSON body.
    response.headers["Retry-After"] = str(retry_after_seconds)
    return response
