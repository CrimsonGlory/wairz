"""OIDC / JWT bearer-token auth for the HTTP API.

IdP-agnostic by design. The verifier validates an RS256 access token against a
configured OIDC issuer's JWKS and checks the audience against either the `aud`
claim (generic OIDC) or the `client_id` claim (AWS Cognito access tokens carry
`client_id`, not `aud`). That keeps the app neutral about the identity provider:
point `oidc_issuer` at the deployment's Cognito user pool and federate the
operator's IdP (JumpCloud, Okta, Azure AD, …) into Cognito, or point it straight
at another OIDC issuer.

Everything is gated by `settings.auth_enabled` (default off), so the local
docker-compose deploy and the test suite stay open and unauthenticated. Only the
HTTP API is gated; the MCP server uses the services/DB directly and is unaffected.

NOTE: `@app.middleware("http")` does not intercept WebSocket connections, so the
terminal/UART WS endpoints are not covered here. Those are docker.sock features
that are out of scope for the cloud MVP (PLAN.md §8); gate them when they land
(token via the WS query string, since browsers can't set WS request headers).
"""

from __future__ import annotations

import logging
from functools import lru_cache

import jwt
from jwt import PyJWKClient
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse

from app.config import get_settings

logger = logging.getLogger(__name__)

# Paths reachable without a token: health probes + API docs.
AUTH_ALLOWLIST = {"/health", "/docs", "/redoc", "/openapi.json"}


class AuthError(Exception):
    """Token missing or invalid — surfaced as 401 by the middleware."""


class OIDCVerifier:
    """Validates RS256 OIDC access tokens against an issuer's JWKS."""

    def __init__(self, issuer: str, audience: str, jwks_url: str = ""):
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = jwks_url or f"{self.issuer}/.well-known/jwks.json"
        # PyJWKClient caches the fetched key set in memory. A short timeout makes
        # an unreachable JWKS endpoint fail fast (→ 401) instead of hanging the
        # request until the proxy times out (→ 504). In the cloud the backend
        # reaches the Cognito JWKS via the cognito-idp VPC endpoint.
        self._jwk_client = PyJWKClient(self.jwks_url, cache_keys=True, timeout=5)

    def verify(self, token: str) -> dict:
        """Return the validated claims, or raise AuthError."""
        try:
            signing_key = self._jwk_client.get_signing_key_from_jwt(token)
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=self.issuer,
                # Audience is checked manually below (Cognito access tokens use
                # `client_id`, not `aud`); still require the standard claims.
                options={"verify_aud": False, "require": ["exp", "iss"]},
            )
        except Exception as exc:  # jwt validation + JWKS fetch errors
            raise AuthError(f"invalid token: {exc}") from exc
        if not self._audience_ok(claims):
            raise AuthError("token audience mismatch")
        # Reject ID tokens (and anything not an access token) for API access.
        # `token_use` is Cognito-specific; absent for generic OIDC access tokens,
        # so only enforce when present — keeps the verifier IdP-agnostic.
        token_use = claims.get("token_use")
        if token_use is not None and token_use != "access":
            raise AuthError(f"expected an access token, got token_use={token_use!r}")
        return claims

    def _audience_ok(self, claims: dict) -> bool:
        if not self.audience:
            return True
        aud = claims.get("aud")
        if isinstance(aud, str) and aud == self.audience:
            return True
        if isinstance(aud, (list, tuple)) and self.audience in aud:
            return True
        # AWS Cognito access tokens: audience is carried in `client_id`.
        return claims.get("client_id") == self.audience


@lru_cache
def get_verifier() -> OIDCVerifier | None:
    """The configured verifier, or None when auth is disabled.

    Cached; tests that toggle settings must call `get_verifier.cache_clear()`.
    """
    s = get_settings()
    if not s.auth_enabled:
        return None
    if not s.oidc_issuer:
        raise RuntimeError("auth_enabled is true but oidc_issuer is unset")
    return OIDCVerifier(s.oidc_issuer, s.oidc_audience, s.oidc_jwks_url)


async def authorize_websocket(websocket) -> dict | None:
    """Authorize a WebSocket connection (the http middleware can't see WS).

    Returns the validated claims (an empty dict when auth is disabled), or None
    after closing the socket if unauthorized — callers must `return` on None and
    do no work. Browsers can't set headers on the WS handshake, so the token is
    taken from the ``access_token`` query param (or an Authorization header for
    non-browser clients). Call this immediately after ``websocket.accept()``.
    """
    verifier = get_verifier()
    if verifier is None:  # auth disabled — allow (local default)
        return {}
    token = websocket.query_params.get("access_token")
    if not token:
        header = websocket.headers.get("authorization", "")
        if header.lower().startswith("bearer "):
            token = header.split(" ", 1)[1].strip()
    if not token:
        await websocket.close(code=4401)  # 4401 = application "Unauthorized"
        return None
    try:
        return await run_in_threadpool(verifier.verify, token)
    except AuthError:
        await websocket.close(code=4401)
        return None


async def auth_guard(request: Request, call_next):
    """FastAPI HTTP middleware enforcing a valid bearer token when auth is on."""
    verifier = get_verifier()
    if verifier is None:  # auth disabled — pass through (local default)
        return await call_next(request)
    if request.method == "OPTIONS" or request.url.path in AUTH_ALLOWLIST:
        return await call_next(request)
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return JSONResponse(status_code=401, content={"detail": "missing bearer token"})
    token = header.split(" ", 1)[1].strip()
    try:
        # JWKS lookup may do (cached) network I/O — keep it off the event loop.
        claims = await run_in_threadpool(verifier.verify, token)
    except AuthError as exc:
        return JSONResponse(status_code=401, content={"detail": str(exc)})
    request.state.user = claims
    return await call_next(request)
