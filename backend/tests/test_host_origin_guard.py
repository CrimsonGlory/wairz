"""Tests for origin_host_guard middleware and the ALLOWED_HOSTS / _cors_origins
allowlists it enforces.

EXTRA_ALLOWED_HOSTS is read directly from the project-root .env at collection
time so the parametrised test cases always reflect whatever the operator has
configured — no hardcoding required.

Coverage:
  - ALLOWED_HOSTS and _cors_origins contents (unit, no HTTP)
  - Blocked host → 403 "host not allowed"
  - localhost / 127.0.0.1 always pass
  - Every host in EXTRA_ALLOWED_HOSTS passes the host check
  - Blocked origin → 403 "origin not allowed"
  - http:// and https:// origins derived from EXTRA_ALLOWED_HOSTS pass
  - Bare hostname entry covers http://<host>:<any-port> via the
    bare-hostname fallback in origin_host_guard
"""
from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator
from unittest.mock import MagicMock

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import ALLOWED_HOSTS, _cors_origins, app

# ---------------------------------------------------------------------------
# Read EXTRA_ALLOWED_HOSTS at collection time.
#
# Priority order:
#   1. Process environment variable (set by Docker Compose or the shell)
#   2. Parse the repo-root .env file directly (local `pytest` invocations
#      where the env var hasn't been exported)
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


def _read_env(key: str) -> str:
    # Fast path: already in the process environment (Docker Compose, CI, etc.)
    if key in os.environ:
        return os.environ[key]
    # Slow path: parse the .env file for bare `pytest` invocations on the host
    env_file = _PROJECT_ROOT / ".env"
    if not env_file.exists():
        return ""
    for line in env_file.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        if k.strip() == key:
            return v.strip()
    return ""


EXTRA_HOSTS: list[str] = [h for h in _read_env("EXTRA_ALLOWED_HOSTS").split(",") if h.strip()]
_BARE_HOSTS: list[str] = [h for h in EXTRA_HOSTS if ":" not in h]

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _disable_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass APIKeyASGIMiddleware so auth never interferes with host/origin tests."""
    from app.middleware import asgi_auth as _m

    fake = MagicMock()
    fake.api_key = ""
    monkeypatch.setattr(_m, "get_settings", lambda: fake)


@asynccontextmanager
async def _client(host: str) -> AsyncIterator[AsyncClient]:
    """Return an AsyncClient whose Host header matches *host*.

    Using base_url=f"http://{host}" causes httpx to derive the Host header
    from the URL, which ASGI transports forward verbatim — no network
    resolution required.
    """
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url=f"http://{host}",
    ) as c:
        yield c


# ---------------------------------------------------------------------------
# ALLOWED_HOSTS contents (unit — no HTTP)
# ---------------------------------------------------------------------------


def test_localhost_in_allowed_hosts() -> None:
    assert "localhost" in ALLOWED_HOSTS


def test_127_in_allowed_hosts() -> None:
    assert "127.0.0.1" in ALLOWED_HOSTS


@pytest.mark.parametrize("host", EXTRA_HOSTS or ["__skip__"])
def test_extra_host_in_allowed_hosts(host: str) -> None:
    if host == "__skip__":
        pytest.skip("EXTRA_ALLOWED_HOSTS not set in .env")
    assert host in ALLOWED_HOSTS, f"{host!r} is missing from ALLOWED_HOSTS"


# ---------------------------------------------------------------------------
# _cors_origins contents (unit — no HTTP)
# ---------------------------------------------------------------------------


def test_cors_origins_include_localhost_3000() -> None:
    assert "http://localhost:3000" in _cors_origins


@pytest.mark.parametrize("host", EXTRA_HOSTS or ["__skip__"])
@pytest.mark.parametrize("scheme", ["http", "https"])
def test_cors_origins_include_extra_host(host: str, scheme: str) -> None:
    if host == "__skip__":
        pytest.skip("EXTRA_ALLOWED_HOSTS not set in .env")
    origin = f"{scheme}://{host}"
    assert origin in _cors_origins, f"{origin!r} is missing from _cors_origins"


# ---------------------------------------------------------------------------
# HTTP middleware — host check
# ---------------------------------------------------------------------------


async def test_blocked_host_returns_403() -> None:
    async with _client("completely-unknown.example.com") as c:
        r = await c.get("/health")
    assert r.status_code == 403
    assert r.json() == {"detail": "host not allowed"}


async def test_localhost_host_not_blocked() -> None:
    async with _client("localhost") as c:
        r = await c.get("/health")
    assert r.json().get("detail") != "host not allowed"


async def test_127_host_not_blocked() -> None:
    async with _client("127.0.0.1") as c:
        r = await c.get("/health")
    assert r.json().get("detail") != "host not allowed"


@pytest.mark.parametrize("host", EXTRA_HOSTS or ["__skip__"])
async def test_extra_host_not_blocked_by_host_guard(host: str) -> None:
    if host == "__skip__":
        pytest.skip("EXTRA_ALLOWED_HOSTS not set in .env")
    async with _client(host) as c:
        r = await c.get("/health")
    assert r.json().get("detail") != "host not allowed", (
        f"Host {host!r} was rejected by origin_host_guard"
    )


# ---------------------------------------------------------------------------
# HTTP middleware — origin check
# ---------------------------------------------------------------------------


async def test_blocked_origin_returns_403() -> None:
    async with _client("localhost") as c:
        r = await c.get("/health", headers={"Origin": "http://attacker.example.com"})
    assert r.status_code == 403
    assert r.json() == {"detail": "origin not allowed"}


@pytest.mark.parametrize("host", EXTRA_HOSTS or ["__skip__"])
@pytest.mark.parametrize("scheme", ["http", "https"])
async def test_extra_host_origin_not_blocked(host: str, scheme: str) -> None:
    if host == "__skip__":
        pytest.skip("EXTRA_ALLOWED_HOSTS not set in .env")
    origin = f"{scheme}://{host}"
    async with _client("localhost") as c:
        r = await c.get("/health", headers={"Origin": origin})
    assert r.json().get("detail") != "origin not allowed", (
        f"Origin {origin!r} was rejected by origin_host_guard"
    )


@pytest.mark.parametrize("host", _BARE_HOSTS or ["__skip__"])
@pytest.mark.parametrize("port", [1234, 8080, 9999])
async def test_bare_hostname_covers_any_port(host: str, port: int) -> None:
    """A bare hostname (no port) in EXTRA_ALLOWED_HOSTS must cover origins on
    any port via the bare-hostname fallback in origin_host_guard."""
    if host == "__skip__":
        pytest.skip("No bare (port-less) hosts in EXTRA_ALLOWED_HOSTS")
    origin = f"http://{host}:{port}"
    async with _client("localhost") as c:
        r = await c.get("/health", headers={"Origin": origin})
    assert r.json().get("detail") != "origin not allowed", (
        f"Origin {origin!r} was blocked; bare host {host!r} is in ALLOWED_HOSTS"
    )
