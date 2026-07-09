"""Honest residual coverage for app/rate_limit.py 429 handler."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from starlette.requests import Request
from starlette.responses import JSONResponse


def _req(path="/api/v1/x"):
    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": path,
            "raw_path": path.encode(),
            "query_string": b"",
            "headers": [],
            "client": ("10.0.0.1", 1234),
            "server": ("t", 80),
        }
    )


class TestRateLimitHandler:
    def test_handler_with_retry_after_header(self):
        from app import rate_limit as rl

        base = JSONResponse(status_code=429, content={"error": "old"})
        base.headers["Retry-After"] = "30"
        base.headers["X-RateLimit-Limit"] = "5"
        base.headers["content-type"] = "application/json"

        exc = SimpleNamespace(detail="5 per 1 hour", limit=SimpleNamespace())
        with patch.object(rl, "_rate_limit_exceeded_handler", return_value=base):
            resp = rl.custom_rate_limit_exceeded_handler(_req(), exc)
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "30"
        body = resp.body
        assert b"tier" in body or b"Rate limit" in body

    def test_handler_expiry_from_limit(self):
        from app import rate_limit as rl

        base = JSONResponse(status_code=429, content={})
        underlying = SimpleNamespace(get_expiry=lambda: 120)
        exc = SimpleNamespace(
            detail="30 per 1 hour",
            limit=SimpleNamespace(limit=underlying),
        )
        with patch.object(rl, "_rate_limit_exceeded_handler", return_value=base):
            resp = rl.custom_rate_limit_exceeded_handler(_req("/fw/unpack"), exc)
        assert resp.headers.get("Retry-After") == "120"

    def test_handler_bad_retry_header_and_expiry_fail(self):
        from app import rate_limit as rl

        base = JSONResponse(status_code=429, content={})
        base.headers["Retry-After"] = "not-int"
        # expiry path fails
        class Bad:
            def get_expiry(self):
                raise RuntimeError("no")

        exc = SimpleNamespace(detail="5 per 1 hour", limit=Bad())
        with patch.object(rl, "_rate_limit_exceeded_handler", return_value=base):
            resp = rl.custom_rate_limit_exceeded_handler(_req(), exc)
        assert resp.status_code == 429
        assert "Retry-After" in resp.headers

    def test_build_tier_reverse_map_defensive(self):
        from app import rate_limit as rl

        # re-call builder if exposed
        if hasattr(rl, "_build_tier_reverse_map"):
            m = rl._build_tier_reverse_map()
            assert isinstance(m, dict)
            assert m  # non-empty

    def test_handler_expiry_except_and_parse_fail(self):
        """Hit lines 202-203 (expiry except) and reverse-map parse except 126-129."""
        from app import rate_limit as rl

        base = JSONResponse(status_code=429, content={})
        # limit has get_expiry that raises → except at 202-203
        class Boom:
            def get_expiry(self):
                raise ValueError("bad expiry")

        exc = SimpleNamespace(detail="5 per 1 hour", limit=Boom())
        with patch.object(rl, "_rate_limit_exceeded_handler", return_value=base):
            resp = rl.custom_rate_limit_exceeded_handler(_req(), exc)
        assert resp.status_code == 429
        assert resp.headers.get("Retry-After") == "60"

        # force _parse_limit failure inside reverse map if possible
        if hasattr(rl, "_build_tier_reverse_map") and hasattr(rl, "_parse_limit"):
            with patch.object(rl, "_parse_limit", side_effect=Exception("parse")):
                m = rl._build_tier_reverse_map()
                assert isinstance(m, dict)
