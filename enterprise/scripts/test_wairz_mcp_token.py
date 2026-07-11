"""Tests for the remote-MCP token helper (wairz_mcp_token.py).

Run: python3 -m pytest enterprise/scripts/test_wairz_mcp_token.py
Stdlib + pytest only; no AWS, no network (a local stub stands in for Cognito).
"""

import base64
import hashlib
import http.server
import importlib.util
import io
import json
import os
import threading
import time
from contextlib import redirect_stdout

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "wairz_mcp_token", os.path.join(_HERE, "wairz_mcp_token.py")
)
tok = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tok)


@pytest.fixture
def cache_in_tmp(tmp_path, monkeypatch):
    monkeypatch.setattr(tok, "CONFIG_DIR", str(tmp_path))
    monkeypatch.setattr(tok, "CACHE_PATH", str(tmp_path / "token.json"))
    monkeypatch.setattr(tok, "CONFIG_PATH", str(tmp_path / "mcp.json"))
    return tmp_path


def _cfg(base="https://example.auth.us-east-1.amazoncognito.com", client="cid"):
    return {"base": base, "client_id": client, "port": 51789,
            "scopes": "openid email profile",
            "redirect_uri": "http://localhost:51789/callback"}


# --- PKCE -------------------------------------------------------------------


def test_pkce_pair_is_valid_s256():
    verifier, challenge = tok._pkce_pair()
    expected = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    assert challenge == expected
    assert "=" not in verifier and "=" not in challenge
    assert 43 <= len(verifier) <= 128  # RFC 7636 length bounds


def test_pkce_pairs_are_random():
    assert tok._pkce_pair()[0] != tok._pkce_pair()[0]


# --- config resolution ------------------------------------------------------


class _Args:
    domain = region = client_id = port = scopes = None


def test_resolve_config_prefix_domain(cache_in_tmp, monkeypatch):
    monkeypatch.setenv("WAIRZ_MCP_COGNITO_DOMAIN", "wairz-prod-auth")
    monkeypatch.setenv("WAIRZ_MCP_REGION", "us-east-1")
    monkeypatch.setenv("WAIRZ_MCP_CLIENT_ID", "abc123")
    cfg = tok.resolve_config(_Args())
    assert cfg["base"] == "https://wairz-prod-auth.auth.us-east-1.amazoncognito.com"
    assert cfg["client_id"] == "abc123"
    assert cfg["redirect_uri"] == "http://localhost:51789/callback"


def test_resolve_config_full_url_domain(cache_in_tmp, monkeypatch):
    monkeypatch.setenv("WAIRZ_MCP_COGNITO_DOMAIN", "https://auth.example.com/")
    monkeypatch.setenv("WAIRZ_MCP_REGION", "us-east-1")
    monkeypatch.setenv("WAIRZ_MCP_CLIENT_ID", "abc123")
    monkeypatch.setenv("WAIRZ_MCP_REDIRECT_PORT", "40000")
    cfg = tok.resolve_config(_Args())
    assert cfg["base"] == "https://auth.example.com"
    assert cfg["redirect_uri"] == "http://localhost:40000/callback"


def test_resolve_config_missing_required(cache_in_tmp, monkeypatch):
    for v in ("WAIRZ_MCP_COGNITO_DOMAIN", "WAIRZ_MCP_REGION", "WAIRZ_MCP_CLIENT_ID"):
        monkeypatch.delenv(v, raising=False)
    with pytest.raises(tok.HelperError):
        tok.resolve_config(_Args())


# --- token resolution -------------------------------------------------------


def test_cache_hit_returns_without_network(cache_in_tmp, monkeypatch):
    tok._save_cache({
        "access_token": "FRESH", "expires_at": int(time.time()) + 3600,
        "refresh_token": "r", "client_id": "cid",
    })

    def _boom(*a, **k):
        raise AssertionError("should not hit the network on a cache hit")

    monkeypatch.setattr(tok, "_post_token", _boom)
    assert tok.ensure_access_token(_cfg()) == "FRESH"


def test_refresh_when_expired(cache_in_tmp, monkeypatch):
    tok._save_cache({
        "access_token": "OLD", "expires_at": int(time.time()) - 10,
        "refresh_token": "REFRESH", "client_id": "cid",
    })
    calls = {}

    def _fake_post(base, fields):
        calls.update(fields)
        return {"access_token": "NEW", "expires_in": 3600}

    monkeypatch.setattr(tok, "_post_token", _fake_post)
    assert tok.ensure_access_token(_cfg()) == "NEW"
    assert calls["grant_type"] == "refresh_token"
    assert calls["refresh_token"] == "REFRESH"
    # refresh grants return no new refresh token → the old one is preserved.
    assert tok._load_cache()["refresh_token"] == "REFRESH"
    assert tok._load_cache()["access_token"] == "NEW"


def test_no_token_raises(cache_in_tmp):
    with pytest.raises(tok.HelperError, match="login"):
        tok.ensure_access_token(_cfg())


def test_cache_invalidated_on_client_mismatch(cache_in_tmp):
    tok._save_cache({
        "access_token": "FRESH", "expires_at": int(time.time()) + 3600,
        "refresh_token": None, "client_id": "OTHER-CLIENT",
    })
    # Different client → cache ignored → no refresh token → error.
    with pytest.raises(tok.HelperError):
        tok.ensure_access_token(_cfg(client="cid"))


def test_headers_output_is_valid_helper_json(cache_in_tmp):
    tok._save_cache({
        "access_token": "TOKVAL", "expires_at": int(time.time()) + 3600,
        "refresh_token": "r", "client_id": "cid",
    })
    buf = io.StringIO()
    with redirect_stdout(buf):
        tok.cmd_headers(_cfg())
    obj = json.loads(buf.getvalue())
    assert obj == {"Authorization": "Bearer TOKVAL"}


# --- end-to-end refresh against a local stub token endpoint -----------------


class _StubHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802
        assert self.path == "/oauth2/token"
        body = json.dumps({"access_token": "E2E-NEW", "expires_in": 3600}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def test_refresh_against_stub_server(cache_in_tmp):
    server = http.server.HTTPServer(("127.0.0.1", 0), _StubHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        tok._save_cache({
            "access_token": "OLD", "expires_at": int(time.time()) - 1,
            "refresh_token": "RT", "client_id": "cid",
        })
        cfg = _cfg(base=f"http://127.0.0.1:{port}")
        assert tok.ensure_access_token(cfg) == "E2E-NEW"
        assert tok._load_cache()["access_token"] == "E2E-NEW"
        assert tok._load_cache()["refresh_token"] == "RT"
    finally:
        server.shutdown()


def test_cache_file_is_0600(cache_in_tmp):
    tok._save_cache({"access_token": "x", "expires_at": 0, "client_id": "cid"})
    mode = os.stat(tok.CACHE_PATH).st_mode & 0o777
    assert mode == 0o600
