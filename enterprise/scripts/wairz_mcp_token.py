#!/usr/bin/env python3
"""Wairz remote-MCP token helper — keep Claude authenticated to /mcp.

A Cognito access token lives ~1h, so a static `Authorization` header in
`.mcp.json` goes stale. Claude Code's `headersHelper` runs a command *fresh on
every connection* and uses the JSON headers it prints — this script is that
command. It logs you in once (browser), caches the refresh token (~30d), and
silently mints a fresh access token on each connect.

Subcommands
-----------
  login     One-time interactive login: Authorization Code + PKCE via the
            Cognito hosted UI (works with a federated SSO IdP too). Caches the
            refresh + access tokens under ~/.config/wairz/.
  headers   Print `{"Authorization": "Bearer <access_token>"}` to stdout —
            this is what you point `headersHelper` at. Non-interactive:
            cache-hit, else refresh-token grant. Exits non-zero (telling you to
            run `login`) if it can't — never opens a browser.
  token     Print just the raw access token (for env vars / manual use).
  logout    Delete the cached tokens.

Configuration (CLI flag > env var > config file ~/.config/wairz/mcp.json):
  --domain   / WAIRZ_MCP_COGNITO_DOMAIN   Cognito hosted-UI domain. Either the
             prefix (e.g. "wairz-prod-auth") or a full https URL. From the
             `cognito_hosted_ui_domain` Terraform output.
  --region   / WAIRZ_MCP_REGION           AWS region (e.g. us-east-1).
  --client-id/ WAIRZ_MCP_CLIENT_ID        Cognito app client id
             (`cognito_app_client_id` output).
  --port     / WAIRZ_MCP_REDIRECT_PORT    Loopback port (default 51789); must
             match the Terraform `mcp_cli_redirect_port` registered on the pool.
  --scopes   / WAIRZ_MCP_SCOPES           default "openid email profile".

Zero third-party dependencies — Python 3.9+ standard library only.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.server
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

DEFAULT_PORT = 51789
DEFAULT_SCOPES = "openid email profile"
# Refresh a little before actual expiry so a token handed to Claude stays valid
# for the whole (short) connection.
EXPIRY_SKEW_SECONDS = 90

CONFIG_DIR = os.path.join(
    os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "wairz"
)
CACHE_PATH = os.path.join(CONFIG_DIR, "token.json")
CONFIG_PATH = os.path.join(CONFIG_DIR, "mcp.json")


class HelperError(Exception):
    """User-facing error; printed to stderr, exits non-zero."""


# --- config -----------------------------------------------------------------


def _file_config() -> dict:
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def resolve_config(args) -> dict:
    fc = _file_config()

    def pick(flag, env, key, default=None, required=False):
        val = (
            getattr(args, flag, None)
            or os.environ.get(env)
            or fc.get(key)
            or default
        )
        if required and not val:
            raise HelperError(
                f"missing {key}: pass --{flag.replace('_', '-')}, set {env}, "
                f"or add it to {CONFIG_PATH}"
            )
        return val

    domain = pick("domain", "WAIRZ_MCP_COGNITO_DOMAIN", "domain", required=True)
    region = pick("region", "WAIRZ_MCP_REGION", "region", required=True)
    client_id = pick("client_id", "WAIRZ_MCP_CLIENT_ID", "client_id", required=True)
    port = int(pick("port", "WAIRZ_MCP_REDIRECT_PORT", "redirect_port", DEFAULT_PORT))
    scopes = pick("scopes", "WAIRZ_MCP_SCOPES", "scopes", DEFAULT_SCOPES)

    if domain.startswith("http://") or domain.startswith("https://"):
        base = domain.rstrip("/")
    else:
        base = f"https://{domain}.auth.{region}.amazoncognito.com"

    return {
        "base": base,
        "client_id": client_id,
        "port": int(port),
        "scopes": scopes,
        "redirect_uri": f"http://localhost:{int(port)}/callback",
    }


# --- token cache ------------------------------------------------------------


def _load_cache() -> dict:
    try:
        with open(CACHE_PATH) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_cache(data: dict) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    # Write 0600 — the refresh token is a long-lived credential.
    fd = os.open(CACHE_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(data, f)


# --- PKCE -------------------------------------------------------------------


def _pkce_pair() -> tuple[str, str]:
    """Return (verifier, challenge) for PKCE S256."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return verifier, challenge


# --- HTTP -------------------------------------------------------------------


def _post_token(base: str, fields: dict) -> dict:
    url = f"{base}/oauth2/token"
    body = urllib.parse.urlencode(fields).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise HelperError(f"token endpoint {e.code}: {detail}") from e
    except urllib.error.URLError as e:
        raise HelperError(f"cannot reach token endpoint: {e.reason}") from e


def _store_token_response(cfg: dict, resp: dict, *, prev_refresh: str | None = None) -> dict:
    access = resp.get("access_token")
    if not access:
        raise HelperError(f"no access_token in response: {resp}")
    cache = {
        "access_token": access,
        "expires_at": int(time.time()) + int(resp.get("expires_in", 3600)),
        # Refresh-token grants don't return a new refresh token; keep the old.
        "refresh_token": resp.get("refresh_token") or prev_refresh,
        "client_id": cfg["client_id"],
        "base": cfg["base"],
    }
    _save_cache(cache)
    return cache


# --- login (interactive) ----------------------------------------------------


class _CallbackHandler(http.server.BaseHTTPRequestHandler):
    captured: dict = {}

    def do_GET(self):  # noqa: N802 (stdlib naming)
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            return
        params = urllib.parse.parse_qs(parsed.query)
        type(self).captured = {k: v[0] for k, v in params.items()}
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        ok = "code" in type(self).captured
        msg = (
            "Wairz MCP login complete — you can close this tab and return to "
            "your terminal." if ok else
            "Wairz MCP login failed: " + type(self).captured.get("error", "unknown")
        )
        self.wfile.write(f"<html><body><h3>{msg}</h3></body></html>".encode())

    def log_message(self, *a):  # silence the default stderr logging
        pass


def cmd_login(cfg: dict) -> None:
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    authorize = f"{cfg['base']}/oauth2/authorize?" + urllib.parse.urlencode({
        "response_type": "code",
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "scope": cfg["scopes"],
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    })

    try:
        server = http.server.HTTPServer(("127.0.0.1", cfg["port"]), _CallbackHandler)
    except OSError as e:
        raise HelperError(
            f"cannot bind loopback port {cfg['port']} ({e}); set "
            f"--port/WAIRZ_MCP_REDIRECT_PORT (and the Terraform "
            f"mcp_cli_redirect_port) to a free port"
        ) from e

    print(f"Opening browser to log in:\n  {authorize}\n", file=sys.stderr)
    try:
        webbrowser.open(authorize)
    except Exception:
        print("(could not open a browser automatically — open the URL above)",
              file=sys.stderr)

    server.timeout = 300
    _CallbackHandler.captured = {}
    server.handle_request()  # blocks until the redirect (or timeout)
    server.server_close()
    captured = _CallbackHandler.captured

    if not captured:
        raise HelperError("timed out waiting for the login redirect")
    if captured.get("state") != state:
        raise HelperError("state mismatch on redirect (possible CSRF) — aborted")
    if "code" not in captured:
        raise HelperError(f"login failed: {captured.get('error_description') or captured}")

    resp = _post_token(cfg["base"], {
        "grant_type": "authorization_code",
        "client_id": cfg["client_id"],
        "code": captured["code"],
        "redirect_uri": cfg["redirect_uri"],
        "code_verifier": verifier,
    })
    cache = _store_token_response(cfg, resp)
    if not cache.get("refresh_token"):
        print("warning: no refresh_token returned; you'll need to re-run login "
              "each hour. Enable a refresh-capable flow on the app client.",
              file=sys.stderr)
    print("Logged in. Token cached at " + CACHE_PATH, file=sys.stderr)


# --- token resolution (non-interactive) -------------------------------------


def ensure_access_token(cfg: dict) -> str:
    cache = _load_cache()
    # Invalidate the cache if it was minted for a different client/pool.
    if cache.get("client_id") and cache["client_id"] != cfg["client_id"]:
        cache = {}
    now = int(time.time())
    if cache.get("access_token") and cache.get("expires_at", 0) - now > EXPIRY_SKEW_SECONDS:
        return cache["access_token"]
    refresh = cache.get("refresh_token")
    if not refresh:
        raise HelperError("no usable token — run: wairz_mcp_token.py login")
    resp = _post_token(cfg["base"], {
        "grant_type": "refresh_token",
        "client_id": cfg["client_id"],
        "refresh_token": refresh,
    })
    return _store_token_response(cfg, resp, prev_refresh=refresh)["access_token"]


def cmd_headers(cfg: dict) -> None:
    token = ensure_access_token(cfg)
    # headersHelper contract: a JSON object of header name -> value on stdout.
    sys.stdout.write(json.dumps({"Authorization": f"Bearer {token}"}))


def cmd_token(cfg: dict) -> None:
    sys.stdout.write(ensure_access_token(cfg))


def cmd_logout(_cfg: dict) -> None:
    try:
        os.remove(CACHE_PATH)
        print("Cleared " + CACHE_PATH, file=sys.stderr)
    except FileNotFoundError:
        print("Nothing cached.", file=sys.stderr)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Wairz remote-MCP token helper.")
    p.add_argument("command", choices=["login", "headers", "token", "logout"])
    p.add_argument("--domain")
    p.add_argument("--region")
    p.add_argument("--client-id", dest="client_id")
    p.add_argument("--port", type=int)
    p.add_argument("--scopes")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "logout":
            cmd_logout({})
            return 0
        cfg = resolve_config(args)
        {"login": cmd_login, "headers": cmd_headers, "token": cmd_token}[args.command](cfg)
        return 0
    except HelperError as e:
        print(f"wairz_mcp_token: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
