"""Rule #46 META-CANARY: the lifespan auth-required gate at
app/main.py:65-76 MUST stay removed (operator direction 2026-05-21,
backlog `auth-gate-removal-2026-05-21`).

If this test fails, the gate has been silently re-introduced. The
asgi_auth.py middleware already no-ops cleanly on falsy api_key, so
the lifespan gate was strictly redundant. Re-introducing it forces
operators to either set API_KEY or set WAIRZ_ALLOW_NO_AUTH=true
manually — friction without security gain for wairz's single-operator
firmware-RE deployment shape.

Cross-refs:
- CLAUDE.md Rule #46 (paired META-CANARY discipline)
- ADAPTIVE_BACKLOG `auth-gate-removal-2026-05-21`
- Session 2b Phase A2 commit (this file ships in that commit)
- backend/app/middleware/asgi_auth.py docstring line 16:
  "Auth is disabled entirely when settings.api_key is falsy"
"""
from __future__ import annotations

import re
from pathlib import Path


def _main_py_source() -> str:
    return Path(__file__).parent.parent.joinpath("app/main.py").read_text()


def _config_py_source() -> str:
    return Path(__file__).parent.parent.joinpath("app/config.py").read_text()


def test_no_lifespan_auth_required_gate():
    """The pre-2026-05-21 gate shape MUST NOT exist in main.py:
    `if not settings.api_key and not settings.allow_no_auth: sys.exit(78)`.
    """
    src = _main_py_source()
    # Match the load-bearing condition shape regardless of whitespace.
    bad_pattern = re.compile(
        r"if\s+not\s+settings\.api_key\s+and\s+not\s+settings\.allow_no_auth\s*:",
        re.MULTILINE,
    )
    assert not bad_pattern.search(src), (
        "Lifespan auth-required gate `if not settings.api_key and not "
        "settings.allow_no_auth:` re-introduced in app/main.py — "
        "auth-gate-removal-2026-05-21 regression. The asgi_auth.py "
        "middleware already no-ops on falsy api_key; the lifespan gate "
        "was redundant. If you need multi-user enforcement, the path is "
        "(a) set API_KEY in .env (middleware enforces) NOT (b) re-add "
        "the lifespan gate."
    )
    # Also assert sys.exit(78) — the EX_CONFIG exit code unique to this
    # gate — is absent. (Other lifespan branches don't use 78.)
    assert "sys.exit(78)" not in src, (
        "sys.exit(78) (EX_CONFIG, the auth-gate's unique exit code) "
        "found in main.py — likely a regressed auth gate."
    )


def test_settings_allow_no_auth_default_is_true():
    """The default for `Settings.allow_no_auth` MUST be True.

    Pre-2026-05-21 the default was False, which forced the lifespan gate
    (now removed) to refuse-to-start unless the operator explicitly set
    WAIRZ_ALLOW_NO_AUTH=true. Flipping the default to True closes the
    same workflow without an env-var dance.
    """
    src = _config_py_source()
    # Match `allow_no_auth: bool = Field(...default=True...)` allowing
    # whitespace and any kwarg ordering.
    pattern = re.compile(
        r"allow_no_auth\s*:\s*bool\s*=\s*Field\s*\(\s*[^)]*\bdefault\s*=\s*True\b",
        re.MULTILINE | re.DOTALL,
    )
    assert pattern.search(src), (
        "Settings.allow_no_auth default is NOT True. Per "
        "auth-gate-removal-2026-05-21 the default was flipped from "
        "False → True so operators don't need to set WAIRZ_ALLOW_NO_AUTH=true "
        "manually for the single-operator deployment shape."
    )


def test_meta_canary_would_fire_on_re_introduced_gate(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46
    §gate-canary-requirement: synthesize a fake main.py with the gate
    re-introduced; confirm the assertion above WOULD reject it.
    """
    bad_src = """
async def lifespan(app):
    settings = get_settings()
    if not settings.api_key and not settings.allow_no_auth:
        print("ERROR")
        sys.exit(78)
    yield
"""
    bad_pattern = re.compile(
        r"if\s+not\s+settings\.api_key\s+and\s+not\s+settings\.allow_no_auth\s*:",
        re.MULTILINE,
    )
    assert bad_pattern.search(bad_src), (
        "META-CANARY broken: synthesize-and-assert canary did NOT "
        "detect the re-introduced gate in the synthetic fake. "
        "Re-author the regex."
    )
    assert "sys.exit(78)" in bad_src
