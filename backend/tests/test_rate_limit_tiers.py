"""Audit-2026-05-04 stream B F-B-07: rate-limit tier coverage assertions.

Three flavours of assertion:

1. **Static** — read each router source for `@limiter.limit(<TIER>)` on
   the documented expensive POSTs.  Catches drift if a future commit
   removes the decorator.

2. **Dynamic** — instantiate FastAPI TestClient against the live router
   surface and replay an endpoint past its tier limit; assert the
   `429 Too Many Requests` response carries `Retry-After` AND the
   structured body shape from
   ``app.rate_limit.custom_rate_limit_exceeded_handler``.  Companion
   to CLAUDE.md Rule #35b (live canary): a static check verifies the
   decorator is present, but only a runtime call verifies the limit
   is actually applied (Rule #30: decorator could be no-op'd by a wrong
   patch site, etc.).

3. **META-CANARY** (Rule #46) — synthesize a temp router file with a
   WRONG tier decorator and assert ``test_expensive_posts_are_rate_limited``
   would fail.  Without this, the static test could silently pass even
   if its assertion logic broke (e.g. a future refactor of the regex
   could match anything).  The canary proves the gate fires.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

_REPO_BACKEND = Path(__file__).parent.parent

# Map each (router file, endpoint regex marker) → expected tier constant.
#
# Tier assignment per rate_limit.py module docstring:
# - TIER_A_HEAVY (5/hour): sync OR ≥5-min event-loop-pinning runs.
#   Reference cases:
#     * security_audit /audit — fully synchronous, 2-10 min, blocks HTTP.
#     * hardware_firmware /cve-match — 202+polling but pins event loop
#       for ~7 min on Yocto-scale bulk inserts.
#     * comparison /decompilation — 2× cold-cache Ghidra calls = ~10 min.
#     * apk_scan + attack_surface — CPU-bound sync, executor-bound,
#       multi-minute on large APKs.
# - TIER_A_LIGHT_ACK (30/hour): event-loop-FREE work bounded ≤2 min.
#   Covers both 202+polling (ack sub-second + detached task) AND
#   sync-executor (event loop free while executor runs) shapes. The
#   server-saturation profile is the same: 30/hour × ~30s typical =
#   ~15 min/hour CPU budget on a single-uvicorn-process backend.
#   Reference cases:
#     * sbom /generate + /vulnerabilities/scan — 202+polling, 30-120 s.
#     * hardware_firmware /authenticode-chain — 202+polling, 1-3 min.
#     * firmware /{id}/unpack — 202+polling, arq-dispatched (was
#       mis-tiered TIER_A_HEAVY pre-2026-05-22; Rule #51 corrects).
#     * device /dumps — 202+polling, in-process detached runner (same
#       mis-tier corrected 2026-05-22).
#     * comparison /firmware + /binary — sync but `run_in_executor`,
#       typically ≤2 min on representative firmware.
#     * bare_metal /bare-metal-hint — sub-second ack + detached walker.
# - TIER_B_DOCKER (20/hour): Docker-spawn jobs (emulation, fuzzing).
# - TIER_C_DEFAULT (100/minute): implicit default, suitable for sub-second
#   sync endpoints. Reference cases:
#     * comparison /text + /instructions — pure-Python / Capstone diff,
#       milliseconds-to-seconds (was mis-tiered TIER_A_HEAVY pre-
#       2026-05-22; Rule #51 corrects).
_EXPECTED_TIERS: dict[tuple[str, str], str] = {
    ("app/routers/security_audit.py", r'@router\.post\("/audit"'): "TIER_A_HEAVY",
    ("app/routers/hardware_firmware.py", r'@router\.post\("/cve-match"'): "TIER_A_HEAVY",
    ("app/routers/firmware.py", r'@router\.post\("/\{firmware_id\}/unpack"'): "TIER_A_LIGHT_ACK",
    ("app/routers/device.py", r'@router\.post\("/dumps"'): "TIER_A_LIGHT_ACK",
    ("app/routers/sbom.py", r'@router\.post\(\s*\n?\s*"/generate"'): "TIER_A_LIGHT_ACK",
    ("app/routers/sbom.py", r'@router\.post\(\s*\n?\s*"/vulnerabilities/scan"'): "TIER_A_LIGHT_ACK",
    ("app/routers/hardware_firmware.py", r'@router\.post\(\s*\n?\s*"/authenticode-chain"'): "TIER_A_LIGHT_ACK",
    ("app/routers/fuzzing.py", r'@router\.post\(\s*\n?\s*"/campaigns/\{campaign_id\}/start"'): "TIER_B_DOCKER",
    ("app/routers/emulation.py", r'@router\.post\("/start"'): "TIER_B_DOCKER",
    ("app/routers/emulation.py", r'@router\.post\(\s*\n?\s*"/system"'): "TIER_B_DOCKER",
    # Rule #52 Phase 2 — bare-metal-hint external-ingestor endpoint (2026-05-19).
    # Sub-second ACK + detached walker fire = TIER_A_LIGHT_ACK per Rule #51.
    ("app/routers/bare_metal.py", r'@router\.post\(\s*\n?\s*"/bare-metal-hint"'): "TIER_A_LIGHT_ACK",
    # ratelimit scout1 (2026-05-19) — CPU-bound sync static-analysis +
    # diff endpoints. Synchronous heavy work = TIER_A_HEAVY (5/hour).
    ("app/routers/apk_scan.py", r'@router\.post\("/manifest"'): "TIER_A_HEAVY",
    ("app/routers/apk_scan.py", r'@router\.post\("/bytecode"'): "TIER_A_HEAVY",
    ("app/routers/apk_scan.py", r'@router\.post\("/sast"'): "TIER_A_HEAVY",
    # over-constraint sweep 2026-05-22 — comparison endpoints re-tiered
    # by work shape (was uniformly TIER_A_HEAVY; only /decompilation
    # genuinely fits HEAVY due to 2× cold-cache Ghidra calls).
    ("app/routers/comparison.py", r'@router\.post\("/firmware"'): "TIER_A_LIGHT_ACK",
    ("app/routers/comparison.py", r'@router\.post\("/binary"'): "TIER_A_LIGHT_ACK",
    ("app/routers/comparison.py", r'@router\.post\("/text"'): "TIER_C_DEFAULT",
    ("app/routers/comparison.py", r'@router\.post\("/instructions"'): "TIER_C_DEFAULT",
    ("app/routers/comparison.py", r'@router\.post\("/decompilation"'): "TIER_A_HEAVY",
    ("app/routers/attack_surface.py", r'@router\.post\("/scan"'): "TIER_A_HEAVY",
}


def _check_tier_alignment(repo_root: Path, expected: dict[tuple[str, str], str]) -> list[str]:
    """Return a list of failure messages — empty list means all aligned.

    Factored out of test_expensive_posts_are_rate_limited so the META-CANARY
    test can call it against a synthetic temp tree and assert it returns
    non-empty for a wrong-tier file.
    """
    failures: list[str] = []
    for (rel_path, marker_pattern), expected_tier in expected.items():
        path = repo_root / rel_path
        text = path.read_text()
        match = re.search(marker_pattern, text, re.MULTILINE)
        if not match:
            failures.append(
                f"{rel_path}: marker pattern `{marker_pattern}` not found — "
                f"endpoint moved or renamed?"
            )
            continue
        # Window: 240 chars after the @router.post line should contain
        # any chained decorators + the function signature.
        window = text[match.start():match.start() + 240]
        if f"@limiter.limit({expected_tier})" not in window:
            failures.append(
                f"{rel_path}: `@limiter.limit({expected_tier})` not found "
                f"adjacent to the matched endpoint marker.  Window:\n{window!r}"
            )
    return failures


def test_expensive_posts_are_rate_limited():
    """Each documented expensive POST endpoint MUST carry a
    `@limiter.limit(<TIER>)` decorator with the expected tier."""
    failures = _check_tier_alignment(_REPO_BACKEND, _EXPECTED_TIERS)
    if failures:
        pytest.fail(
            "Rate-limit tier coverage missing on documented expensive POSTs:\n  - "
            + "\n  - ".join(failures)
        )


def test_tier_constant_values_pinned():
    """Tier constants are load-bearing — any change MUST be a deliberate
    commit, not a drift.  Pinning the values here catches accidental
    edits to ``app/rate_limit.py`` that would silently change the
    saturation calculus."""
    from app import rate_limit
    assert rate_limit.TIER_A_HEAVY == "5/hour"
    assert rate_limit.TIER_A_LIGHT_ACK == "30/hour"
    assert rate_limit.TIER_B_DOCKER == "20/hour"
    assert rate_limit.TIER_C_DEFAULT == "100/minute"


def test_expected_tiers_count_size_locked():
    """Pin the count of documented expensive POSTs so adding a new
    rate-limited endpoint without updating this test fails loudly.

    Current count: 20 (11 prior + 9 from scout1: 3 apk_scan + 5
    comparison + 1 attack_surface).
    """
    assert len(_EXPECTED_TIERS) == 20, (
        f"_EXPECTED_TIERS count drift: expected 20, got {len(_EXPECTED_TIERS)}. "
        "Adding a rate-limited endpoint? Update this assertion + the dict above."
    )


def test_meta_canary_wrong_tier_decorator_detected(tmp_path):
    """Rule #46 META-CANARY for ``test_expensive_posts_are_rate_limited``.

    Synthesize a router file with a wrong-tier decorator and confirm
    ``_check_tier_alignment`` reports it.  Without this canary, the static
    test's assertion logic could silently break (e.g. a regex change
    that accidentally always matches) and the gate would still report
    pass on the production tree.
    """
    fake_root = tmp_path / "backend"
    routers = fake_root / "app" / "routers"
    routers.mkdir(parents=True)
    # Plant a synthetic security_audit.py with a WRONG tier decorator
    # (TIER_A_LIGHT_ACK instead of TIER_A_HEAVY).
    (routers / "security_audit.py").write_text(
        "from app.rate_limit import TIER_A_LIGHT_ACK, limiter\n\n"
        '@router.post("/audit")\n'
        "@limiter.limit(TIER_A_LIGHT_ACK)\n"
        "async def audit(): pass\n"
    )
    expected = {
        ("app/routers/security_audit.py", r'@router\.post\("/audit"'): "TIER_A_HEAVY",
    }
    failures = _check_tier_alignment(fake_root, expected)
    assert failures, (
        "META-CANARY failed: the static check should have rejected a wrong "
        "tier decorator but reported no failures. The test's assertion "
        "logic is broken — every prior 'pass' was a silent no-check."
    )
    assert "TIER_A_HEAVY" in failures[0], (
        f"META-CANARY: failure message should name the expected tier; got: {failures[0]!r}"
    )


def test_meta_canary_missing_endpoint_detected(tmp_path):
    """Rule #46 META-CANARY companion — confirm the static check catches
    a MISSING endpoint (regex marker doesn't match anything in the file),
    not just a wrong-tier one.  Two failure modes; two canaries.
    """
    fake_root = tmp_path / "backend"
    routers = fake_root / "app" / "routers"
    routers.mkdir(parents=True)
    # Plant a synthetic security_audit.py that DOESN'T have the expected
    # @router.post("/audit") endpoint.
    (routers / "security_audit.py").write_text(
        '# no audit endpoint here — testing missing-marker detection\n'
        '@router.post("/something-else")\n'
        '@limiter.limit(TIER_A_HEAVY)\n'
        'async def other(): pass\n'
    )
    expected = {
        ("app/routers/security_audit.py", r'@router\.post\("/audit"'): "TIER_A_HEAVY",
    }
    failures = _check_tier_alignment(fake_root, expected)
    assert failures, "META-CANARY: missing endpoint should fail the check"
    assert "marker pattern" in failures[0] and "not found" in failures[0], (
        f"META-CANARY: failure message should explain the missing marker; got: {failures[0]!r}"
    )


# ---------------------------------------------------------------------------
# Dynamic 429 — actually hit a rate-limited endpoint past its limit and
# confirm the structured-body 429 response shape from
# app.rate_limit.custom_rate_limit_exceeded_handler.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dynamic_429_response_shape_on_security_audit():
    """Hit POST /security/audit TIER_A_HEAVY+1 = 6 times and assert
    the last response is 429 with the structured body shape that
    ``custom_rate_limit_exceeded_handler`` produces (commit 616e89d +
    afa23a9). Rule #35b live canary: proves SlowAPIMiddleware is wired
    + custom handler is installed + reverse-tier-map resolves correctly.

    Uses POST /security/audit (canonical TIER_A_HEAVY example, synchronous,
    rate_limit.py docstring reference case). Was POST /firmware/{id}/unpack
    pre-over-constraint-sweep-2026-05-22; switched because unpack's correct
    tier per Rule #51 is TIER_A_LIGHT_ACK (event-loop-free arq dispatch),
    not HEAVY. The decorator fires before the function body, so the 404
    from a fake firmware row never reaches the test — we only care the
    6th call returns 429.
    """
    from unittest.mock import MagicMock

    from httpx import ASGITransport, AsyncClient

    from app.main import app
    from app.middleware import asgi_auth as _auth_mod
    from app.rate_limit import limiter

    # Disable auth so we don't need an API key.
    fake_settings = MagicMock()
    fake_settings.api_key = ""
    original_get_settings = _auth_mod.get_settings
    _auth_mod.get_settings = lambda: fake_settings  # type: ignore[assignment]

    # Reset the limiter so prior tests / dev requests don't contaminate
    # the bucket. Re-enable in case some other test left it disabled.
    prior_enabled = limiter.enabled
    limiter.enabled = True
    limiter.reset()
    try:
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            # 6 POSTs — TIER_A_HEAVY is 5/hour, so the 6th must 429.
            project_id = "00000000-0000-0000-0000-000000000001"
            url = f"/api/v1/projects/{project_id}/security/audit"
            responses = []
            for _ in range(6):
                r = await client.post(url)
                responses.append(r)
            # First 5 should not be 429 (they may be 404/409/422 from the
            # function body — that's fine; we just need them to NOT be the
            # rate-limited response).
            assert all(r.status_code != 429 for r in responses[:5]), (
                f"Expected first 5 to NOT be 429; got statuses "
                f"{[r.status_code for r in responses[:5]]}"
            )
            last = responses[-1]
            assert last.status_code == 429, (
                f"Expected 6th response to be 429; got {last.status_code}: {last.text[:200]}"
            )
            # Structured body shape per custom_rate_limit_exceeded_handler.
            body = last.json()
            assert set(body.keys()) >= {"detail", "error", "tier", "retry_after_seconds", "hint"}, (
                f"429 body missing required keys; got: {set(body.keys())}"
            )
            assert body["tier"] == "TIER_A_HEAVY", (
                f"tier should resolve to TIER_A_HEAVY; got: {body['tier']!r}"
            )
            assert isinstance(body["retry_after_seconds"], int) and body["retry_after_seconds"] > 0, (
                f"retry_after_seconds should be a positive int; got: {body['retry_after_seconds']!r}"
            )
            assert "5 per 1 hour" in body["error"], (
                f"error should include the parsed limit string; got: {body['error']!r}"
            )
            # Retry-After header per RFC 7231 §7.1.3.
            retry_after = last.headers.get("retry-after")
            assert retry_after is not None, "Retry-After header MUST be set on 429"
            assert retry_after == str(body["retry_after_seconds"]), (
                f"Retry-After header ({retry_after!r}) should match body's "
                f"retry_after_seconds ({body['retry_after_seconds']})"
            )
    finally:
        _auth_mod.get_settings = original_get_settings  # type: ignore[assignment]
        limiter.enabled = prior_enabled
        limiter.reset()
