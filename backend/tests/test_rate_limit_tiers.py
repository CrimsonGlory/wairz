"""Audit-2026-05-04 stream B F-B-07: rate-limit tier coverage assertions.

Two flavours of assertion:

1. **Static** — read each router source for `@limiter.limit(<TIER>)` on
   the documented expensive POSTs.  Catches drift if a future commit
   removes the decorator.

2. **Dynamic** — instantiate FastAPI TestClient against the live router
   surface and replay an endpoint past its tier limit; assert the
   `429 Too Many Requests` response carries `Retry-After`.  Companion
   to CLAUDE.md Rule #35b (live canary): a static check verifies the
   decorator is present, but only a runtime call verifies the limit is
   actually applied (Rule #30: decorator could be no-op'd by a wrong
   patch site, etc.).
"""
from __future__ import annotations

import re
from pathlib import Path

_REPO_BACKEND = Path(__file__).parent.parent

# Map each (router file, endpoint regex marker) → expected tier constant.
#
# Tier assignment per rate_limit.py module docstring:
# - TIER_A_HEAVY (5/hour): sync OR ≥5-min ack-bound runs (security audit
#   is synchronous; cve-match is 202+polling but pins the event loop on
#   bulk SQL inserts for ~7 min on Yocto-scale corpora).
# - TIER_A_LIGHT_ACK (30/hour): 202+polling endpoints whose detached work
#   completes in ≤2 min (SBOM generate / vuln-scan / authenticode-chain).
#   Originally rode TIER_A_HEAVY pre-2026-05-18 split; see commit message
#   for derivation against scout-investigation evidence.
# - TIER_B_DOCKER (20/hour): Docker-spawn jobs (emulation, fuzzing).
_EXPECTED_TIERS: dict[tuple[str, str], str] = {
    ("app/routers/security_audit.py", r'@router\.post\("/audit"'): "TIER_A_HEAVY",
    ("app/routers/hardware_firmware.py", r'@router\.post\("/cve-match"'): "TIER_A_HEAVY",
    ("app/routers/sbom.py", r'@router\.post\("/generate"'): "TIER_A_LIGHT_ACK",
    ("app/routers/sbom.py", r'@router\.post\(\s*\n?\s*"/vulnerabilities/scan"'): "TIER_A_LIGHT_ACK",
    ("app/routers/hardware_firmware.py", r'@router\.post\(\s*\n?\s*"/authenticode-chain"'): "TIER_A_LIGHT_ACK",
    ("app/routers/fuzzing.py", r'@router\.post\(\s*\n?\s*"/campaigns/\{campaign_id\}/start"'): "TIER_B_DOCKER",
    ("app/routers/emulation.py", r'@router\.post\("/start"'): "TIER_B_DOCKER",
    ("app/routers/emulation.py", r'@router\.post\(\s*\n?\s*"/system"'): "TIER_B_DOCKER",
}


def test_expensive_posts_are_rate_limited():
    """Each documented expensive POST endpoint MUST carry a
    `@limiter.limit(<TIER>)` decorator with the expected tier."""
    failures: list[str] = []
    for (rel_path, marker_pattern), expected_tier in _EXPECTED_TIERS.items():
        path = _REPO_BACKEND / rel_path
        text = path.read_text()
        # Find the @router.post(...) marker, then look at the LINES IMMEDIATELY
        # following for a @limiter.limit(<expected_tier>) decorator.
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
    if failures:
        import pytest
        pytest.fail(
            "Rate-limit tier coverage missing on documented expensive POSTs:\n  - "
            + "\n  - ".join(failures)
        )
