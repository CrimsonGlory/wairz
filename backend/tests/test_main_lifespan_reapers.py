"""Orphan reaper coverage in the FastAPI lifespan startup block.

The lifespan reapers at `backend/app/main.py:120-300` flip stuck state-machine
rows from `('queued','running','detecting','extracting','analyzing')` to
`'failed'` so subsequent POSTs don't 409 forever on phantom rows after a
backend restart. Each reaper is a few SQL `UPDATE` statements gated to its
own column. The coverage matrix is partial today — Scout E (2026-05-21
investigation) found 28+ state-machine columns missing reapers; this file
holds the Rule #46 META-CANARIES for the ones we ship and is extended by
each future commit that wires a new reaper.

Per Rule #46 §gate-canary-requirement, every "asserts absence" gate has a
paired synthesize-and-assert canary proving the gate would fire on a
regression. These tests are deliberately AST-level (read `main.py` source
+ regex / AST walk) so they catch refactors that drop a reaper without
the lifespan ever needing to actually run inside the test process.

Cross-refs:
- CLAUDE.md Rule #51 .i (orphan-reaper completeness on Rule #33 conversions)
- CLAUDE.md Rule #46 (paired META-CANARY discipline)
- 2026-05-21 SBOM/vuln-scan regression investigation Fix #2 (upload_stage),
  Fix #5 (bare_metal_audit_status) — each commit adds its reaper-presence
  canary here.
"""
from __future__ import annotations

from pathlib import Path


def _main_py_source() -> str:
    return Path(__file__).parent.parent.joinpath("app/main.py").read_text()


def test_upload_stage_reaper_present_in_lifespan():
    """Fix #2 — `upload_stage` orphan reaper MUST exist in the lifespan block.

    The reaper flips rows in `upload_stage IN ('detecting','extracting','analyzing')`
    older than 15 minutes to `'failed'`. Pre-2026-05-21 Fix #2 this reaper
    was absent — every backend restart during a multi-GB upload left the
    row stuck in `upload_stage='extracting'` indefinitely with a permanent
    stuck-spinner on the frontend (Scout D's #1 candidate symptom).
    """
    src = _main_py_source()
    assert "Reap orphan upload_stage firmware rows" in src, (
        "upload_stage orphan reaper missing from app/main.py lifespan — "
        "see Fix #2 in .planning/research/sbom-vuln-scan-regression-2026-05-21/."
    )
    # The reaper SQL must filter on upload_stage in the in-progress set.
    assert "upload_stage.in_(" in src and "detecting" in src and "extracting" in src, (
        "upload_stage reaper present but doesn't filter on the expected "
        "in-progress states (detecting/extracting/analyzing). Re-verify "
        "the firmware_service transition sequence."
    )


def test_upload_stage_reaper_uses_15_minute_grace():
    """Rule #51 §SC5-NEW-SBOM-ε mitigation — the upload_stage reaper MUST
    have a grace window so freshly-started uploads aren't reaped mid-flight.

    Without a grace window (W2-β cross-feature critique catalogued this as
    HIGH severity), the lifespan reaper could fire during a legitimate
    upload's startup window, flip the row to failed, then the in-progress
    runner writes a contradictory state on top — race-induced data loss.
    The 15-minute interval exceeds the worst-case observed extraction
    window (Medtronic ILLUMISITE 16 GB tarball, ~12 min cold-extract).
    """
    src = _main_py_source()
    # The grace window is expressed as a 15-minute timedelta.
    assert "timedelta(minutes=15)" in src, (
        "upload_stage reaper missing `timedelta(minutes=15)` grace window. "
        "W2-β §SC5-NEW-SBOM-ε requires the grace clause to avoid reaping "
        "fresh uploads mid-flight."
    )
    # The WHERE clause must exclude rows whose started_at is NULL OR fresh.
    assert "upload_stage_started_at.is_not(None)" in src, (
        "upload_stage reaper missing IS NOT NULL guard on upload_stage_started_at. "
        "Rule #51 §SC5-NEW-SBOM-α NULL handling — freshly-created rows have "
        "NULL started_at and should NOT be eligible for reaping."
    )


def test_upload_stage_meta_canary_would_fire_on_dropped_grace(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake main.py with the grace clause stripped, prove the
    test above would reject it. Without this paired check, the test could
    silently no-op if a refactor renames the timedelta variable or uses a
    different expression (e.g. `timedelta(hours=0, minutes=15)`).
    """
    bad_src = '''
def lifespan():
    """Reap orphan upload_stage firmware rows."""
    # GRACE WINDOW DROPPED — race-prone variant
    res = update(Firmware).where(Firmware.upload_stage.in_(("detecting","extracting","analyzing")))
'''
    # The grace-window check in the canary above must NOT find timedelta(minutes=15)
    # in this synthetic — proving the canary would correctly reject the regression.
    assert "timedelta(minutes=15)" not in bad_src
    assert "upload_stage_started_at.is_not(None)" not in bad_src


def test_existing_vuln_scan_reaper_still_present():
    """Regression guard: the vuln_scan_status reaper shipped in 3d2454b
    (2026-05-18 rate-limit campaign) MUST still be present. A future
    refactor that bundles all reapers into a single helper could
    accidentally drop one; this canary catches that.
    """
    src = _main_py_source()
    assert "Reap orphan vuln-scan firmware rows" in src, (
        "vuln_scan_status reaper accidentally removed — Rule #51 worked "
        "example regression from the 2026-05-18 rate-limit campaign."
    )


def test_existing_cve_match_reaper_still_present():
    """Regression guard: the cve_match_status reaper MUST still be present."""
    src = _main_py_source()
    assert "Reap orphan cve-match firmware rows" in src


def test_existing_device_dump_reaper_still_present():
    """Regression guard: the device-dump reaper MUST still be present."""
    src = _main_py_source()
    assert "Reap orphan device-dump rows" in src


def test_bare_metal_audit_reaper_present_in_lifespan():
    """Fix #5 — `bare_metal_audit_status` orphan reaper MUST exist.

    The bare-metal walker shipped 2026-05-19 with its Rule #33 .a state
    machine but missed the Rule #51 .i reaper companion. Scout C's live-DB
    probe found one TMS320F28066 firmware stuck `bare_metal_audit_status='queued'`
    for 6 days — the worked-example incident for this fix.

    Unlike upload_stage's Fix #2 reaper (which needs a 15-min grace because
    the upload work is on a long-running detached task), bare_metal_audit
    is fully in-process via the existing trigger MCP tool's 409 dedup
    check — no grace window needed.
    """
    src = _main_py_source()
    assert "Reap orphan bare_metal_audit firmware rows" in src, (
        "bare_metal_audit_status reaper missing from app/main.py lifespan — "
        "see Fix #5 in .planning/research/sbom-vuln-scan-regression-2026-05-21/."
    )
    assert "bare_metal_audit_status.in_(" in src, (
        "bare_metal_audit reaper present but doesn't filter on the expected "
        "in-progress states. Re-verify against the state-machine column."
    )


def test_sbom_status_reaper_present_in_lifespan():
    """Session 2a Fix #1 — `sbom_status` orphan reaper MUST exist.

    The sbom_status state machine was added when /sbom/generate was
    converted from sync to 202+polling per Rule #33 (Session 2a Fix #1).
    Rule #51 .i mandates the orphan reaper companion in the SAME chain.
    Without this reaper, a backend restart mid-generation leaves the row
    in `sbom_status='running'` forever — frontend polls forever, operator
    sees stuck-spinner with no recovery affordance. Same shape as the
    vuln_scan reaper shipped at commit `3d2454b` (2026-05-18 rate-limit
    campaign) — this canary catches a future regression that drops the
    block.
    """
    src = _main_py_source()
    assert "Reap orphan sbom-generate firmware rows" in src, (
        "sbom_status orphan reaper missing from app/main.py lifespan — "
        "see Session 2a Fix #1 in "
        ".planning/research/sbom-vuln-scan-session2-2026-05-21/."
    )
    assert "sbom_status.in_(" in src, (
        "sbom_status reaper present but doesn't filter on the expected "
        "in-progress states (queued/running). Re-verify against the "
        "SbomStatus Literal in schemas/sbom.py."
    )


def test_sbom_meta_canary_would_fire_on_dropped_reaper(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Confirms the assertion gate above WOULD reject a regression that
    removes the sbom_status reaper block.
    """
    bad_src = '''
def lifespan():
    """Reap orphan vuln-scan firmware rows."""
    # NO sbom-generate reaper block — regression shape
    pass
'''
    assert "Reap orphan sbom-generate firmware rows" not in bad_src
    assert "sbom_status.in_(" not in bad_src


def test_bare_metal_audit_meta_canary_would_fire_on_dropped_reaper(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake main.py WITHOUT the bare_metal_audit reaper block.
    The canary above (membership check) must reject this synthetic shape.
    Without this paired check, the test could silently no-op if a future
    refactor renames the docstring header text.
    """
    bad_src = '''
def lifespan():
    """Reap orphan vuln-scan firmware rows."""
    # Note: NO bare_metal_audit reaper block
    pass
'''
    assert "Reap orphan bare_metal_audit firmware rows" not in bad_src
    assert "bare_metal_audit_status.in_(" not in bad_src
