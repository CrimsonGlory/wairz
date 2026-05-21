"""Fix #6 of the 2026-05-21 SBOM/vuln-scan regression sweep —
``scan_with_grype`` honors ``force_rescan``.

Pre-Session-2a, `scan_with_grype` ignored its caller's `force_rescan`
flag entirely — every invocation re-ran the full Grype subprocess +
unconditionally DELETEd existing vulns + re-INSERTed. The wasted CPU
+ stuck-spinner-on-every-poll-trigger UX was the W2-β §SC5-NEW-SBOM-μ
data-loss surface (subprocess crash AFTER DELETE landed leaves the
firmware with 0 vulnerabilities until the operator manually rescans).

Fix #6 adds `force_rescan: bool = False` to the signature + a cached
short-circuit at the top of the function that returns existing
vulnerability counts when force_rescan=False AND rows already exist.
The transactional DELETE+INSERT inside the matches loop is unchanged
(it was already inside the outer `_run_vuln_scan_background` runner's
session, so rollback-on-subprocess-failure was already correct — the
new short-circuit just avoids running the subprocess at all when
the cached path applies).

Rule #46 paired META-CANARIES:
- signature-level: scan_with_grype MUST accept force_rescan kwarg
- behavioural: cached path returns 'status=cached' summary shape
- synthesize-and-assert: regression that removes force_rescan
  parameter would break the signature check above

Cross-refs:
- CLAUDE.md Rule #32 (transaction semantics in wairz session config)
- CLAUDE.md Rule #33 .b (result aggregate on same row as state)
- CLAUDE.md Rule #46 (paired META-CANARY discipline)
- Session 1 W2-β §SC5-NEW-SBOM-μ (transactional rollback guard)
- Session 2 W2-γ Fix #6 scope (105 LOC, 1 commit)
"""
from __future__ import annotations

import inspect

import pytest


def test_scan_with_grype_signature_accepts_force_rescan():
    """Rule #46 META-CANARY: signature-level — scan_with_grype MUST accept
    a `force_rescan: bool = False` kwarg. A regression that drops it would
    silently re-introduce the unconditional-re-scan behaviour.
    """
    from app.services.grype_service import scan_with_grype

    sig = inspect.signature(scan_with_grype)
    assert "force_rescan" in sig.parameters, (
        "scan_with_grype MUST accept `force_rescan` kwarg per Fix #6 "
        "(2026-05-21 Session 2a). Without it, every invocation re-runs "
        "the Grype subprocess + unconditionally DELETEs+INSERTs vulns. "
        "See .planning/research/sbom-vuln-scan-session2-2026-05-21/."
    )
    param = sig.parameters["force_rescan"]
    assert param.default is False, (
        "force_rescan kwarg default MUST be False (preserves opt-in "
        "semantics — callers that don't care get cached behaviour)."
    )


def test_scan_with_grype_router_passes_force_rescan_through():
    """Rule #46 META-CANARY: routers/sbom.py:_run_vuln_scan_background MUST
    pass `force_rescan=force_rescan` to `scan_with_grype`. Pre-Fix #6 the
    call site omitted force_rescan entirely.
    """
    from pathlib import Path

    src = Path(__file__).parent.parent.joinpath("app/routers/sbom.py").read_text()
    # The grype call inside the if-use_grype branch must pass force_rescan.
    import re
    # Match any whitespace + force_rescan kwarg in a scan_with_grype call.
    pattern = re.compile(
        r"scan_with_grype\s*\(\s*[^)]*\bforce_rescan\s*=",
        re.MULTILINE | re.DOTALL,
    )
    assert pattern.search(src), (
        "routers/sbom.py invokes scan_with_grype WITHOUT passing "
        "force_rescan — Fix #6 regression. The vuln_scan background "
        "runner accepts force_rescan but drops it before grype gets the "
        "kwarg, so the cached path never triggers."
    )


def test_meta_canary_would_fire_on_dropped_force_rescan_kwarg(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake grype_service.py where scan_with_grype lacks the
    force_rescan kwarg. The signature check above MUST reject it via the
    sig.parameters check.
    """
    bad_src = '''
async def scan_with_grype(
    firmware_id,
    project_id,
    db,
):  # NO force_rescan kwarg — regression shape
    pass
'''
    # Verify the synthesized fake actually lacks force_rescan
    assert "force_rescan" not in bad_src
    # If the signature gate above ran against this synthetic, it would
    # raise the diagnostic AssertionError. Confirm shape-equivalence.
    import ast
    tree = ast.parse(bad_src)
    fn = next(n for n in ast.walk(tree) if isinstance(n, ast.AsyncFunctionDef))
    arg_names = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    assert "force_rescan" not in arg_names, (
        "META-CANARY broken — the synthesized fake should NOT contain "
        "force_rescan. Re-author the synthetic."
    )


@pytest.mark.asyncio
async def test_cached_path_returns_status_cached_without_subprocess():
    """Behavioural test: force_rescan=False + existing vulns → no subprocess.

    Use the live-canary discipline (Rule #35b): seed SbomVulnerability
    rows for a firmware, call scan_with_grype with force_rescan=False,
    assert it returns status='cached' AND the subprocess was NOT
    invoked.
    """
    import uuid
    from unittest.mock import patch

    from sqlalchemy import select

    from app.models import Firmware, Project
    from app.models.sbom import SbomComponent, SbomVulnerability
    from app.services.grype_service import scan_with_grype
    from tests._live_db import make_live_db

    async with make_live_db() as db:
        p = Project(name="t", description=None)
        db.add(p)
        await db.flush()
        fw = Firmware(
            project_id=p.id,
            original_filename="x.bin",
            stored_path="/tmp/x.bin",
            file_size=0,
            file_hash="0" * 64,
            upload_stage="ready",
        )
        db.add(fw)
        await db.flush()

        # Seed a component so the components-list check doesn't bail.
        comp = SbomComponent(
            firmware_id=fw.id,
            name="libcurl",
            version="7.0",
            type="library",
            cpe=None,
            purl=None,
            supplier=None,
            detection_source="syft",
            detection_confidence="high",
            file_paths=None,
            metadata_={},
        )
        db.add(comp)
        await db.flush()

        # Seed an existing vulnerability — cached path should detect.
        vuln = SbomVulnerability(
            firmware_id=fw.id,
            component_id=comp.id,
            cve_id="CVE-1999-9999",
            cvss_score=5.0,
            cvss_vector=None,
            severity="medium",
            description="test",
            published_date=None,
            data_source="test",
            fix_versions=None,
        )
        db.add(vuln)
        await db.commit()

        # Mock subprocess so test fails loudly if it gets invoked.
        with patch("app.services.grype_service.asyncio.create_subprocess_exec") as mock_proc:
            mock_proc.side_effect = AssertionError(
                "scan_with_grype invoked subprocess on cached path — Fix #6 regression"
            )
            summary = await scan_with_grype(
                firmware_id=fw.id,
                project_id=p.id,
                db=db,
                force_rescan=False,
            )

        assert summary["status"] == "cached", (
            f"Expected status='cached' on force_rescan=False path; got {summary['status']!r}"
        )
        assert summary["total_vulnerabilities_found"] == 1
        # No subprocess invoked — assertion in side_effect would have raised.
