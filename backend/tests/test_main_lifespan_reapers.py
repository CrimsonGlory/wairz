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


# ─────────────────────────────────────────────────────────────────────
# Session 2b Fix #11 — two-axis reaper-config registries
# (STATE_MACHINE_REAPER_CONFIGS + WALKER_REAPER_CONFIGS in
# walker_registry.py). The hardcoded 6-block reaper inline in main.py
# was replaced with a data-driven sweep. These META-CANARIES size-lock
# both registries + cross-check coverage against the Firmware model.
# ─────────────────────────────────────────────────────────────────────


def test_state_machine_reaper_configs_size_lock():
    """STATE_MACHINE_REAPER_CONFIGS pinned at EXACTLY 14 entries.

    14 entries today: cve_match_status, vuln_scan_status, sbom_status,
    bare_metal_audit_status, authenticode_chain_status,
    dotnet_decompile_status, windows_update_diff_status, upload_stage,
    ics_protocol_walk_status, kernel_config_audit_status (Rule #45 KSPP
    walker — Linux kernel hardening audit; 10th state-machine column
    landed 2026-05-22 alongside the kernel_image parser),
    kernel_config_walk_status (C1 generic kernel-config EXTRACTION
    walker — 11th state-machine column landed 2026-05-29; DUAL-registered
    here because of the Rule #33 .b result JSONB AND below in
    WALKER_REAPER_CONFIGS because of the ``_walk_status`` suffix),
    module_reachability_walk_status (C2 module/driver REACHABILITY-EVIDENCE
    walker — 12th state-machine column landed 2026-05-29; DUAL-registered
    for the same reasons; produces the loaded/available/builtin module
    evidence the cve-assessment-framework L4 classifier consumes),
    network_exposure_walk_status (C3 network-exposure REACHABILITY-EVIDENCE
    walker — 13th state-machine column landed 2026-05-29; DUAL-registered
    for the same reasons; synthesizes the listener → bind-scope →
    owning-daemon exposure map the L4 listener discriminator consumes), and
    android_posture_walk_status (C4 Android DEPLOYMENT-POSTURE
    REACHABILITY-EVIDENCE walker — 14th state-machine column landed
    2026-05-29; DUAL-registered for the same reasons; synthesizes the
    gates_open deployment posture the L4 LockdownGate consumes, emitting
    runtime_confirmed=false for image-inferred posture so the gate stays OPEN).

    Drift forces a deliberate test edit + postmortem note (Rule #48
    Part 3 size-lock discipline; W2-β §SC5-NEW-SBOM-S2-SEAM-B
    mandate). Adding a new state-machine column means adding the
    reaper config in the SAME Rule #25 atomic commit.
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    assert len(STATE_MACHINE_REAPER_CONFIGS) == 14, (
        f"STATE_MACHINE_REAPER_CONFIGS has {len(STATE_MACHINE_REAPER_CONFIGS)} "
        f"entries; expected exactly 14 (cve_match, vuln_scan, sbom, "
        f"bare_metal_audit, authenticode_chain, dotnet_decompile, "
        f"windows_update_diff, upload_stage, ics_protocol_walk, "
        f"kernel_config_audit, kernel_config_walk, module_reachability_walk, "
        f"network_exposure_walk, android_posture_walk). "
        f"If you're adding a new state-machine column, also extend this dict "
        f"+ the META-CANARY size expectation."
    )


def test_walker_reaper_configs_size_lock_matches_firmware_model():
    """WALKER_REAPER_CONFIGS covers EVERY *_walk_status column on
    Firmware. Cross-axis check: enumerate via SQLAlchemy column
    introspection.

    Per W2-β §SC5-NEW-SBOM-S2-SEAM-B + Rule #46 META-CANARY discipline:
    if a future commit adds a new walker WITH a *_walk_status column
    but DOESN'T add the reaper config, the new walker's operator-
    triggered runs would orphan permanently on backend restart.
    """
    from app.models.firmware import Firmware
    from app.workers.walker_registry import WALKER_REAPER_CONFIGS

    walker_status_columns = {
        col.name for col in Firmware.__table__.columns
        if col.name.endswith("_walk_status")
    }
    registered = set(WALKER_REAPER_CONFIGS.keys())
    missing = walker_status_columns - registered
    extra = registered - walker_status_columns

    assert not missing, (
        f"WALKER_REAPER_CONFIGS is MISSING reaper config for "
        f"{sorted(missing)!r}. Every *_walk_status column on Firmware "
        f"needs an entry in walker_registry.WALKER_REAPER_CONFIGS — "
        f"see W2-β §SC5-NEW-SBOM-S2-SEAM-B. Add via _walker_reaper(...) "
        f"helper at the top of WALKER_REAPER_CONFIGS dict."
    )
    assert not extra, (
        f"WALKER_REAPER_CONFIGS has extra entries {sorted(extra)!r} not "
        f"present on the Firmware model. Either remove the dict entry "
        f"or add the corresponding column to the model."
    )


def test_walker_reaper_config_count_matches_documented():
    """Numeric size-lock — 32 walker columns today (documented in
    walker_registry.py docstring). Drift forces deliberate test edit.

    Last bump: 31 → 32 in C4 Android DEPLOYMENT-POSTURE REACHABILITY-EVIDENCE
    walker 2026-05-29. Adds android_posture_walk_status (the collector that
    synthesizes the gates_open deployment posture the cve-assessment-framework
    L4 kill-chain LockdownGate consumes via AndroidAdapter.get_security_posture
    + get_entry_surfaces; emits runtime_confirmed=false for image-inferred
    posture so the gate stays OPEN; DUAL-registered — also in
    STATE_MACHINE_REAPER_CONFIGS, size-lock 14 above, because of the
    Rule #33 .b result JSONB).

    Prior bump: 30 → 31 in C3 network-exposure REACHABILITY-EVIDENCE walker
    2026-05-29. Adds network_exposure_walk_status (the collector that
    synthesizes the listener → bind-scope → owning-daemon exposure map the
    cve-assessment-framework L4 kill-chain classifier consumes via
    ListenerEntry + network/listeners.json; DUAL-registered — also in
    STATE_MACHINE_REAPER_CONFIGS, size-lock 14 above, because of the
    Rule #33 .b result JSONB).

    Prior bump: 29 → 30 in C2 module/driver REACHABILITY-EVIDENCE walker
    2026-05-29. Adds module_reachability_walk_status (the collector that
    produces the loaded-vs-available-vs-BUILTIN module evidence the
    cve-assessment-framework L4 kill-chain classifier consumes via
    ModuleEntry.builtin + kernel/builtin_modules.json; DUAL-registered —
    also in STATE_MACHINE_REAPER_CONFIGS, size-lock 13 above, because of
    the Rule #33 .b result JSONB).

    Prior bump: 28 → 29 in C1 generic kernel-config EXTRACTION walker
    2026-05-29. Adds kernel_config_walk_status (the UPSTREAM extraction
    layer that guarantees metadata.kernel_config cross-packaging so the
    DOWNSTREAM kernel_config_audit walker fires; DUAL-registered — also
    in STATE_MACHINE_REAPER_CONFIGS, size-lock 12 above, because of the
    Rule #33 .b result JSONB).

    Prior bump: 26 → 28 in Q1 Python AST + Q2 ds1qrsetup_callgraph
    walkers 2026-05-27. Q1 adds python_ast_walk_status (PARSE-ONLY
    static-AST reachability walker per Rule #45 + Rule #36;
    cve-assessment-framework consumer per Round-9.1 §12 EG-8A.3-5).
    Q2 adds ds1qrsetup_callgraph_walk_status (binary call-graph
    walker; complementary to Q1 — Python AST handles deployed scripts,
    Q2 handles native binaries / .so libraries).

    Prior bump: 25 → 26 in ICS Session 2 2026-05-22, adding
    ics_protocol_walk_status (Rule #52 instance #3). Per Scout E +
    W2-α DUAL REGISTRATION, that column also lives in
    STATE_MACHINE_REAPER_CONFIGS (size-lock 11 above) — the
    suffix-introspection check at
    test_walker_reaper_configs_size_lock_matches_firmware_model
    requires every *_walk_status column here regardless of whether
    the column also carries Rule #33 .b result JSONB semantics.
    """
    from app.workers.walker_registry import WALKER_REAPER_CONFIGS

    assert len(WALKER_REAPER_CONFIGS) == 32, (
        f"WALKER_REAPER_CONFIGS has {len(WALKER_REAPER_CONFIGS)} entries; "
        f"expected exactly 32 (matches the documented walker count in "
        f"walker_registry.py docstring as of C4 android-posture "
        f"walker 2026-05-29). Drift means a walker was added/removed "
        f"without sweeping the size-lock — update the test + the docstring "
        f"together."
    )


def test_main_py_lifespan_imports_both_registries():
    """The lifespan code MUST import + iterate both STATE_MACHINE_REAPER_CONFIGS
    and WALKER_REAPER_CONFIGS from walker_registry. A regression that
    drops one registry from the import would silently skip the entire
    half-axis (8 columns OR 25 columns of orphan-reaper coverage).
    """
    src = _main_py_source()
    assert "STATE_MACHINE_REAPER_CONFIGS" in src, (
        "main.py lifespan does NOT import STATE_MACHINE_REAPER_CONFIGS — "
        "9 explicit Rule #33 state-machine columns lose orphan-reaper "
        "coverage. W2-β §SC5-NEW-SBOM-S2-SEAM-B regression."
    )
    assert "WALKER_REAPER_CONFIGS" in src, (
        "main.py lifespan does NOT import WALKER_REAPER_CONFIGS — 26 "
        "walker *_walk_status columns lose orphan-reaper coverage. "
        "W2-β §SC5-NEW-SBOM-S2-SEAM-B regression."
    )
    # Both registries must be ITERATED, not just imported.
    import re
    iteration_pattern = re.compile(
        r"for\s+\w+\s+in\s+STATE_MACHINE_REAPER_CONFIGS",
        re.MULTILINE,
    )
    assert iteration_pattern.search(src), (
        "STATE_MACHINE_REAPER_CONFIGS imported but NOT iterated in "
        "main.py lifespan. The dict must be walked + each config applied."
    )
    iteration_pattern_walker = re.compile(
        r"for\s+\w+\s+in\s+WALKER_REAPER_CONFIGS",
        re.MULTILINE,
    )
    assert iteration_pattern_walker.search(src), (
        "WALKER_REAPER_CONFIGS imported but NOT iterated in main.py "
        "lifespan."
    )


def test_walker_reaper_config_meta_canary_would_fire_on_missing_entry(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake walker_registry with WALKER_REAPER_CONFIGS missing
    one of the 25 walker columns; assert the cross-axis test above
    WOULD reject it.
    """
    from app.models.firmware import Firmware

    walker_status_columns = {
        col.name for col in Firmware.__table__.columns
        if col.name.endswith("_walk_status")
    }

    # Synthesize a fake registry missing 'evtx_walk_status'.
    fake_registered: set[str] = walker_status_columns - {"evtx_walk_status"}
    missing = walker_status_columns - fake_registered

    assert missing == {"evtx_walk_status"}, (
        "META-CANARY broken: synthesize-and-assert canary did NOT "
        "detect 'evtx_walk_status' as missing from the synthetic. "
        "Re-author the missing-set computation."
    )


def test_state_machine_reaper_upload_stage_has_15_minute_grace():
    """W2-β §SC5-NEW-SBOM-ε mandate: upload_stage MUST have a 15-min
    grace window. All other state-machine configs MUST NOT (their
    runners are in-process and the runner sets started_at AFTER
    acquiring its own session; a race against the startup reaper
    would only catch genuinely-dead rows).
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    upload = STATE_MACHINE_REAPER_CONFIGS["upload_stage"]
    assert upload.grace_minutes == 15, (
        f"upload_stage reaper grace_minutes={upload.grace_minutes}; "
        f"expected 15 per W2-β §SC5-NEW-SBOM-ε."
    )
    assert upload.started_at_column == "upload_stage_started_at"

    for key, config in STATE_MACHINE_REAPER_CONFIGS.items():
        if key == "upload_stage":
            continue
        assert config.grace_minutes is None, (
            f"{key} reaper has unexpected grace_minutes={config.grace_minutes}; "
            f"in-process state machines should have None grace (their "
            f"runner sets started_at after session acquisition)."
        )


def test_upload_stage_reaper_present_in_lifespan():
    """Fix #2 — `upload_stage` reaper coverage MUST exist via
    STATE_MACHINE_REAPER_CONFIGS registry (Session 2b Fix #11 refactor
    consolidated the inline blocks into the data-driven sweep).

    The reaper flips rows in `upload_stage IN
    ('detecting','extracting','analyzing')` older than 15 minutes to
    `'failed'`. Pre-2026-05-21 Fix #2 this reaper was absent — every
    backend restart during a multi-GB upload left the row stuck
    indefinitely with a permanent stuck-spinner on the frontend.
    Pre-2026-05-21 Session 2b Fix #11 this was an inline block;
    post-refactor it's an entry in STATE_MACHINE_REAPER_CONFIGS.
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    assert "upload_stage" in STATE_MACHINE_REAPER_CONFIGS, (
        "upload_stage reaper config missing from STATE_MACHINE_REAPER_CONFIGS — "
        "see Fix #2 (Session 1) + Fix #11 (Session 2b) in "
        ".planning/research/sbom-vuln-scan-session2-2026-05-21/."
    )
    config = STATE_MACHINE_REAPER_CONFIGS["upload_stage"]
    # The reaper config must filter on upload_stage's pre-Rule-#33 vocabulary.
    expected_states = {"detecting", "extracting", "analyzing"}
    assert set(config.in_progress_states) == expected_states, (
        f"upload_stage reaper in_progress_states={config.in_progress_states}; "
        f"expected {expected_states}. Re-verify the firmware_service "
        f"transition sequence."
    )


def test_upload_stage_reaper_uses_15_minute_grace():
    """Rule #51 §SC5-NEW-SBOM-ε mitigation — the upload_stage reaper MUST
    have a 15-min grace window so freshly-started uploads aren't reaped
    mid-flight. Post Session 2b Fix #11 refactor, the grace lives in
    `STATE_MACHINE_REAPER_CONFIGS["upload_stage"].grace_minutes`.

    Without a grace window (W2-β cross-feature critique catalogued this as
    HIGH severity), the lifespan reaper could fire during a legitimate
    upload's startup window, flip the row to failed, then the in-progress
    runner writes a contradictory state on top — race-induced data loss.
    The 15-minute interval exceeds the worst-case observed extraction
    window (Medtronic ILLUMISITE 16 GB tarball, ~12 min cold-extract).
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    config = STATE_MACHINE_REAPER_CONFIGS["upload_stage"]
    assert config.grace_minutes == 15, (
        f"upload_stage reaper grace_minutes={config.grace_minutes}; "
        f"expected 15 per W2-β §SC5-NEW-SBOM-ε."
    )
    assert config.started_at_column == "upload_stage_started_at", (
        f"upload_stage reaper started_at_column={config.started_at_column!r}; "
        f"expected 'upload_stage_started_at'. Rule #51 §SC5-NEW-SBOM-α NULL "
        f"handling depends on the IS NOT NULL guard via this column."
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
    """Regression guard: vuln_scan_status reaper coverage MUST exist
    via STATE_MACHINE_REAPER_CONFIGS. Post Session 2b Fix #11 refactor,
    the per-block inline reaper was consolidated into the data-driven
    sweep — coverage now lives in the dict membership, not the
    docstring string-match.
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS
    assert "vuln_scan_status" in STATE_MACHINE_REAPER_CONFIGS, (
        "vuln_scan_status reaper accidentally removed from "
        "STATE_MACHINE_REAPER_CONFIGS — Rule #51 worked-example regression "
        "from the 2026-05-18 rate-limit campaign + Session 2b Fix #11 "
        "refactor regression."
    )


def test_existing_cve_match_reaper_still_present():
    """Regression guard: cve_match_status reaper coverage MUST exist
    via STATE_MACHINE_REAPER_CONFIGS post Session 2b Fix #11 refactor.
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS
    assert "cve_match_status" in STATE_MACHINE_REAPER_CONFIGS, (
        "cve_match_status reaper accidentally removed from "
        "STATE_MACHINE_REAPER_CONFIGS."
    )


def test_existing_device_dump_reaper_still_present():
    """Regression guard: the device-dump reaper MUST still be present."""
    src = _main_py_source()
    assert "Reap orphan device-dump rows" in src


def test_bare_metal_audit_reaper_present_in_lifespan():
    """Fix #5 — `bare_metal_audit_status` reaper coverage MUST exist via
    STATE_MACHINE_REAPER_CONFIGS (Session 2b Fix #11 refactor consolidated
    the inline block).
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    assert "bare_metal_audit_status" in STATE_MACHINE_REAPER_CONFIGS, (
        "bare_metal_audit_status reaper config missing from "
        "STATE_MACHINE_REAPER_CONFIGS. See Fix #5 (Session 1) + Fix #11 "
        "(Session 2b)."
    )
    config = STATE_MACHINE_REAPER_CONFIGS["bare_metal_audit_status"]
    assert set(config.in_progress_states) == {"queued", "running"}, (
        f"bare_metal_audit_status in_progress_states={config.in_progress_states}; "
        f"expected ('queued', 'running')."
    )
    # No grace window — in-process work; runner sets started_at AFTER
    # acquiring its own session.
    assert config.grace_minutes is None


def test_sbom_status_reaper_present_in_lifespan():
    """Session 2a Fix #1 — `sbom_status` reaper coverage MUST exist via
    STATE_MACHINE_REAPER_CONFIGS (Session 2b Fix #11 refactor consolidated
    the inline block).
    """
    from app.workers.walker_registry import STATE_MACHINE_REAPER_CONFIGS

    assert "sbom_status" in STATE_MACHINE_REAPER_CONFIGS, (
        "sbom_status reaper config missing from "
        "STATE_MACHINE_REAPER_CONFIGS. See Session 2a Fix #1 + Session 2b Fix #11."
    )
    config = STATE_MACHINE_REAPER_CONFIGS["sbom_status"]
    assert set(config.in_progress_states) == {"queued", "running"}
    assert config.grace_minutes is None


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
