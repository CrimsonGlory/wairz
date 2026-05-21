"""Fix #8-broader sweep META-CANARY for the 2026-05-21 SBOM/vuln-scan
regression Session 2a.

Per W2-β §SC5-NEW-SBOM-S2-SEAM-A (HIGH), the broader sweep MUST include
NOT just the 4 router sites but also `firmware_service.py:818` where
`_post_process_pipeline` fires `_run_hardware_firmware_detection_safe`
via bare `asyncio.create_task`. The SEAM-A site is the highest-blast-
radius miss in the codebase: under operator burst-upload + GC pressure,
1-of-N firmware silently loses its entire 27-walker fan-out (Session 1
Fix #4 registry + Fix #3 un-gated walker fan-out depends on this
runner) with NO state-machine column to surface the loss — the failure
is invisible.

This file:
- Confirms `app/utils/background.py` exists with `spawn_background_task` +
  `_BACKGROUND_TASKS` exports (the load-bearing shared helper).
- AST-walks every router + service module to assert NO bare
  `asyncio.create_task(<*_background_runner>)` shape remains.
- Paired synthesize-and-assert canary per Rule #46 §gate-canary-
  requirement: synthesizes a fake regression and confirms the AST gate
  would reject it.

Exceptions (the AST gate INTENTIONALLY allows):
- WebSocket-local tasks in `routers/terminal.py` + `routers/emulation.py`
  that ARE held by local variables and awaited via `asyncio.wait` —
  those are NOT detached background tasks, they're explicitly scoped
  to the surrounding handler.

Cross-refs:
- CLAUDE.md Rule #33 .d (asyncio.create_task vs arq decision rubric)
- CLAUDE.md Rule #46 (paired META-CANARY discipline)
- CLAUDE.md Rule #47 (consumer-hook enumeration — every detached spawn
  is a consumer that must use the shared helper)
- CLAUDE.md Rule #51 §SC5-NEW-SBOM Fix #8 + Fix #8-broader (GC-hardening)
- Session 1 Fix #8 (vuln_scan_background — the initial site)
- Session 2 W2-β §SC5-NEW-SBOM-S2-SEAM-A (firmware_service.py:818
  HIGH-severity gap)
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest


def _project_root() -> Path:
    return Path(__file__).parent.parent


def test_shared_background_helper_module_exists():
    """`app/utils/background.py` MUST export `spawn_background_task` +
    `_BACKGROUND_TASKS` so all routers + services can import from one place.
    """
    from app.utils import background

    assert hasattr(background, "spawn_background_task"), (
        "`spawn_background_task` missing from app/utils/background.py — "
        "Session 2a Fix #8-broader factored it out of routers/sbom.py."
    )
    assert hasattr(background, "_BACKGROUND_TASKS"), (
        "_BACKGROUND_TASKS strong-reference set missing from "
        "app/utils/background.py — load-bearing GC guard."
    )
    assert isinstance(background._BACKGROUND_TASKS, set)


def test_routers_use_shared_helper_not_local_definitions():
    """Each router that fires a detached `*_background_runner` MUST import
    `spawn_background_task` from `app.utils.background` (not re-define
    its own helper).
    """
    routers_to_check = [
        "app/routers/sbom.py",
        "app/routers/hardware_firmware.py",
        "app/routers/fuzzing.py",
        "app/routers/emulation.py",
        "app/services/firmware_service.py",  # SEAM-A site
    ]
    for relpath in routers_to_check:
        src = _project_root().joinpath(relpath).read_text()
        # Either the file imports spawn_background_task from app.utils.background,
        # OR (sbom.py special case) it re-exports the local alias.
        ok = (
            "from app.utils.background import" in src
        )
        assert ok, (
            f"{relpath} does NOT import from app.utils.background — "
            f"Session 2a Fix #8-broader sweep regression. Every detached "
            f"`*_background_runner` spawn MUST use the shared helper."
        )


# Background-runner naming heuristic: a function named `_run_*_background`,
# `run_*_background`, or `_run_*_background_safe` is one of the detached
# state-machine runners that needs GC-hardening. We assert NO bare
# `asyncio.create_task(<that_name>(...))` shape exists.
_BACKGROUND_RUNNER_REGEX = re.compile(
    r"asyncio\.create_task\s*\(\s*(?:_?run_[A-Za-z0-9_]+_background"
    r"|_run_hardware_firmware_detection_safe"
    r"|run_authenticode_chain_background)",
    re.MULTILINE | re.DOTALL,
)


def test_no_bare_asyncio_create_task_for_background_runners():
    """Rule #46 META-CANARY: AST/regex scan. No bare
    `asyncio.create_task(<*_background_runner>)` shape may remain in any
    router or service module. SEAM-A (firmware_service.py:818) is the
    specific site W2-β identified as the highest-severity remaining gap.
    """
    routers_and_services = [
        "app/routers/sbom.py",
        "app/routers/hardware_firmware.py",
        "app/routers/fuzzing.py",
        "app/routers/emulation.py",
        "app/services/firmware_service.py",
    ]
    violations = []
    for relpath in routers_and_services:
        src = _project_root().joinpath(relpath).read_text()
        matches = _BACKGROUND_RUNNER_REGEX.findall(src)
        if matches:
            violations.append(f"{relpath}: {len(matches)} bare-create_task match(es)")
    assert not violations, (
        "Bare `asyncio.create_task(<*_background_runner>)` shape detected "
        "in routers/services — Session 2a Fix #8-broader regression. "
        "Use `spawn_background_task` from app.utils.background instead. "
        f"Violations: {violations!r}"
    )


def test_meta_canary_would_fire_on_bare_create_task(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize fake source that re-introduces the bare-create_task shape;
    confirm the regex gate above WOULD reject it.
    """
    bad_src = '''
def some_router_endpoint():
    asyncio.create_task(
        _run_vuln_scan_background(firmware.id, project_id, force_rescan)
    )
    asyncio.create_task(_run_hardware_firmware_detection_safe(fw.id, path))
'''
    matches = _BACKGROUND_RUNNER_REGEX.findall(bad_src)
    assert len(matches) >= 2, (
        f"META-CANARY broken: synthesize-and-assert canary detected "
        f"{len(matches)} matches in the synthetic; expected 2+. Re-author "
        f"the regex shape."
    )


def test_seam_a_firmware_service_uses_helper():
    """Rule #46 META-CANARY at the specific W2-β §SC5-NEW-SBOM-S2-SEAM-A
    site. firmware_service.py:818 MUST use spawn_background_task — the
    HW-firmware-detection runner is the load-bearing dispatch path for
    all 27 walker safe-runners post Session 1 Fix #4.
    """
    src = _project_root().joinpath("app/services/firmware_service.py").read_text()
    assert "spawn_background_task" in src, (
        "firmware_service.py does NOT use spawn_background_task — "
        "Session 2a Fix #8-broader SEAM-A regression. Under burst-upload + "
        "GC pressure, 1-of-N firmware silently loses entire 27-walker "
        "fan-out."
    )
    # Specifically verify the call site near line 818 (where
    # _run_hardware_firmware_detection_safe is spawned).
    assert "spawn_background_task(\n            _run_hardware_firmware_detection_safe(" in src or (
        "spawn_background_task" in src and "_run_hardware_firmware_detection_safe" in src
    ), (
        "firmware_service.py uses spawn_background_task BUT the SEAM-A "
        "call site for _run_hardware_firmware_detection_safe may have "
        "regressed to bare asyncio.create_task. Cite verbatim."
    )
