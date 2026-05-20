"""Fix #8 of the 2026-05-21 SBOM/vuln-scan regression investigation —
detached background tasks in `routers/sbom.py` MUST hold a strong
reference until completion.

Scout D's #1 candidate symptom for the operator-reported regression was a
"stuck Scanning… spinner" — the post-202 polling loop sees
`vuln_scan_status='running'` forever because the bare `asyncio.create_task`
at the pre-fix `routers/sbom.py:583` returned a task whose only reference
was the asyncio scheduler's weak reference. Under memory pressure or GC
the task vanishes mid-run, the row never advances to `completed`/`failed`,
and the operator's frontend stuck-polls indefinitely.

Fix shape: module-level `_BACKGROUND_TASKS: set[asyncio.Task]` + helper
`_spawn_background_task(coro)` that adds the task to the set and registers
an `add_done_callback(set.discard)` so the set self-trims on completion
without growing unbounded.

Per https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task
this is the documented best practice ("Important: Save a reference to the
result of this function, to avoid a task disappearing mid-execution").

Cross-refs:
- CLAUDE.md Rule #46 (paired META-CANARY discipline)
- CLAUDE.md Rule #51 §SC5-NEW-SBOM Fix #8 (GC-hardening)
- Scout D primary report finding (sbom.py:583 GC risk)
"""
from __future__ import annotations

import asyncio
import re
from pathlib import Path

import pytest


def _sbom_router_source() -> str:
    return Path(__file__).parent.parent.joinpath(
        "app/routers/sbom.py"
    ).read_text()


def test_spawn_background_task_helper_exists():
    """The helper that wraps `asyncio.create_task` with a strong reference
    MUST be defined at module scope."""
    from app.routers import sbom
    assert hasattr(sbom, "_spawn_background_task"), (
        "_spawn_background_task helper missing from app/routers/sbom.py — "
        "see Fix #8 in .planning/research/sbom-vuln-scan-regression-2026-05-21/."
    )
    assert hasattr(sbom, "_BACKGROUND_TASKS"), (
        "_BACKGROUND_TASKS set missing — the strong-reference set is the "
        "load-bearing GC guard."
    )
    assert isinstance(sbom._BACKGROUND_TASKS, set), (
        "_BACKGROUND_TASKS should be a `set`, not a list/dict — "
        "set.discard is the no-error variant required by add_done_callback."
    )


@pytest.mark.asyncio
async def test_spawn_background_task_keeps_strong_reference_until_done():
    """The helper adds the new task to `_BACKGROUND_TASKS` and removes it
    once the coroutine completes — preventing GC mid-run AND avoiding
    unbounded growth."""
    from app.routers import sbom

    # Clear the set so we have a clean count.
    sbom._BACKGROUND_TASKS.clear()

    started = asyncio.Event()
    done = asyncio.Event()

    async def _short_running():
        started.set()
        await asyncio.sleep(0.01)
        done.set()

    task = sbom._spawn_background_task(_short_running())
    await started.wait()
    assert task in sbom._BACKGROUND_TASKS, (
        "Task NOT in _BACKGROUND_TASKS while running — strong reference "
        "missing, GC could collect it."
    )
    await done.wait()
    # Allow the done_callback to run.
    await asyncio.sleep(0.01)
    assert task not in sbom._BACKGROUND_TASKS, (
        "Task still in _BACKGROUND_TASKS after completion — set didn't "
        "self-trim, will grow unbounded under heavy load."
    )


def test_no_bare_asyncio_create_task_for_vuln_scan_background():
    """Rule #46 META-CANARY: AST-level — the vuln_scan background spawn
    MUST use the helper, NOT bare `asyncio.create_task(_run_vuln_scan_background…)`.

    A regression that drops the helper at the spawn site re-introduces
    the GC-vanish risk; this canary catches it without needing to run the
    full vuln-scan flow.
    """
    src = _sbom_router_source()
    # Match `asyncio.create_task(\s*_run_vuln_scan_background` exactly.
    bad_pattern = re.compile(
        r"asyncio\.create_task\s*\(\s*_run_vuln_scan_background",
        re.MULTILINE,
    )
    matches = bad_pattern.findall(src)
    assert not matches, (
        f"Bare `asyncio.create_task(_run_vuln_scan_background…)` re-introduced "
        f"in app/routers/sbom.py — found {len(matches)} occurrence(s). "
        "Use `_spawn_background_task` instead. See Fix #8."
    )


def test_vuln_scan_spawn_uses_helper():
    """Positive form: the spawn site MUST invoke `_spawn_background_task`."""
    src = _sbom_router_source()
    helper_pattern = re.compile(
        r"_spawn_background_task\s*\(\s*\n?\s*_run_vuln_scan_background",
        re.MULTILINE,
    )
    assert helper_pattern.search(src), (
        "The `_run_vuln_scan_background` spawn site no longer routes through "
        "`_spawn_background_task` — Fix #8 GC guard removed."
    )


def test_meta_canary_would_fire_on_bare_create_task(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake `routers/sbom.py` that re-introduces the bare
    `asyncio.create_task(_run_vuln_scan_background…)`. Confirm the regex
    canary above WOULD reject it.
    """
    bad_src = '''
def some_endpoint():
    asyncio.create_task(
        _run_vuln_scan_background(firmware.id, project_id, force_rescan)
    )
'''
    bad_pattern = re.compile(
        r"asyncio\.create_task\s*\(\s*_run_vuln_scan_background",
        re.MULTILINE,
    )
    assert bad_pattern.search(bad_src), (
        "META-CANARY broken: synthesize-and-assert canary did NOT detect the "
        "bare-create_task shape in the synthetic fake. Re-author the regex."
    )
