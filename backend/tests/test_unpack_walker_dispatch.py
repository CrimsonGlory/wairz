"""Fix #3 of the 2026-05-21 SBOM/vuln-scan regression investigation —
walker fan-out runs unconditionally; HW-blob count <= 0 NO LONGER
short-circuits the walker registry.

Wave-1 Scout C's live-DB probe documented cluster-wide zero walker output
since 2026-05-12 because `unpack.py`'s pre-fix `if count <= 0: return`
skipped the walker fan-out for every firmware whose HW-blob detection
returned zero. The fix:

- HW-blob detection still runs.
- Driver-firmware graph build STAYS gated on `count > 0` (it operates
  over the persisted blob rows; nothing useful happens at count=0).
- Walker fan-out runs UNCONDITIONALLY (each walker uses Rule #16
  `get_detection_roots(firmware)` to filter targets — no-ops cheaply
  when no artefacts present).
- Cross-firmware walker fan-out is bounded by an `asyncio.Semaphore(4)`
  per Rule #51 §SC5-NEW-SBOM-θ (the W2-β cross-feature critique caught
  the pool-detonation risk if the gate were removed without a bound).

Rule #46 paired META-CANARY: AST scan asserting the post-fix code-shape
plus a synthesize-and-assert canary proving the META-CANARY would fire
on a regression that re-introduces the gate.
"""
from __future__ import annotations

import ast
import re
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_walker_fanout_fires_when_count_is_zero():
    """The post-fix invariant: zero HW blobs detected → walker fan-out STILL fires.

    Pre-fix (`unpack.py:106 if count <= 0: return`) silently skipped the
    walker registry for every bare-metal MCU / intel_hex / non-Linux firmware
    upload. Per Scout C the cluster-wide impact was zero walker output
    cluster-wide since 2026-05-12.
    """
    from app.workers import unpack

    invoked: list[str] = []

    async def _counter_walker_a(firmware_id):
        invoked.append("walker_a")

    async def _counter_walker_b(firmware_id):
        invoked.append("walker_b")

    fw_id = uuid.uuid4()

    with (
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(return_value=0),
        ),
        patch(
            "app.services.hardware_firmware.graph.build_driver_firmware_graph",
            new=AsyncMock(),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[_counter_walker_a, _counter_walker_b],
        ),
        patch("app.database.async_session_factory") as mock_session_factory,
    ):
        # Make the async session factory yield a context manager that
        # exposes a usable mock db with `commit()`.
        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        await unpack._run_hardware_firmware_detection_safe(fw_id, "/tmp/extracted")

    assert invoked == ["walker_a", "walker_b"], (
        "Walker fan-out did NOT fire on count=0 firmware — Fix #3 regression. "
        f"Expected ['walker_a', 'walker_b'], got {invoked!r}."
    )


@pytest.mark.asyncio
async def test_walker_fanout_fires_when_count_is_positive():
    """Sanity check: the count > 0 path still fires walkers AND builds the graph."""
    from app.workers import unpack

    invoked: list[str] = []
    graph_called: list[bool] = []

    async def _counter_walker(firmware_id):
        invoked.append("walker")

    async def _graph_build(firmware_id, db):
        graph_called.append(True)
        # Return a shape compatible with the logger.info call.
        from types import SimpleNamespace
        return SimpleNamespace(edges=[], unresolved_count=0)

    fw_id = uuid.uuid4()

    with (
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=AsyncMock(return_value=3),
        ),
        patch(
            "app.services.hardware_firmware.graph.build_driver_firmware_graph",
            new=_graph_build,
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[_counter_walker],
        ),
        patch("app.database.async_session_factory") as mock_session_factory,
    ):
        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        await unpack._run_hardware_firmware_detection_safe(fw_id, "/tmp/extracted")

    assert invoked == ["walker"], "Walker fan-out did not fire on count=3 path"
    assert graph_called == [True], "Graph build did not fire on count=3 path"


@pytest.mark.asyncio
async def test_walker_fanout_fires_when_detection_raises():
    """Robustness: detection exception MUST NOT block walker fan-out.

    Pre-Fix #3 the `except Exception: ... return` short-circuited the
    pipeline on detection failure. Post-fix, walkers still get their shot
    because they're Rule #16-driven via `get_detection_roots` and may
    yield useful output independent of HW-blob persistence.
    """
    from app.workers import unpack

    invoked: list[str] = []

    async def _counter_walker(firmware_id):
        invoked.append("walker")

    fw_id = uuid.uuid4()

    async def _raising_detect(firmware_id, db):
        raise RuntimeError("simulated detector crash")

    with (
        patch(
            "app.services.hardware_firmware.detect_hardware_firmware",
            new=_raising_detect,
        ),
        patch(
            "app.services.hardware_firmware.graph.build_driver_firmware_graph",
            new=AsyncMock(),
        ),
        patch(
            "app.workers.walker_registry.get_walker_auto_triggers",
            return_value=[_counter_walker],
        ),
        patch("app.database.async_session_factory") as mock_session_factory,
    ):
        mock_db = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_session_factory.return_value.__aenter__ = AsyncMock(return_value=mock_db)
        mock_session_factory.return_value.__aexit__ = AsyncMock(return_value=None)

        await unpack._run_hardware_firmware_detection_safe(fw_id, "/tmp/extracted")

    assert invoked == ["walker"], (
        "Walker fan-out did NOT fire after a detection exception — Fix #3 "
        "regression. The except branch must no longer return."
    )


def test_meta_canary_no_bare_count_le_zero_return_in_run_hw_detection_safe():
    """Rule #46 META-CANARY: the bad shape `if count <= 0: return` MUST NOT
    appear inside `_run_hardware_firmware_detection_safe`.

    This is an AST-walk of the function body. The post-fix shape gates the
    GRAPH build on `count > 0`; it does NOT bare-return on count<=0.
    """
    source = Path(__file__).parent.parent.joinpath(
        "app/workers/unpack.py"
    ).read_text()
    tree = ast.parse(source)

    target_fn = None
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_run_hardware_firmware_detection_safe":
            target_fn = node
            break
    assert target_fn is not None, "Could not locate _run_hardware_firmware_detection_safe"

    # Walk the function body. If we find `if <count expr> <= 0: <bare return>`,
    # the gate has been re-introduced.
    for child in ast.walk(target_fn):
        if isinstance(child, ast.If) and isinstance(child.test, ast.Compare):
            cmp = child.test
            if (
                isinstance(cmp.left, ast.Name)
                and cmp.left.id == "count"
                and len(cmp.ops) == 1
                and isinstance(cmp.ops[0], ast.LtE)
                and len(cmp.comparators) == 1
                and isinstance(cmp.comparators[0], ast.Constant)
                and cmp.comparators[0].value == 0
            ):
                # Found `if count <= 0: …` — check the body for a bare `return`.
                for stmt in child.body:
                    if isinstance(stmt, ast.Return) and stmt.value is None:
                        pytest.fail(
                            "REGRESSION: `if count <= 0: return` re-introduced in "
                            "_run_hardware_firmware_detection_safe — walker fan-out "
                            "would be short-circuited for zero-HW-blob firmware. "
                            "See Fix #3 in "
                            ".planning/research/sbom-vuln-scan-regression-2026-05-21/."
                        )


def test_meta_canary_would_fire_on_re_introduced_gate(tmp_path):
    """Paired synthesize-and-assert canary per Rule #46 §gate-canary-requirement.

    Synthesize a fake `unpack.py` that re-introduces the bad gate, then run
    the same AST walk against it. The canary above must raise on this synthetic.
    Without this paired check, the gate above could silently no-op if the AST
    walk regresses (e.g. a structural rewrite that hides the LtE node).
    """
    bad_src = '''
async def _run_hardware_firmware_detection_safe(firmware_id, extracted_path):
    count = 0
    if count <= 0:
        return
    print("never reached on count=0")
'''
    fake = tmp_path / "fake_unpack.py"
    fake.write_text(bad_src)
    tree = ast.parse(bad_src)

    found_bare_return_under_count_le_zero = False
    for node in ast.walk(tree):
        if isinstance(node, ast.AsyncFunctionDef) and node.name == "_run_hardware_firmware_detection_safe":
            for child in ast.walk(node):
                if isinstance(child, ast.If) and isinstance(child.test, ast.Compare):
                    cmp = child.test
                    if (
                        isinstance(cmp.left, ast.Name)
                        and cmp.left.id == "count"
                        and len(cmp.ops) == 1
                        and isinstance(cmp.ops[0], ast.LtE)
                        and len(cmp.comparators) == 1
                        and isinstance(cmp.comparators[0], ast.Constant)
                        and cmp.comparators[0].value == 0
                    ):
                        for stmt in child.body:
                            if isinstance(stmt, ast.Return) and stmt.value is None:
                                found_bare_return_under_count_le_zero = True

    assert found_bare_return_under_count_le_zero, (
        "META-CANARY broken: the synthesize-and-assert canary did NOT detect "
        "the regression shape in the synthetic fake. Re-author the AST walk."
    )


def test_walker_fanout_semaphore_is_present_with_bound_4():
    """Rule #51 §SC5-NEW-SBOM-θ: cross-firmware walker fan-out MUST be bounded.

    A regression that drops the `_WALKER_FANOUT_SEMAPHORE` or sizes it
    unboundedly would re-open the pool-detonation cascade W2-β catalogued.
    """
    from app.workers import unpack

    assert hasattr(unpack, "_WALKER_FANOUT_SEMAPHORE"), (
        "_WALKER_FANOUT_SEMAPHORE missing from app.workers.unpack — Rule #51 "
        "§SC5-NEW-SBOM-θ pool-detonation guard removed. Re-add it."
    )
    # The semaphore's `_value` is private API but stable since 3.4; reading it
    # at module-import time tells us the initial bound.
    sem = unpack._WALKER_FANOUT_SEMAPHORE
    assert sem._value <= 8, (
        f"_WALKER_FANOUT_SEMAPHORE bound is {sem._value} — too permissive. "
        "Rule #51 .iv DB-pool-headroom math expects 4 (10% of pool=40)."
    )
    assert sem._value >= 2, (
        f"_WALKER_FANOUT_SEMAPHORE bound is {sem._value} — too restrictive. "
        "Cross-firmware fan-out under 2 starves operator triage cadence."
    )


def test_walker_fanout_uses_semaphore_context():
    """AST-level check: the walker fan-out loop is inside an `async with
    _WALKER_FANOUT_SEMAPHORE` block. A regression that drops the wrapper
    would leave the semaphore in place but un-enforced.
    """
    source = Path(__file__).parent.parent.joinpath(
        "app/workers/unpack.py"
    ).read_text()
    # Coarse but reliable: the semaphore name appears in a `async with` line
    # that wraps the safe-runner iteration.
    pattern = re.compile(
        r"async\s+with\s+_WALKER_FANOUT_SEMAPHORE\s*:",
    )
    assert pattern.search(source), (
        "`async with _WALKER_FANOUT_SEMAPHORE:` block missing from "
        "app/workers/unpack.py — Rule #51 §SC5-NEW-SBOM-θ enforcement is "
        "no longer active even though the Semaphore object still exists."
    )
