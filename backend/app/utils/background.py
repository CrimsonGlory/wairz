"""GC-hardened background-task helper for detached coroutines.

Wraps :func:`asyncio.create_task` with a module-level strong-reference set
so the task cannot be garbage-collected mid-run. Per Python's asyncio docs
(https://docs.python.org/3/library/asyncio-task.html#asyncio.create_task —
"Important: Save a reference to the result of this function, to avoid a
task disappearing mid-execution"), bare ``asyncio.create_task(coro)``
returns a task whose only reference is the event loop's WEAK reference.
Under memory pressure or GC, the task can be collected mid-run; for the
wairz long-running state-machine runners, that means the firmware row
stays stuck in ``*_status='running'`` forever and the frontend polls
indefinitely (Session 1 Scout D's #1 candidate symptom — stuck "Scanning…"
spinner).

Originally factored out of ``backend/app/routers/sbom.py`` (Session 1
Fix #8 introduced the helper there as a local-to-router module) in
Session 2a Fix #8-broader (2026-05-21). Now imported by every router +
service that fires detached coroutines.

Usage::

    from app.utils.background import spawn_background_task

    spawn_background_task(
        _run_my_long_background(firmware.id),
        name=f"my_op_{firmware.id}",  # asyncio.all_tasks() debugger legibility
    )

Cross-refs:
- CLAUDE.md Rule #33 .d (asyncio.create_task vs arq decision rubric — this
  is the asyncio.create_task lane's GC-hardening discipline)
- CLAUDE.md Rule #46 (paired META-CANARY discipline; absence-asserting
  gates need synthesize-and-assert canaries)
- CLAUDE.md Rule #51 §SC5-NEW-SBOM Fix #8 GC-hardening (Session 1 +
  Session 2a SEAM-A extension to firmware_service.py:818)
"""
from __future__ import annotations

import asyncio
from collections.abc import Coroutine
from typing import Any

# Module-level strong-reference set per the asyncio documentation. Tasks
# added here cannot be collected mid-run; the `add_done_callback` removes
# them on natural completion so the set self-trims and never grows
# unbounded.
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


def spawn_background_task(
    coro: Coroutine[Any, Any, Any],
    *,
    name: str | None = None,
) -> asyncio.Task[Any]:
    """Create + track a detached background task with a strong reference.

    Replaces bare ``asyncio.create_task(coro)`` calls per Rule #51
    §SC5-NEW-SBOM GC-hardening discipline.
    """
    task = asyncio.create_task(coro, name=name)
    _BACKGROUND_TASKS.add(task)
    task.add_done_callback(_BACKGROUND_TASKS.discard)
    return task


__all__ = ["_BACKGROUND_TASKS", "spawn_background_task"]
