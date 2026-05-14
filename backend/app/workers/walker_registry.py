"""Walker auto-trigger registry — single source of truth for post-extraction walker hooks.

Every walker that ships a Rule #39 ``auto_<op>_walk_firmware_safe`` (or the older
``auto_walk_firmware_safe`` / ``auto_extract_drivers_safe`` shapes) registers in
:data:`WALKER_AUTO_TRIGGERS` here. Both the legacy ``_run_hardware_firmware_detection_safe``
hook in :mod:`app.workers.unpack` AND the new ``_post_process_pipeline`` in
:mod:`app.services.firmware_service` iterate this list to fire walkers after
detection completes. The duplicate inline import chains that existed before
walker_registry.py are gone — adding a new walker is a one-line addition here.

Per Rule #39, each safe-runner:

- Owns its own ``async_session_factory()`` session — never shares the caller's.
- Swallows exceptions silently and logs (fire-and-forget shape).
- Does NOT mutate ``firmware.<op>_walk_status`` (leaves it ``idle`` so an
  operator-triggered re-walk via the corresponding ``trigger_<op>_walk`` MCP
  tool succeeds without a 409 conflict).

Per Rule #16, each walker resolves its targets via
``get_detection_roots(firmware)`` — so the upstream pipeline MUST set
``firmware.extracted_path`` (and call ``populate_detection_roots``) BEFORE
the walkers fire, or every walker will see an empty root list and no-op.

The list is intentionally a flat ``list[Callable]`` rather than a richer
structure (no per-walker enabled-flag, no priority ordering, no per-firmware
filter) — wairz's policy is "fire every walker; let each one's own
``get_detection_roots`` filter decide whether work exists". A walker whose
target artefact is absent from the firmware tree returns the empty-result
shape and costs ~one ``scandir`` per detection root — cheap.
"""
from __future__ import annotations

import logging
import uuid
from collections.abc import Awaitable, Callable

logger = logging.getLogger(__name__)


# Type alias for a walker safe-runner — takes a firmware UUID, returns None,
# swallows exceptions internally.
WalkerSafeRunner = Callable[[uuid.UUID], Awaitable[None]]


def _load_walker_safe_runners() -> list[WalkerSafeRunner]:
    """Lazy-import every walker safe-runner and return them in registration order.

    Lazy-imported here (not at module top) to keep the cold-import cost
    off any caller that imports :mod:`walker_registry` purely for the
    type alias or the list shape. Each ``from app.services.X_walker
    import auto_*_walk_firmware_safe`` triggers loading the walker
    module + its dependencies (regipy / python-evtx / dissect.* / etc.) —
    deferring until the list is actually iterated is the right shape.
    """
    # Phase γ — registry hives + driver INF/CAT + Windows event log.
    # Phase η/θ/ι/κ — Windows + Linux artefact walkers (each Rule #39 triplet).
    from app.services.appcompat_walker import auto_appcompat_walk_firmware_safe
    from app.services.bcd_walker import auto_bcd_walk_firmware_safe
    from app.services.container_walker import auto_container_walk_firmware_safe
    from app.services.dpapi_walker import auto_dpapi_walk_firmware_safe
    from app.services.driver_extractor import auto_extract_drivers_safe
    from app.services.efs_walker import auto_efs_walk_firmware_safe
    from app.services.esp_walker import auto_esp_walk_firmware_safe
    from app.services.etl_walker import auto_etl_walk_firmware_safe
    from app.services.evtx_service import auto_walk_firmware_safe as evtx_auto_walk
    from app.services.journald_walker import auto_journald_walk_firmware_safe
    from app.services.linux_persistence_walker import (
        auto_linux_persistence_walk_firmware_safe,
    )
    from app.services.lnk_walker import auto_lnk_walk_firmware_safe
    from app.services.mbr_vbr_walker import auto_mbr_vbr_walk_firmware_safe
    from app.services.memory_image_enumerator import (
        auto_memory_image_enumeration_safe,
    )
    from app.services.mft_walker import auto_mft_walk_firmware_safe
    from app.services.prefetch_walker import (
        auto_walk_firmware_safe as prefetch_auto_walk,
    )
    from app.services.registry_hive_walker import (
        auto_walk_firmware_safe as registry_auto_walk,
    )
    from app.services.scheduled_task_walker import (
        auto_scheduled_task_walk_firmware_safe,
    )
    from app.services.sdb_walker import auto_sdb_walk_firmware_safe
    from app.services.srum_walker import auto_walk_firmware_safe as srum_auto_walk
    from app.services.systemd_walker import auto_systemd_walk_firmware_safe
    from app.services.usnjrnl_walker import auto_usnjrnl_walk_firmware_safe
    from app.services.windows_info_walker import (
        auto_windows_info_walk_firmware_safe,
    )
    from app.services.windows_injection_walker import (
        auto_windows_injection_walk_firmware_safe,
    )
    from app.services.windows_processes_walker import (
        auto_windows_processes_walk_firmware_safe,
    )
    from app.services.wmi_walker import auto_wmi_walk_firmware_safe

    return [
        # Phase γ
        registry_auto_walk,
        auto_extract_drivers_safe,
        evtx_auto_walk,
        # Windows artefact walkers
        auto_appcompat_walk_firmware_safe,
        auto_bcd_walk_firmware_safe,
        auto_dpapi_walk_firmware_safe,
        auto_efs_walk_firmware_safe,
        auto_esp_walk_firmware_safe,
        auto_etl_walk_firmware_safe,
        auto_lnk_walk_firmware_safe,
        auto_mbr_vbr_walk_firmware_safe,
        # λ.α.B — memory-dump-image enumerator (metadata only; no Vol3
        # invocation here — λ.α.D's vol3_runner is the Vol3 entry point).
        auto_memory_image_enumeration_safe,
        # λ.α.D — Vol3 windows.info walker. Order-dependent on λ.α.B
        # above: this walker iterates memory_dump_image rows the
        # enumerator just persisted. Sequential dispatch (per
        # ``_fire_walker_auto_triggers``) guarantees the enumerator
        # commits its rows before this walker queries them.
        auto_windows_info_walk_firmware_safe,
        # λ.β — Vol3 windows_processes walker (pslist/psscan/pstree/cmdline).
        # Order-dependent on λ.α.B (memory_dump_image rows must exist).
        # Independent of λ.α.D — the windows.info walk and the pslist
        # plugin family can run in either order; this walker fires after
        # windows_info purely so the operator-facing UI surfaces the
        # cheaper aggregate first.
        auto_windows_processes_walk_firmware_safe,
        # λ.γ — Vol3 windows_injection walker (windows.malware.*).
        # Order-dependent on λ.α.B. Wires EXCLUSIVELY to the
        # ``windows.malware.<X>`` namespace per the 2026-06-07
        # deprecation deadline for the top-level paths.
        auto_windows_injection_walk_firmware_safe,
        auto_mft_walk_firmware_safe,
        prefetch_auto_walk,
        auto_scheduled_task_walk_firmware_safe,
        auto_sdb_walk_firmware_safe,
        srum_auto_walk,
        auto_usnjrnl_walk_firmware_safe,
        auto_wmi_walk_firmware_safe,
        # Cross-platform / Linux artefact walkers
        auto_container_walk_firmware_safe,
        auto_journald_walk_firmware_safe,
        auto_linux_persistence_walk_firmware_safe,
        auto_systemd_walk_firmware_safe,
    ]


# Module-level cache so repeated dispatches do not re-pay the lazy-import cost.
_CACHED_TRIGGERS: list[WalkerSafeRunner] | None = None


def get_walker_auto_triggers() -> list[WalkerSafeRunner]:
    """Return the cached list of walker safe-runners.

    First call lazy-imports + caches; subsequent calls are O(1).
    Tests can clear the cache via ``_clear_walker_registry_cache()``
    (mainly useful for the rare case where a test monkey-patches a
    safe-runner symbol after the list has been built).
    """
    global _CACHED_TRIGGERS
    if _CACHED_TRIGGERS is None:
        _CACHED_TRIGGERS = _load_walker_safe_runners()
        logger.debug(
            "walker_registry: loaded %d auto-trigger safe-runners",
            len(_CACHED_TRIGGERS),
        )
    return _CACHED_TRIGGERS


def _clear_walker_registry_cache() -> None:
    """Test-only helper to drop the cached registry."""
    global _CACHED_TRIGGERS
    _CACHED_TRIGGERS = None


# Eager-resolved alias for callers that want a list literal — invokes the
# lazy load once at import time. Most callers should prefer
# :func:`get_walker_auto_triggers` so the cost stays deferred until the
# first actual dispatch.
WALKER_AUTO_TRIGGERS = get_walker_auto_triggers()


__all__ = [
    "WALKER_AUTO_TRIGGERS",
    "WalkerSafeRunner",
    "_clear_walker_registry_cache",
    "get_walker_auto_triggers",
]
