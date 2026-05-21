"""Walker auto-trigger registry + reaper-config registry.

Single source of truth for (a) post-extraction walker auto-trigger hooks
and (b) the lifespan orphan-reaper sweep configuration that pairs with
every Rule #33 state-machine column.

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
from dataclasses import dataclass

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
    from app.services.bare_metal_walker import auto_bare_metal_audit_firmware_safe
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
        # Bare-metal MCU/DSP audit walker (Rule #52 first worked-example
        # surface). Registered here so bare-metal firmware uploads (TMS320,
        # C28x, STM32, etc.) auto-trigger the audit after extraction; without
        # this entry `bare_metal_audit_status` stays `idle` indefinitely and
        # operators must hand-roll an MCP trigger call. The Rule #39 safe-runner
        # at `bare_metal_walker.py:656` is consumer-hook number 27 per Rule #47
        # enumeration; the matching cross-firmware MCP tool ships as
        # `ai/tools/bare_metal.py::lookup_bare_metal_findings_across_firmwares`
        # (Rule #44 mandatory).
        auto_bare_metal_audit_firmware_safe,
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


@dataclass(frozen=True)
class WalkerReaperConfig:
    """Configuration for one orphan-reaper sweep entry.

    Drives the lifespan startup reaper in ``app/main.py`` that flips
    rows stuck in ``in_progress_states`` to ``failed`` after a backend
    crash. Same shape works for both axes:

    - **WALKER_REAPER_CONFIGS** — operator-trigger-MCP runs against a
      walker's ``*_walk_status`` column. The walker's auto-trigger runner
      (Rule #39 .safe semantics) does NOT mutate the status column; only
      the operator-triggered ``trigger_<op>_walk`` MCP tool does.
    - **STATE_MACHINE_REAPER_CONFIGS** — operator-initiated 202+polling
      runs against an explicit ``*_status`` column (sbom_status,
      vuln_scan_status, cve_match_status, etc.).

    The two-axis split is W2-β §SC5-NEW-SBOM-S2-SEAM-B mandate:
    naive single-list (derive everything from WALKER_AUTO_TRIGGERS)
    loses the defensive coverage for explicit state-machine columns
    that AREN'T walkers (sbom_status / upload_stage / etc.). Both
    dicts ship together; Rule #46 META-CANARY size-locks each.

    Fields:
        column_name: e.g. "sbom_status" / "appcompat_walk_status"
        in_progress_states: states that mean "runner is dead; reap"
            — typically ("queued", "running") for Rule #33 .a 5-state
            machines; ("detecting", "extracting", "analyzing") for
            upload_stage's pre-Rule-#33 shape
        failure_message: human-readable error message written to the
            error column on reap
        finished_at_column: optional companion column to stamp with
            ``NOW()`` on reap (None = skip)
        error_column: optional companion column to write
            ``failure_message`` to (None = skip)
        started_at_column: optional started_at column used for the
            grace window check (REQUIRED if grace_minutes is set)
        grace_minutes: optional grace window per W2-β §SC5-NEW-SBOM-ε.
            None = no grace (in-process work; runner sets started_at
            AFTER acquiring its own session, so a race against the
            startup reaper would only catch genuinely-dead rows).
            int = detached background task that may still be spinning
            up when the lifespan reaper fires — skip rows whose
            started_at is recent.

    Frozen dataclass so the registry can't be mutated at runtime by
    misbehaving callers; size-lock META-CANARY in
    ``tests/test_main_lifespan_reapers.py`` enforces the membership
    contract.
    """
    column_name: str
    in_progress_states: tuple[str, ...]
    failure_message: str
    finished_at_column: str | None = None
    error_column: str | None = None
    started_at_column: str | None = None
    grace_minutes: int | None = None


# ─────────────────────────────────────────────────────────────────────
# STATE_MACHINE_REAPER_CONFIGS — explicit Rule #33 state-machine columns
# (operator-initiated; pair with a Rule #33 sync→202+polling refactor +
# its lifespan reaper companion per Rule #51 .i).
# ─────────────────────────────────────────────────────────────────────
STATE_MACHINE_REAPER_CONFIGS: dict[str, WalkerReaperConfig] = {
    "cve_match_status": WalkerReaperConfig(
        column_name="cve_match_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="cve_match_finished_at",
        error_column="cve_match_error",
    ),
    "vuln_scan_status": WalkerReaperConfig(
        column_name="vuln_scan_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="vuln_scan_finished_at",
        error_column="vuln_scan_error",
    ),
    "sbom_status": WalkerReaperConfig(
        column_name="sbom_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="sbom_status_finished_at",
        error_column="sbom_status_error",
    ),
    "bare_metal_audit_status": WalkerReaperConfig(
        column_name="bare_metal_audit_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="bare_metal_audit_finished_at",
        error_column="bare_metal_audit_error",
    ),
    "authenticode_chain_status": WalkerReaperConfig(
        column_name="authenticode_chain_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="authenticode_chain_finished_at",
        error_column="authenticode_chain_error",
    ),
    "dotnet_decompile_status": WalkerReaperConfig(
        column_name="dotnet_decompile_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="dotnet_decompile_finished_at",
        error_column="dotnet_decompile_error",
    ),
    "windows_update_diff_status": WalkerReaperConfig(
        column_name="windows_update_diff_status",
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; runner state lost",
        finished_at_column="windows_update_diff_finished_at",
        error_column="windows_update_diff_error",
    ),
    "upload_stage": WalkerReaperConfig(
        # upload_stage uses pre-Rule-#33 vocabulary
        # (detecting/extracting/analyzing) and a 15-min grace window
        # per W2-β §SC5-NEW-SBOM-ε — the post-process background task
        # runs detached via spawn_background_task and may still be
        # spinning up when the lifespan reaper fires; the grace clause
        # avoids reaping a fresh row mid-startup.
        column_name="upload_stage",
        in_progress_states=("detecting", "extracting", "analyzing"),
        failure_message="Backend restarted; upload runner state lost",
        finished_at_column="upload_stage_finished_at",
        error_column="upload_stage_error",
        started_at_column="upload_stage_started_at",
        grace_minutes=15,
    ),
}


# ─────────────────────────────────────────────────────────────────────
# WALKER_REAPER_CONFIGS — *_walk_status columns. Operator-trigger-MCP
# runs land here (trigger_<op>_walk MCP tool flips idle → queued; the
# Rule #39 outer runner cycles queued → running → completed | failed).
# Auto-fire (walker_registry.WALKER_AUTO_TRIGGERS) leaves status='idle'
# per Rule #39 .safe contract so re-triggers don't 409.
# ─────────────────────────────────────────────────────────────────────
def _walker_reaper(column: str, *, prefix: str | None = None) -> WalkerReaperConfig:
    """Helper: build a stock walker-reaper config from the column name."""
    base = prefix or column.removesuffix("_walk_status")
    return WalkerReaperConfig(
        column_name=column,
        in_progress_states=("queued", "running"),
        failure_message="Backend restarted; walker runner state lost",
        finished_at_column=f"{base}_walk_finished_at",
        error_column=f"{base}_walk_error",
    )


# 25 walker status columns; each Rule #33 .a 5-state with NO grace
# (operator-triggered in-process work). Per Rule #46 the META-CANARY
# in tests/test_main_lifespan_reapers.py SIZE-LOCKS this dict and
# CROSS-CHECKS that EVERY *_walk_status column on the Firmware model
# is registered here.
WALKER_REAPER_CONFIGS: dict[str, WalkerReaperConfig] = {
    "registry_hive_walk_status": _walker_reaper("registry_hive_walk_status"),
    "evtx_walk_status": _walker_reaper("evtx_walk_status"),
    "prefetch_walk_status": _walker_reaper("prefetch_walk_status"),
    "srum_walk_status": _walker_reaper("srum_walk_status"),
    "scheduled_task_walk_status": _walker_reaper("scheduled_task_walk_status"),
    "lnk_walk_status": _walker_reaper("lnk_walk_status"),
    "mft_walk_status": _walker_reaper("mft_walk_status"),
    "bcd_walk_status": _walker_reaper("bcd_walk_status"),
    "journald_walk_status": _walker_reaper("journald_walk_status"),
    "systemd_walk_status": _walker_reaper("systemd_walk_status"),
    "etl_walk_status": _walker_reaper("etl_walk_status"),
    "efs_walk_status": _walker_reaper("efs_walk_status"),
    "container_walk_status": _walker_reaper("container_walk_status"),
    "appcompat_walk_status": _walker_reaper("appcompat_walk_status"),
    "persistence_walk_status": _walker_reaper("persistence_walk_status"),
    "dpapi_walk_status": _walker_reaper("dpapi_walk_status"),
    "usnjrnl_walk_status": _walker_reaper("usnjrnl_walk_status"),
    "wmi_walk_status": _walker_reaper("wmi_walk_status"),
    "esp_walk_status": _walker_reaper("esp_walk_status"),
    "mbr_vbr_walk_status": _walker_reaper("mbr_vbr_walk_status"),
    "sdb_walk_status": _walker_reaper("sdb_walk_status"),
    "memory_dump_walk_status": _walker_reaper("memory_dump_walk_status"),
    "windows_info_walk_status": _walker_reaper("windows_info_walk_status"),
    "windows_processes_walk_status": _walker_reaper("windows_processes_walk_status"),
    "windows_injection_walk_status": _walker_reaper("windows_injection_walk_status"),
}


__all__ = [
    "STATE_MACHINE_REAPER_CONFIGS",
    "WALKER_AUTO_TRIGGERS",
    "WALKER_REAPER_CONFIGS",
    "WalkerReaperConfig",
    "WalkerSafeRunner",
    "_clear_walker_registry_cache",
    "get_walker_auto_triggers",
]
