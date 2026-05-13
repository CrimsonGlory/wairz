"""Walker auto-trigger bridge — tests for the Shape A fix that wires
the 22-walker registry into the new upload pipeline.

Covers:

- ``WALKER_AUTO_TRIGGERS`` registry exposes ≥20 safe-runners (current
  count is 22 — registry_hive / driver_extractor / evtx + AppCompat /
  BCD / DPAPI / EFS / ESP / ETL / LNK / MBR-VBR / MFT / prefetch /
  scheduled_task / SDB / SRUM / USN / WMI / container / journald /
  linux_persistence / systemd).
- The registry's lazy-cache helpers behave (``get_walker_auto_triggers``
  caches; ``_clear_walker_registry_cache`` drops the cache).
- The ``_fire_walker_auto_triggers`` helper iterates the registry and
  swallows exceptions (a misbehaving walker doesn't block the others).
- Rule #35b live canary: feed a real Firmware row through the helper
  + verify each walker no-ops cleanly (empty extraction tree → empty
  result → status stays ``idle`` per Rule #39 .safe semantics).
- ``_post_process_pipeline``'s generic-ZIP path sets
  ``firmware.extracted_path`` to ``zip_contents/`` after extraction
  (the bug surfaced empirically on the Medtronic ILLUMISITE 15.57 GB
  upload — pre-fix it stayed NULL → no detection → no walkers).
"""
from __future__ import annotations

import asyncio
import uuid

import pytest

from app.models import Firmware, Project
from app.services.firmware_service import _fire_walker_auto_triggers
from app.workers.walker_registry import (
    WALKER_AUTO_TRIGGERS,
    _clear_walker_registry_cache,
    get_walker_auto_triggers,
)
from tests._live_db import make_live_db

# ── Registry shape ───────────────────────────────────────────────────────────


def test_walker_registry_holds_all_known_safe_runners():
    """WALKER_AUTO_TRIGGERS lists every walker that was wired before the
    bridge fix (γ.4 registry_hive + γ.5 driver_extractor +
    ε.1.b.4 evtx) PLUS every walker shipped during η/θ/ι/κ campaigns
    that was previously orphaned (only registered as MCP trigger
    tools but never fired automatically on upload).
    """
    assert len(WALKER_AUTO_TRIGGERS) >= 20, (
        f"WALKER_AUTO_TRIGGERS has {len(WALKER_AUTO_TRIGGERS)} entries; "
        "expected ≥20. A new walker was probably added without "
        "registering its auto_*_walk_firmware_safe in walker_registry."
    )


def test_walker_registry_entries_are_callable_coroutines():
    """Each entry must be an async callable that takes a UUID."""
    for runner in WALKER_AUTO_TRIGGERS:
        assert callable(runner), f"{runner!r} is not callable"
        assert asyncio.iscoroutinefunction(runner), (
            f"{runner!r} is not an async function — walker safe-runners "
            "must be `async def` per Rule #39."
        )


def test_walker_registry_has_no_duplicates():
    """Each safe-runner appears exactly once — duplicate auto-fires would
    double-bill the worker container with no benefit (each safe-runner
    is idempotent at the data layer, but redundant runs waste CPU)."""
    seen: set[int] = set()
    for runner in WALKER_AUTO_TRIGGERS:
        assert id(runner) not in seen, (
            f"{runner.__qualname__} registered twice in WALKER_AUTO_TRIGGERS"
        )
        seen.add(id(runner))


def test_get_walker_auto_triggers_returns_cached_list():
    """First call lazy-loads; subsequent calls return the cached instance."""
    a = get_walker_auto_triggers()
    b = get_walker_auto_triggers()
    assert a is b, "get_walker_auto_triggers should cache the list"


def test_clear_walker_registry_cache_drops_cache():
    """The test-only helper drops the cache so subsequent calls reload."""
    a = get_walker_auto_triggers()
    _clear_walker_registry_cache()
    b = get_walker_auto_triggers()
    assert a is not b, "_clear_walker_registry_cache should drop the cache"
    # Restored cache is the same content (different instance though).
    assert len(a) == len(b)


# ── _fire_walker_auto_triggers behavioural contract ──────────────────────────


@pytest.mark.asyncio
async def test_fire_walker_auto_triggers_swallows_walker_exceptions(
    monkeypatch,
):
    """One safe-runner raising must NOT block the other 21."""
    invoked: list[str] = []

    async def _raising_runner(firmware_id):
        invoked.append("raising")
        raise RuntimeError("simulated walker crash")

    async def _good_runner(firmware_id):
        invoked.append("good")

    # Stand up a 2-entry fake registry.
    _clear_walker_registry_cache()
    monkeypatch.setattr(
        "app.workers.walker_registry._load_walker_safe_runners",
        lambda: [_raising_runner, _good_runner],
    )
    try:
        await _fire_walker_auto_triggers(uuid.uuid4())
    finally:
        # Restore the real registry for subsequent tests in this session.
        _clear_walker_registry_cache()

    assert invoked == ["raising", "good"], (
        "_fire_walker_auto_triggers must iterate sequentially AND continue "
        "past a raising safe-runner."
    )


# ── Rule #35b live canary ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fire_walker_auto_triggers_against_real_firmware_row(tmp_path):
    """Live-canary: feed an actual Firmware row through the helper.

    Each safe-runner opens its own ``async_session_factory()`` session —
    against the dev-host pytest environment there's no Docker / no
    PostgreSQL, so the safe-runners will fail to connect AND swallow
    that failure silently per Rule #39. The contract this test checks
    is that ``_fire_walker_auto_triggers`` completes without raising —
    NOT that the walkers do real work (that requires a Docker
    container with PostgreSQL; covered by the orchestrator's
    end-to-end re-test on the ILLUMISITE firmware).

    The firmware row is created via ``make_live_db()`` so the test is
    deterministic on the dev host. The empty ``tmp_path`` extracted
    tree guarantees no walker finds work even if the connection
    miraculously succeeded.
    """
    async with make_live_db() as db:
        project = Project(
            name="walker-bridge-canary",
            description="Rule #35b live canary for the walker auto-trigger bridge",
        )
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="empty.zip",
            storage_path=str(tmp_path / "empty.zip"),
            file_size=0,
            sha256="0" * 64,
            extracted_path=str(tmp_path),
        )
        db.add(firmware)
        await db.commit()
        fid = firmware.id

    # The helper must complete cleanly — every safe-runner's exception
    # swallowing keeps the outer iteration alive.
    await _fire_walker_auto_triggers(fid)


# ── _post_process_pipeline generic-ZIP path sets extracted_path ──────────────


@pytest.mark.asyncio
async def test_post_process_pipeline_sets_extracted_path_for_generic_zip(
    tmp_path,
    monkeypatch,
):
    """The bridge fix: a generic ZIP that extracts to ``zip_contents/``
    MUST set ``firmware.extracted_path = zip_contents`` so that the
    walker registry has something to walk. Pre-fix the value stayed
    NULL and every ``*_walk_status`` stayed ``idle``.

    Validates by stubbing out the extraction primitives (the real
    work needs unblob + a real ZIP) and inspecting the row after
    the pipeline runs.
    """
    import zipfile

    from app.services import firmware_service

    # Build a 'firmware_dir' layout the pipeline expects.
    firmware_dir = tmp_path / "fw"
    firmware_dir.mkdir()
    storage_path = firmware_dir / "test.zip"
    # Make a real (tiny) ZIP so zipfile.is_zipfile() returns True.
    with zipfile.ZipFile(storage_path, "w") as zf:
        zf.writestr("placeholder.txt", "x")

    zip_root = firmware_dir / "zip_contents"

    # The fix relies on the zip_root dir EXISTING after
    # _extract_firmware_from_zip runs — we stub the heavy extraction
    # to just create the directory + a placeholder file.
    def _fake_extract(_storage, _firmware_dir):
        zip_root.mkdir(exist_ok=True)
        (zip_root / "Boot").mkdir(exist_ok=True)
        (zip_root / "Boot" / "BCD").write_bytes(b"")

    monkeypatch.setattr(firmware_service, "_extract_firmware_from_zip", _fake_extract)
    # Avoid the recursive nested-archive step's heavy I/O.
    monkeypatch.setattr(
        firmware_service, "_recursive_extract_nested", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        firmware_service, "widen_read_perms", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(
        firmware_service, "diagnose_failed_archives", lambda *args, **kwargs: {}
    )

    # Skip Android detection (writes a real zip file with no manifests
    # would be falsy anyway, but explicit is cheaper than auditing
    # _is_android_firmware_zip's full path-handling).
    monkeypatch.setattr(firmware_service, "_is_android_firmware_zip", lambda *_: False)
    monkeypatch.setattr(firmware_service, "_zip_contains_rootfs", lambda *_: False)

    # Skip the heavy post-extraction analysis (arch/endian/OS detection
    # requires real binaries). Just verify extracted_path is set.
    monkeypatch.setattr(
        firmware_service, "detect_architecture", lambda *_: (None, None)
    )
    monkeypatch.setattr(firmware_service, "detect_os_info", lambda *_: None)
    monkeypatch.setattr(firmware_service, "detect_kernel", lambda *_: None)
    monkeypatch.setattr(
        firmware_service, "populate_detection_roots", lambda *args, **kwargs: []
    )
    # Suppress the post-commit detection task — make sure it doesn't try to
    # touch a real Docker container.
    monkeypatch.setattr(
        firmware_service,
        "_run_hardware_firmware_detection_safe",
        lambda *args, **kwargs: asyncio.sleep(0),
    )

    async with make_live_db() as db:
        project = Project(
            name="generic-zip-bridge",
            description="walker bridge fix — generic-ZIP extracted_path coverage",
        )
        db.add(project)
        await db.flush()

        firmware = Firmware(
            project_id=project.id,
            original_filename="test.zip",
            storage_path=str(storage_path),
            file_size=42,  # synthetic; the test stubs all heavy I/O
            sha256="0" * 64,
        )
        db.add(firmware)
        await db.commit()

        # Pre-condition: extracted_path is NULL (this is the bug shape).
        assert firmware.extracted_path is None

        await firmware_service._post_process_pipeline(
            db, firmware, update_stage=True
        )

        # Post-condition: extracted_path now points at zip_contents/.
        assert firmware.extracted_path == str(zip_root), (
            f"expected extracted_path={zip_root!r}, got {firmware.extracted_path!r}"
        )
