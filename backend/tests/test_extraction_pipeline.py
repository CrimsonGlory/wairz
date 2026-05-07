"""Phase 1 contract tests for the extraction pipeline dispatch layer.

Covers:

1. Strategy resolution — every ``DetectedFormat`` value resolves to a
   strategy without ``KeyError`` (forward-compatible registry shape).
2. Format → strategy mapping — no-handler formats route to
   :func:`unpack_no_handler`; default formats route to
   :func:`unpack_firmware`.
3. Fallback to fresh detection — when ``firmware.detected_format`` is
   None, the dispatcher consults the file's magic bytes via
   :func:`detect_format`.
4. Rule #35b live canary — a real :class:`Firmware` ORM row stamped
   with ``detected_format='wim_archive'`` runs end-to-end through
   :func:`run_unpack`, persists no extraction, and returns an
   :class:`UnpackResult` whose log carries the WIM-format workaround
   text from :data:`CAPABILITY_NOTES`.
5. ``unpack_no_handler`` direct contract — fixture ``.tibx`` file
   produces ``success=False`` with the Acronis workaround text.
6. ``UNKNOWN`` passes through to the default strategy (the unpack
   monolith), not to ``unpack_no_handler`` — preserves the Rule #19
   evidence-first discipline of letting unblob attempt unclassified
   files.
"""

from __future__ import annotations

import uuid
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from sqlalchemy import select

from app.models.firmware import Firmware
from app.models.project import Project
from app.services.extraction_pipeline import resolve_strategy, run_unpack
from app.services.format_detection import (
    CAPABILITY_NOTES,
    DetectedFormat,
)
from app.workers.extraction_strategies import (
    STRATEGIES,
    Strategy,
    get_strategy,
)
from app.workers.unpack import unpack_firmware
from app.workers.unpack_no_handler import unpack_no_handler

from tests._live_db import make_live_db


# ---------------------------------------------------------------------------
# 1. Strategy resolution coverage — every enum value must resolve.
# ---------------------------------------------------------------------------

def test_every_detected_format_resolves_to_a_strategy():
    """``get_strategy`` returns a callable for every ``DetectedFormat``."""
    for fmt in DetectedFormat:
        strategy = get_strategy(fmt)
        assert callable(strategy), f"{fmt} did not resolve to a callable"


def test_strategies_table_covers_every_detected_format():
    """The static ``STRATEGIES`` map must enumerate every enum value.

    Forward-compatibility is preserved by ``get_strategy``'s ``.get(fmt,
    _DEFAULT)`` fallback, but the static map should still list every
    format explicitly so adding a new format triggers a thoughtful
    routing decision rather than silently defaulting.
    """
    missing = [f for f in DetectedFormat if f not in STRATEGIES]
    assert not missing, f"STRATEGIES missing entries for: {missing}"


# ---------------------------------------------------------------------------
# 2. Format → strategy mapping smoke
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "fmt",
    [
        DetectedFormat.WIM_ARCHIVE,
        DetectedFormat.QNX_IFS,
        DetectedFormat.ACRONIS_BACKUP,
    ],
)
def test_no_handler_formats_route_to_unpack_no_handler(fmt: DetectedFormat):
    assert get_strategy(fmt) is unpack_no_handler


@pytest.mark.parametrize(
    "fmt",
    [
        DetectedFormat.LINUX_FIRMWARE_BLOB,
        DetectedFormat.TAR_ARCHIVE,
        DetectedFormat.ANDROID_APK,
        DetectedFormat.ANDROID_OTA,
        DetectedFormat.ZIP_ARCHIVE,
        DetectedFormat.PE_EXECUTABLE,
        DetectedFormat.ISO_9660,
        DetectedFormat.WINDOWS_INSTALLER_ISO,
    ],
)
def test_default_formats_route_to_unpack_firmware(fmt: DetectedFormat):
    assert get_strategy(fmt) is unpack_firmware


def test_unknown_format_routes_to_default_not_no_handler():
    """``DetectedFormat.UNKNOWN`` must let unblob have a try.

    Rule #19 evidence-first discipline — the detection layer is
    informational, not gating. A file we couldn't classify might still
    be something unblob's heuristics can crack open.
    """
    assert get_strategy(DetectedFormat.UNKNOWN) is unpack_firmware
    assert get_strategy(DetectedFormat.UNKNOWN) is not unpack_no_handler


# ---------------------------------------------------------------------------
# 3. Fallback to fresh detect_format() when detected_format is None.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_resolve_strategy_falls_back_to_fresh_detection_when_column_is_none(
    tmp_path: Path,
):
    """Older rows uploaded pre-detection don't have detected_format set.

    The dispatcher must re-run :func:`detect_format` against the file
    and route based on the result.
    """
    # squashfs little-endian magic: 'hsqs' at offset 0 → LINUX_FIRMWARE_BLOB
    blob = tmp_path / "old.bin"
    blob.write_bytes(b"hsqs" + b"\x00" * 60)

    # Build a stub firmware with detected_format=None (older row).
    fw = Firmware(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        sha256="a" * 64,
        storage_path=str(blob),
        detected_format=None,
    )

    fmt, strategy = await resolve_strategy(fw)
    assert fmt is DetectedFormat.LINUX_FIRMWARE_BLOB
    assert strategy is unpack_firmware


@pytest.mark.asyncio
async def test_resolve_strategy_handles_unparseable_detected_format(
    tmp_path: Path,
):
    """A garbage value in ``firmware.detected_format`` falls back to fresh detection."""
    blob = tmp_path / "wim.bin"
    # MSWIM\x00\x00\x00 → WIM_ARCHIVE
    blob.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 64)

    fw = Firmware(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        sha256="b" * 64,
        storage_path=str(blob),
        detected_format="not-a-real-enum-value",
    )

    fmt, strategy = await resolve_strategy(fw)
    assert fmt is DetectedFormat.WIM_ARCHIVE
    assert strategy is unpack_no_handler


# ---------------------------------------------------------------------------
# 4. Rule #35b live canary — real Firmware row, real ORM round-trip.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_unpack_live_canary_wim_archive_routes_to_no_handler(
    tmp_path: Path,
):
    """Round-trip: persist a Firmware row with detected_format='wim_archive',
    call run_unpack(), assert the no-handler workaround text appears.

    Verifies the value-flow contract: the persisted column drives the
    dispatch, which drives the worker, which drives the user-facing
    workaround text. Mock-only tests cannot catch a regression where
    the dispatcher reads the wrong column or the strategy returns the
    wrong format's note.
    """
    storage_file = tmp_path / "firmware.wim"
    # Real WIM magic so the unpack_no_handler's fresh detect_format()
    # also lands on WIM_ARCHIVE — confirms detect-time and dispatch-time
    # agree.
    storage_file.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 64)

    async with make_live_db() as db:
        pid = uuid.uuid4()
        project = Project(id=pid, name="live-canary-pipeline", status="ready")
        db.add(project)
        await db.flush()

        firmware = Firmware(
            id=uuid.uuid4(),
            project_id=pid,
            sha256="c" * 64,
            storage_path=str(storage_file),
            detected_format=DetectedFormat.WIM_ARCHIVE.value,
        )
        db.add(firmware)
        await db.commit()

        # SELECT the persisted row before dispatch — proves the column
        # actually round-tripped through the ORM (not just an in-memory
        # attribute).
        row = (
            await db.execute(select(Firmware).where(Firmware.id == firmware.id))
        ).scalar_one()
        assert row.detected_format == DetectedFormat.WIM_ARCHIVE.value

        result = await run_unpack(
            row,
            output_base_dir=str(tmp_path),
            firmware_id=row.id,
        )

    assert result.success is False
    assert result.error is not None
    assert "no extraction handler" in result.error.lower()
    # CAPABILITY_NOTES integration: the WIM-specific workaround
    # mentions wimlib AND 7-Zip. If the test trips because copy
    # changed, update CAPABILITY_NOTES and this assertion in lock-
    # step (Rule #21 sync discipline).
    log_lower = result.unpack_log.lower()
    assert "wimlib" in log_lower or "7-zip" in log_lower, (
        f"WIM workaround note missing from unpack_log: {result.unpack_log!r}"
    )


# ---------------------------------------------------------------------------
# 5. unpack_no_handler unit contract.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_unpack_no_handler_acronis_backup(tmp_path: Path):
    """Acronis ``.tibx`` files produce a clear no-handler failure."""
    # Acronis has no public magic; detection falls back to extension.
    backup = tmp_path / "image.tibx"
    backup.write_bytes(b"\xff" * 256)

    result = await unpack_no_handler(
        firmware_path=str(backup),
        output_base_dir=str(tmp_path),
    )

    assert result.success is False
    assert result.error is not None
    assert "no extraction handler" in result.error.lower()
    # Workaround text from CAPABILITY_NOTES.
    expected = CAPABILITY_NOTES[DetectedFormat.ACRONIS_BACKUP]
    assert expected in result.unpack_log


@pytest.mark.asyncio
async def test_unpack_no_handler_invokes_progress_callback(tmp_path: Path):
    """The strategy contract includes calling progress_callback if provided."""
    backup = tmp_path / "boot.wim"
    backup.write_bytes(b"MSWIM\x00\x00\x00" + b"\x00" * 64)

    progress = AsyncMock()
    result = await unpack_no_handler(
        firmware_path=str(backup),
        output_base_dir=str(tmp_path),
        progress_callback=progress,
    )

    assert result.success is False
    progress.assert_awaited()  # at least once
    # The final progress=100 sentinel is the contract: callers
    # transition the firmware row out of the unpacking stage.
    final_call = progress.await_args
    assert final_call.args[1] == 100


# ---------------------------------------------------------------------------
# 6. UNKNOWN passes through to the default strategy via run_unpack.
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_run_unpack_unknown_format_calls_default_strategy(tmp_path: Path):
    """``UNKNOWN`` files dispatch to ``unpack_firmware`` (not no-handler).

    Patches the default strategy with an :class:`AsyncMock` so the test
    doesn't actually run unblob/binwalk; only the dispatch decision is
    under test.
    """
    blob = tmp_path / "mystery.bin"
    # Random bytes — no signature matches → DetectedFormat.UNKNOWN.
    blob.write_bytes(b"\xfe" * 256)

    fw = Firmware(
        id=uuid.uuid4(),
        project_id=uuid.uuid4(),
        sha256="e" * 64,
        storage_path=str(blob),
        detected_format=DetectedFormat.UNKNOWN.value,
    )

    fake_default = AsyncMock(return_value="fake-result-sentinel")
    new_strategies: dict[DetectedFormat, Strategy] = dict(STRATEGIES)
    new_strategies[DetectedFormat.UNKNOWN] = fake_default

    with patch.dict(
        "app.workers.extraction_strategies.STRATEGIES",
        new_strategies,
        clear=True,
    ):
        result = await run_unpack(fw, output_base_dir=str(tmp_path), firmware_id=fw.id)

    assert result == "fake-result-sentinel"
    fake_default.assert_awaited_once()
    # Verify the strategy was called with the correct positional/keyword args.
    call = fake_default.await_args
    assert call.args[0] == str(blob)
    assert call.kwargs.get("firmware_id") == fw.id
