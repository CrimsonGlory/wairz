"""Tests for ``scripts/backfill_detection.py``.

Phase 4 of the ``feature-extraction-integrity`` campaign.  The live DB path
is exercised separately (via ``docker compose exec``); this test file
covers the per-firmware helper shape plus the edge-cases in the direction:

* DPCS10-shape fixture yields ``blobs_delta >= 1`` on a real (in-memory)
  session walk.
* A row with ``extracted_path=None`` produces a ``skipped`` result and
  never raises.
* Dry-run does NOT insert new blob rows.
* ``run_backfill`` with an empty DB prints the no-rows marker and exits
  cleanly.
"""

from __future__ import annotations

import struct
import sys
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

# Import path: ``backend/scripts`` isn't on sys.path by default in tests.
_BACKEND_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _BACKEND_ROOT / "scripts"
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

import backfill_detection  # noqa: E402  (post-sys.path insertion)

from app.models.firmware import Firmware  # noqa: E402


def _write_dpcs10_fixture(tmp_path: Path) -> tuple[str, dict[str, bytes]]:
    """Build a tiny DPCS10-shape extraction tree.

    Returns (extracted_path, {basename: bytes}).
    """
    extracted = tmp_path / "extracted"
    rootfs = extracted / "rootfs"
    for p in ("vendor", "system", "odm"):
        (rootfs / p).mkdir(parents=True)
    scatter = extracted / "DPCS10_test"
    scatter.mkdir()

    # Minimal MTK preloader — triggers the mtk_preloader parser.
    preloader_header = b"MMM\x01\x38\x00\x00\x00"
    gfh_block = struct.pack(
        "<3sBHH4sBBIIIIIII8s",
        b"MMM", 1, 50, 0x0000, b"pm\x00\x00",
        1, 2, 0x80000000, 200, 1024, 50, 16, 0, 0,
        b"V1.0\x00\x00\x00\x00",
    )
    preloader = (preloader_header + gfh_block).ljust(512, b"\x00")
    (scatter / "preloader_test.bin").write_bytes(preloader)

    # Minimal MTK LK — 0x58881688 magic.
    lk_header = struct.pack("<IIII", 0x58881688, 0, 512, 1) + b"\x00" * 16
    lk_name = b"lk\x00" + b"\x00" * 29
    lk_body = (lk_header + lk_name + b"\x00" * 32).ljust(1024, b"\x00")
    (scatter / "lk.img").write_bytes(lk_body)

    return str(rootfs / "vendor"), {
        "preloader_test.bin": preloader,
        "lk.img": lk_body,
    }


class _InMemoryDB:
    """Minimal async-session stand-in.

    The detector does ``insert(Model).values([dict, dict...])``; we capture
    the dicts off ``stmt._multi_values`` and answer count queries from the
    captured list.  ``scalar_one_or_none()`` returns the registered Firmware
    row so ``detect_hardware_firmware`` can resolve its walk_roots.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._firmware_row: Any = None
        self.commit_count = 0

    def set_firmware_row(self, firmware: Any) -> None:
        self._firmware_row = firmware

    async def execute(self, stmt: Any):
        from sqlalchemy.sql.dml import Insert as _Insert
        from sqlalchemy.sql.selectable import Select as _Select

        if isinstance(stmt, _Insert):
            multi = getattr(stmt, "_multi_values", None)
            if multi and multi[0]:
                for col_dict in multi[0]:
                    self.rows.append(
                        {col.key: value for col, value in col_dict.items()}
                    )
            return MagicMock()

        if isinstance(stmt, _Select):
            # Count queries return an int; select(Firmware) returns the firmware.
            stmt_str = str(stmt).lower()
            scalar_value: Any
            if "count(" in stmt_str:
                if "hardware_firmware_blobs" in stmt_str:
                    scalar_value = len(self.rows)
                else:
                    scalar_value = 0
                mock_result = MagicMock()
                mock_result.scalar_one = MagicMock(return_value=scalar_value)
                return mock_result

            mock_result = MagicMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=self._firmware_row)
            scalars_proxy = MagicMock()
            scalars_proxy.all = MagicMock(
                return_value=[self._firmware_row] if self._firmware_row else []
            )
            mock_result.scalars = MagicMock(return_value=scalars_proxy)
            return mock_result

        return MagicMock()

    async def flush(self) -> None:
        return None

    async def commit(self) -> None:
        self.commit_count += 1

    async def rollback(self) -> None:
        return None

    def add(self, obj: Any) -> None:
        # SbomVulnerability inserts land here — not counted as blob rows.
        pass


async def test_backfill_one_detects_blobs_on_dpcs10_fixture(tmp_path: Path) -> None:
    extracted_path, _ = _write_dpcs10_fixture(tmp_path)

    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.original_filename = "DPCS10_test.zip"
    fw.extracted_path = extracted_path
    fw.device_metadata = None

    db = _InMemoryDB()
    db.set_firmware_row(fw)

    # Patch the CVE matcher — we're not testing CVE plumbing here.
    with patch.object(backfill_detection, "match_firmware_cves", new=AsyncMock(return_value=[])):
        result = await backfill_detection.backfill_one(fw, db, dry_run=False)

    assert result.status == "ok", f"unexpected status: {result}"
    assert result.blobs_delta >= 1, (
        f"Expected >=1 new blob; got delta={result.blobs_delta}, rows={db.rows}"
    )
    assert result.roots_count >= 1
    # Audit stamp landed.
    assert fw.device_metadata is not None
    audit = (fw.device_metadata or {}).get("detection_audit")
    assert audit is not None
    assert "last_backfill_at" in audit
    assert audit.get("blobs_detected") == result.blobs_after


async def test_backfill_one_skips_when_extracted_path_none() -> None:
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.original_filename = "never_unpacked.zip"
    fw.extracted_path = None
    fw.device_metadata = None

    db = _InMemoryDB()
    result = await backfill_detection.backfill_one(fw, db, dry_run=False)

    assert result.status == "skipped"
    assert "no extraction" in result.note
    assert result.blobs_delta == 0


async def test_backfill_one_skips_when_extraction_missing(tmp_path: Path) -> None:
    gone = tmp_path / "does_not_exist"
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.original_filename = "vanished.zip"
    fw.extracted_path = str(gone)
    fw.device_metadata = None

    db = _InMemoryDB()
    result = await backfill_detection.backfill_one(fw, db, dry_run=False)
    assert result.status == "skipped"
    assert "missing" in result.note


async def test_dry_run_does_not_insert_blobs(tmp_path: Path) -> None:
    extracted_path, _ = _write_dpcs10_fixture(tmp_path)

    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.original_filename = "DPCS10_dryrun.zip"
    fw.extracted_path = extracted_path
    fw.device_metadata = None

    db = _InMemoryDB()
    db.set_firmware_row(fw)

    result = await backfill_detection.backfill_one(fw, db, dry_run=True)

    assert result.status == "ok"
    assert result.roots_count >= 1
    # Zero inserted rows — dry-run must not call the detector.
    assert db.rows == [], f"Dry-run inserted rows: {db.rows}"
    assert result.blobs_delta == 0
    assert "dry-run" in result.note


async def test_run_backfill_empty_db_prints_marker(capsys) -> None:
    """Empty DB path: exits cleanly, prints the no-rows marker, no crash."""
    mock_result = MagicMock()
    scalars_proxy = MagicMock()
    scalars_proxy.all = MagicMock(return_value=[])
    mock_result.scalars = MagicMock(return_value=scalars_proxy)

    fake_session = AsyncMock()
    fake_session.execute = AsyncMock(return_value=mock_result)
    fake_session.__aenter__ = AsyncMock(return_value=fake_session)
    fake_session.__aexit__ = AsyncMock(return_value=None)

    with patch.object(
        backfill_detection,
        "async_session_factory",
        return_value=fake_session,
    ):
        summary = await backfill_detection.run_backfill(dry_run=False)

    assert summary.processed == 0
    assert summary.results == []
    captured = capsys.readouterr()
    assert "no firmware in DB" in captured.out


async def test_dry_run_banner_printed(tmp_path: Path, capsys) -> None:
    """``=== DRY RUN — no writes ===`` banner lands when --dry-run is set."""
    extracted_path, _ = _write_dpcs10_fixture(tmp_path)
    fw = MagicMock(spec=Firmware)
    fw.id = uuid.uuid4()
    fw.original_filename = "DPCS10_banner.zip"
    fw.extracted_path = extracted_path
    fw.device_metadata = None

    db = _InMemoryDB()
    db.set_firmware_row(fw)

    # Outer session returns the firmware list; inner per-firmware session
    # is the same stub (we don't actually need distinct sessions for this
    # assertion).
    def _session_factory():
        session = AsyncMock()
        # Outer call — list firmware
        session.execute = db.execute  # direct reuse: handles both list + count
        session.__aenter__ = AsyncMock(return_value=db)
        session.__aexit__ = AsyncMock(return_value=None)
        return session

    with patch.object(
        backfill_detection, "async_session_factory", side_effect=_session_factory
    ), patch.object(
        backfill_detection, "match_firmware_cves", new=AsyncMock(return_value=[])
    ):
        summary = await backfill_detection.run_backfill(dry_run=True)

    captured = capsys.readouterr()
    assert "=== DRY RUN — no writes ===" in captured.out
    # All results must be 'ok' with zero blob inserts (dry-run).
    for r in summary.results:
        assert r.status in ("ok", "skipped")
        assert r.blobs_delta == 0
