"""Tests for the Phase η.A.C NTFS $MFT walker triplet.

Rule #35b live canary — exercises the inner orchestrator
(``_do_mft_run``) against a real test DB via ``make_live_db()``.

dissect.ntfs requires a seekable NTFS-formatted image. Synthesizing
one in-process is heavy (mkfs.ntfs + loop-mount + ADS injection).
For tier-1 tests we mock ``dissect.ntfs.NTFS`` and feed it
record-shaped fakes (Rule #30 — patch the source module, not the
service). The walker's per-record extraction helpers, aggregation
math, and ORM persistence flow exercise via these fakes; an
integration-test extension against a real NTFS image is deferred to
a follow-up (sudo / ntfs-3g not available in dev venv).

Covers:
- Pure-function helpers (looks_like_ntfs / walk_raw_ntfs_images /
  is_dissect_ntfs_available).
- Per-record extraction (timestamps / ADS / file_size / flags).
- Inner orchestrator against a real test DB.
- Aggregate math (records_walked / timestomp_candidates / ADS counts).
- Caps (max_records / max_ads).
- Defensive boundaries (orphan records, parse failures, missing libs).
"""
from __future__ import annotations

import os
import struct
import tempfile
import uuid
from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import select

from app.models import Firmware, Project, WindowsMftRecord
from app.services.mft_walker import (
    DISSECT_NTFS_UNAVAILABLE,
    _build_target_metadata,
    _do_mft_run,
    _extract_data_summary,
    _extract_fn_timestamps,
    _extract_si_timestamps,
    _safe_filename,
    _safe_full_path,
    _safe_in_use,
    _safe_is_directory,
    _safe_is_reparse_point,
    is_dissect_ntfs_available,
    looks_like_ntfs,
    walk_raw_ntfs_images,
)
from tests._live_db import make_live_db


# ── NTFS boot sector / image fixture helpers ─────────────────────────────────


def _make_ntfs_boot_sector() -> bytes:
    """Return a 512-byte buffer whose first 11 bytes carry the NTFS
    boot signature. The remaining bytes are zeros — enough for
    looks_like_ntfs() to return True without satisfying a real
    parse."""
    buf = bytearray(512)
    # Jump instruction (3 bytes) + OEM ID "NTFS    " (8 bytes)
    buf[0:3] = b"\xeb\x52\x90"
    buf[3:11] = b"NTFS    "
    return bytes(buf)


@contextmanager
def _temp_ntfs_image() -> str:
    """Yield a path to a temp file with an NTFS boot sector signature
    but otherwise zeroed — for tests that need a passing magic check
    without needing a full NTFS volume to parse."""
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as fp:
        fp.write(_make_ntfs_boot_sector())
        path = fp.name
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


# ── _make_fake_record helpers ────────────────────────────────────────────────


def _make_fake_attribute_collection_si(*, creation_ns, mod_ns, change_ns, access_ns):
    """Return a MagicMock that behaves like a single-element
    AttributeCollection for $STANDARD_INFORMATION."""
    coll = MagicMock()
    coll.__bool__ = lambda self: True
    coll.creation_time_ns = creation_ns
    coll.last_modification_time_ns = mod_ns
    coll.last_change_time_ns = change_ns
    coll.last_access_time_ns = access_ns
    return coll


def _make_fake_attribute_collection_fn(*, creation_ns, mod_ns, change_ns, access_ns):
    """Return a MagicMock that behaves like a single-element
    AttributeCollection for $FILE_NAME."""
    coll = MagicMock()
    coll.__bool__ = lambda self: True
    coll.creation_time_ns = creation_ns
    coll.last_modification_time_ns = mod_ns
    coll.last_change_time_ns = change_ns
    coll.last_access_time_ns = access_ns
    return coll


def _make_fake_attribute_collection_data(*, primary_size: int | None, ads: list[tuple[str, int]]):
    """Return a list-like AttributeCollection that contains an
    unnamed primary $DATA attribute (header.name="") and 0+ named
    ADS attributes."""
    attrs = []
    if primary_size is not None:
        primary = MagicMock()
        primary.header.name = ""
        primary.header.size = primary_size
        primary.header.allocated_size = primary_size
        attrs.append(primary)
    for name, size in ads:
        attr = MagicMock()
        attr.header.name = name
        attr.header.size = size
        attr.header.allocated_size = size
        attrs.append(attr)
    return attrs


def _make_fake_attributes(*, si=None, fn=None, data=None):
    """Build a dict-like fake for record.attributes that supports
    ``[ATTRIBUTE_TYPE_CODE.X]`` indexing.

    Indexing keys map by integer (signal a real ATTRIBUTE_TYPE_CODE
    enum) — STANDARD_INFORMATION=0x10, FILE_NAME=0x30, DATA=0x80.
    """
    table = {}
    if si is not None:
        table[0x10] = si
    if fn is not None:
        table[0x30] = fn
    if data is not None:
        table[0x80] = data

    class FakeAttributes:
        def __getitem__(self, key):
            # ATTRIBUTE_TYPE_CODE enum has a .value attribute.
            if hasattr(key, "value"):
                key = key.value
            return table.get(key, [])

    return FakeAttributes()


def _make_fake_mft_record(
    *,
    segment: int = 100,
    in_use: bool = True,
    is_dir: bool = False,
    is_reparse: bool = False,
    full_path: str | None = "Windows\\System32\\cmd.exe",
    filename: str | None = "cmd.exe",
    si=None,
    fn=None,
    data=None,
    sequence_number: int = 1,
    flags: int = 1,  # FILE_RECORD_SEGMENT_IN_USE
):
    """Build a fake MftRecord-shaped MagicMock for the walker."""
    record = MagicMock()
    record.segment = segment
    record.header.Flags = flags if in_use else (flags & ~1)
    record.header.SequenceNumber = sequence_number
    record.attributes = _make_fake_attributes(si=si, fn=fn, data=data)
    record.is_dir.return_value = is_dir
    # is_file() is determined by the record's type flag at the NTFS
    # level, not by whether the parent chain happens to resolve. An
    # orphan record (full_path raises) can still be a file.
    record.is_file.return_value = not is_dir and not is_reparse
    record.is_reparse_point.return_value = is_reparse
    if full_path is None:
        record.full_path.side_effect = Exception("orphan")
    else:
        record.full_path.return_value = full_path
    record.filename = filename
    return record


def _make_firmware(project_id: uuid.UUID, name: str, sha_seed: str) -> Firmware:
    """Centralised Firmware factory (mirror η.C.A pattern)."""
    return Firmware(
        project_id=project_id,
        original_filename=name,
        storage_path=f"/tmp/{name}",
        sha256=(sha_seed * 64)[:64],
        file_size=1024,
    )


# ── Helper-function tests ────────────────────────────────────────────────────


def test_is_dissect_ntfs_available_true():
    """dep installed in dev venv post-η.A.0."""
    assert is_dissect_ntfs_available() is True


def test_looks_like_ntfs_with_boot_sector():
    """Magic check passes on synthesised NTFS boot sector."""
    with _temp_ntfs_image() as path:
        assert looks_like_ntfs(path) is True


def test_looks_like_ntfs_with_zero_bytes():
    """Magic check fails on all-zero file."""
    with tempfile.NamedTemporaryFile(suffix=".raw", delete=False) as fp:
        fp.write(b"\x00" * 512)
        path = fp.name
    try:
        assert looks_like_ntfs(path) is False
    finally:
        os.unlink(path)


def test_looks_like_ntfs_on_missing_file():
    """OSError → False (defensive boundary)."""
    assert looks_like_ntfs("/nonexistent/path/foo.raw") is False


def test_walk_raw_ntfs_images_finds_candidates_by_extension():
    """Walker enumerates candidates by extension, regardless of
    magic-check status (magic is a per-image check inside the inner
    runner)."""
    with tempfile.TemporaryDirectory() as root:
        # Create candidates with each supported extension.
        for ext in (".dd", ".raw", ".ntfs", ".img", ".bin"):
            p = os.path.join(root, f"disk{ext}")
            with open(p, "wb") as fp:
                fp.write(b"\x00" * 16)
        # Non-candidate
        with open(os.path.join(root, "notes.txt"), "wb") as fp:
            fp.write(b"hello")

        hits = walk_raw_ntfs_images([root])
        # 5 candidates, 0 non-candidates
        assert len(hits) == 5
        assert all(any(h.endswith(ext) for ext in (".dd", ".raw", ".ntfs", ".img", ".bin")) for h in hits)


def test_walk_raw_ntfs_images_handles_missing_root_gracefully():
    """Non-existent detection root returns empty list, no raise."""
    hits = walk_raw_ntfs_images(["/nonexistent/dir/path"])
    assert hits == []


def test_walk_raw_ntfs_images_handles_mixed_roots():
    """One valid + one missing root: returns valid-root hits only."""
    with tempfile.TemporaryDirectory() as good_root:
        with open(os.path.join(good_root, "disk.raw"), "wb") as fp:
            fp.write(b"\x00")
        hits = walk_raw_ntfs_images([good_root, "/missing"])
        assert len(hits) == 1


# ── Per-record extraction tests ──────────────────────────────────────────────


def test_extract_si_timestamps_full():
    """SI extraction pulls all 4 ns timestamps."""
    si = _make_fake_attribute_collection_si(
        creation_ns=132_000_000_000_000_000,
        mod_ns=132_500_000_000_000_000,
        change_ns=132_500_000_000_000_000,
        access_ns=133_000_000_000_000_000,
    )
    record = _make_fake_mft_record(si=si)
    out = _extract_si_timestamps(record)
    assert out["creation_ns"] == 132_000_000_000_000_000
    assert out["modification_ns"] == 132_500_000_000_000_000
    assert out["change_ns"] == 132_500_000_000_000_000
    assert out["access_ns"] == 133_000_000_000_000_000


def test_extract_si_timestamps_missing_si():
    """Record without $SI returns all None."""
    record = _make_fake_mft_record(si=None)
    out = _extract_si_timestamps(record)
    assert out == {
        "creation_ns": None,
        "modification_ns": None,
        "change_ns": None,
        "access_ns": None,
    }


def test_extract_fn_timestamps_full():
    """FN extraction pulls all 4 ns timestamps."""
    fn = _make_fake_attribute_collection_fn(
        creation_ns=132_000_000_000_000_000,
        mod_ns=132_000_000_000_000_000,
        change_ns=132_000_000_000_000_000,
        access_ns=132_000_000_000_000_000,
    )
    record = _make_fake_mft_record(fn=fn)
    out = _extract_fn_timestamps(record)
    assert all(v == 132_000_000_000_000_000 for v in out.values())


def test_extract_data_summary_primary_only():
    """File with primary $DATA and no ADS."""
    data = _make_fake_attribute_collection_data(
        primary_size=4096, ads=[]
    )
    record = _make_fake_mft_record(data=data)
    primary, ads = _extract_data_summary(record)
    assert primary == 4096
    assert ads == []


def test_extract_data_summary_with_zone_identifier_ads():
    """File with primary $DATA + Zone.Identifier ADS."""
    data = _make_fake_attribute_collection_data(
        primary_size=51200,
        ads=[("Zone.Identifier", 130)],
    )
    record = _make_fake_mft_record(data=data)
    primary, ads = _extract_data_summary(record)
    assert primary == 51200
    assert len(ads) == 1
    assert ads[0]["name"] == "Zone.Identifier"
    assert ads[0]["size"] == 130


def test_extract_data_summary_with_hidden_ads():
    """File with primary $DATA + hidden ADS containing payload."""
    data = _make_fake_attribute_collection_data(
        primary_size=2048,
        ads=[
            ("Zone.Identifier", 130),
            ("hidden", 8192),
        ],
    )
    record = _make_fake_mft_record(data=data)
    primary, ads = _extract_data_summary(record)
    assert primary == 2048
    assert len(ads) == 2


def test_extract_data_summary_no_data_attribute():
    """Directory record — no $DATA attribute."""
    record = _make_fake_mft_record(data=None, is_dir=True)
    primary, ads = _extract_data_summary(record)
    assert primary is None
    assert ads == []


def test_safe_full_path_orphan():
    """Orphan record raises → returns None."""
    record = _make_fake_mft_record(full_path=None)
    assert _safe_full_path(record) is None


def test_safe_filename_present():
    record = _make_fake_mft_record(filename="cmd.exe")
    assert _safe_filename(record) == "cmd.exe"


def test_safe_filename_missing():
    record = _make_fake_mft_record(filename=None)
    assert _safe_filename(record) is None


def test_safe_is_directory_true():
    record = _make_fake_mft_record(is_dir=True, full_path="Windows", filename="Windows")
    assert _safe_is_directory(record) is True


def test_safe_is_directory_false():
    record = _make_fake_mft_record(is_dir=False)
    assert _safe_is_directory(record) is False


def test_safe_is_reparse_point_true():
    record = _make_fake_mft_record(is_reparse=True)
    assert _safe_is_reparse_point(record) is True


def test_safe_in_use_allocated():
    """FILE_RECORD_SEGMENT_IN_USE flag set → True."""
    record = _make_fake_mft_record(in_use=True, flags=1)
    assert _safe_in_use(record) is True


def test_safe_in_use_deleted():
    """FILE_RECORD_SEGMENT_IN_USE flag clear → False."""
    record = _make_fake_mft_record(in_use=False, flags=0)
    assert _safe_in_use(record) is False


def test_build_target_metadata_shape():
    """target_metadata payload carries the expected keys."""
    record = _make_fake_mft_record(sequence_number=5, flags=1)
    payload = _build_target_metadata(record)
    assert "reparse_point" in payload
    assert "attribute_flags" in payload
    assert "sequence_number" in payload
    assert payload["sequence_number"] == 5
    assert payload["attribute_flags"] == 1


# ── DISSECT_NTFS_UNAVAILABLE shape ───────────────────────────────────────────


def test_dissect_ntfs_unavailable_shape():
    """Module-level UNAVAILABLE constant carries the documented keys."""
    assert DISSECT_NTFS_UNAVAILABLE["status"] == "unavailable"
    assert "not installed" in DISSECT_NTFS_UNAVAILABLE["reason"]
    assert DISSECT_NTFS_UNAVAILABLE["records"] == 0


# ── Inner orchestrator live-canary tests ─────────────────────────────────────


class _FakeFs:
    """Minimal NTFS-fs stand-in for the inner orchestrator. Supports
    fs.mft.segments() yielding the provided records list."""

    def __init__(self, records: list):
        self.mft = MagicMock()
        self.mft.segments.return_value = iter(records)
        self.mft._record_count = len(records)


def _patch_ntfs_factory(records: list):
    """Patch dissect.ntfs.NTFS to return a _FakeFs wrapping ``records``."""
    fake = _FakeFs(records)
    return patch("dissect.ntfs.NTFS", return_value=fake)


@pytest.mark.asyncio
async def test_do_mft_run_no_detection_roots():
    """No detection roots → empty result aggregate, no rows persisted."""
    async with make_live_db() as db:
        project = Project(name="η.A.C empty roots")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-empty.bin", "e")
        db.add(firmware)
        await db.flush()

        with patch(
            "app.services.mft_walker.get_detection_roots",
            return_value=[],
        ):
            result = await _do_mft_run(db, firmware.id)

        assert result["images_scanned"] == 0
        assert result["records_walked"] == 0
        assert result["records_persisted"] == 0
        assert result["per_image"] == []


@pytest.mark.asyncio
async def test_do_mft_run_no_image_candidates():
    """Detection root exists but has no raw NTFS image candidates →
    empty aggregate."""
    async with make_live_db() as db:
        project = Project(name="η.A.C no candidates")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-no-imgs.bin", "n")
        db.add(firmware)
        await db.flush()

        with tempfile.TemporaryDirectory() as root:
            # No matching files
            with open(os.path.join(root, "notes.txt"), "wb") as fp:
                fp.write(b"hello")

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ):
                result = await _do_mft_run(db, firmware.id)

        assert result["images_scanned"] == 0
        assert result["records_walked"] == 0


@pytest.mark.asyncio
async def test_do_mft_run_image_not_ntfs():
    """Image candidate but missing NTFS boot signature → status=not_ntfs."""
    async with make_live_db() as db:
        project = Project(name="η.A.C not ntfs")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-notntfs.bin", "x")
        db.add(firmware)
        await db.flush()

        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, "garbage.raw")
            with open(path, "wb") as fp:
                fp.write(b"\x00" * 4096)  # No NTFS magic

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ):
                result = await _do_mft_run(db, firmware.id)

        assert result["images_scanned"] == 1
        assert len(result["per_image"]) == 1
        assert result["per_image"][0]["status"] == "not_ntfs"


@pytest.mark.asyncio
async def test_do_mft_run_persists_records_for_synthetic_image():
    """Valid NTFS magic + mocked dissect.ntfs.NTFS yielding 3 record
    fakes → 3 WindowsMftRecord rows persisted."""
    async with make_live_db() as db:
        project = Project(name="η.A.C live canary")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-real.bin", "r")
        db.add(firmware)
        await db.flush()

        # Build 3 records: cmd.exe (healthy), notepad.exe (timestomp
        # candidate — SI mtime < FN mtime), explorer.exe (with hidden
        # ADS).
        rec_cmd = _make_fake_mft_record(
            segment=100,
            full_path="Windows\\System32\\cmd.exe",
            filename="cmd.exe",
            si=_make_fake_attribute_collection_si(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_500_000_000_000_000,
                change_ns=132_500_000_000_000_000,
                access_ns=133_000_000_000_000_000,
            ),
            fn=_make_fake_attribute_collection_fn(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_000_000_000_000_000,
                change_ns=132_000_000_000_000_000,
                access_ns=132_000_000_000_000_000,
            ),
            data=_make_fake_attribute_collection_data(
                primary_size=289_792, ads=[],
            ),
        )
        rec_timestomp = _make_fake_mft_record(
            segment=101,
            full_path="Users\\victim\\dropper.exe",
            filename="dropper.exe",
            si=_make_fake_attribute_collection_si(
                creation_ns=131_500_000_000_000_000,  # SI = 2017
                mod_ns=131_500_000_000_000_000,
                change_ns=131_500_000_000_000_000,
                access_ns=131_500_000_000_000_000,
            ),
            fn=_make_fake_attribute_collection_fn(
                creation_ns=132_900_000_000_000_000,  # FN = 2024 (timestomp!)
                mod_ns=132_900_000_000_000_000,
                change_ns=132_900_000_000_000_000,
                access_ns=132_900_000_000_000_000,
            ),
            data=_make_fake_attribute_collection_data(
                primary_size=8192, ads=[],
            ),
        )
        rec_ads = _make_fake_mft_record(
            segment=102,
            full_path="Users\\victim\\Downloads\\installer.exe",
            filename="installer.exe",
            si=_make_fake_attribute_collection_si(
                creation_ns=132_700_000_000_000_000,
                mod_ns=132_700_000_000_000_000,
                change_ns=132_700_000_000_000_000,
                access_ns=132_700_000_000_000_000,
            ),
            fn=_make_fake_attribute_collection_fn(
                creation_ns=132_700_000_000_000_000,
                mod_ns=132_700_000_000_000_000,
                change_ns=132_700_000_000_000_000,
                access_ns=132_700_000_000_000_000,
            ),
            data=_make_fake_attribute_collection_data(
                primary_size=51200,
                ads=[
                    ("Zone.Identifier", 130),  # Below benign tag threshold
                    ("hidden", 4096),          # Above threshold → hidden candidate
                ],
            ),
        )

        with tempfile.TemporaryDirectory() as root:
            img_path = os.path.join(root, "disk.raw")
            with open(img_path, "wb") as fp:
                fp.write(_make_ntfs_boot_sector())

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ), _patch_ntfs_factory([rec_cmd, rec_timestomp, rec_ads]):
                result = await _do_mft_run(db, firmware.id)

        await db.commit()

        # Aggregate counters
        assert result["images_scanned"] == 1
        assert result["records_walked"] == 3
        assert result["records_persisted"] == 3
        # Timestomp candidate: rec_timestomp (SI mtime < FN mtime)
        assert result["timestomp_candidates"] == 1
        # ADS streams seen: 2 (Zone.Identifier + hidden)
        assert result["ads_streams_seen"] == 2
        # ADS hidden candidates: 1 (only "hidden" > _ADS_BENIGN_TAG_SIZE)
        assert result["ads_hidden_candidates"] == 1

        # Persisted rows
        rows = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 3

        filenames = {r.filename for r in rows}
        assert filenames == {"cmd.exe", "dropper.exe", "installer.exe"}

        # Rule #35b live canary: confirm the timestomp row's SI/FN
        # comparison persists with full precision so the η.A.D
        # classifier can re-derive the verdict from the row.
        ts_row = next(r for r in rows if r.filename == "dropper.exe")
        assert (
            ts_row.si_last_modification_ns
            < ts_row.fn_last_modification_ns
        )

        # ADS row carries 2 stamped ADS entries.
        ads_row = next(r for r in rows if r.filename == "installer.exe")
        assert ads_row.ads_streams is not None
        assert len(ads_row.ads_streams) == 2


@pytest.mark.asyncio
async def test_do_mft_run_caps_persisted_records():
    """records_walked > max_records → caps records_persisted but
    continues iterating for aggregate counters."""
    async with make_live_db() as db:
        project = Project(name="η.A.C cap test")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-cap.bin", "c")
        db.add(firmware)
        await db.flush()

        # Build 6 minimal records; cap walker at 3 persisted.
        records = [
            _make_fake_mft_record(
                segment=i,
                full_path=f"Windows\\file{i}.exe",
                filename=f"file{i}.exe",
                si=_make_fake_attribute_collection_si(
                    creation_ns=132_000_000_000_000_000,
                    mod_ns=132_000_000_000_000_000,
                    change_ns=132_000_000_000_000_000,
                    access_ns=132_000_000_000_000_000,
                ),
                fn=_make_fake_attribute_collection_fn(
                    creation_ns=132_000_000_000_000_000,
                    mod_ns=132_000_000_000_000_000,
                    change_ns=132_000_000_000_000_000,
                    access_ns=132_000_000_000_000_000,
                ),
                data=_make_fake_attribute_collection_data(
                    primary_size=1024, ads=[],
                ),
            )
            for i in range(6)
        ]

        with tempfile.TemporaryDirectory() as root:
            img_path = os.path.join(root, "disk.raw")
            with open(img_path, "wb") as fp:
                fp.write(_make_ntfs_boot_sector())

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ), _patch_ntfs_factory(records):
                result = await _do_mft_run(db, firmware.id, max_records=3)

        # Walked all 6, persisted only 3.
        assert result["records_walked"] == 6
        assert result["records_persisted"] == 3


@pytest.mark.asyncio
async def test_do_mft_run_orphan_records_persist_with_null_path():
    """Orphan records (full_path raises) still persist with null path."""
    async with make_live_db() as db:
        project = Project(name="η.A.C orphan")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-orphan.bin", "o")
        db.add(firmware)
        await db.flush()

        rec_orphan = _make_fake_mft_record(
            segment=999,
            full_path=None,  # Orphan — full_path raises
            filename="orphaned.txt",
            si=_make_fake_attribute_collection_si(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_000_000_000_000_000,
                change_ns=132_000_000_000_000_000,
                access_ns=132_000_000_000_000_000,
            ),
            fn=_make_fake_attribute_collection_fn(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_000_000_000_000_000,
                change_ns=132_000_000_000_000_000,
                access_ns=132_000_000_000_000_000,
            ),
            data=_make_fake_attribute_collection_data(
                primary_size=128, ads=[],
            ),
        )

        with tempfile.TemporaryDirectory() as root:
            img_path = os.path.join(root, "disk.raw")
            with open(img_path, "wb") as fp:
                fp.write(_make_ntfs_boot_sector())

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ), _patch_ntfs_factory([rec_orphan]):
                result = await _do_mft_run(db, firmware.id)

        await db.commit()

        rows = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].full_path is None
        assert rows[0].filename == "orphaned.txt"


@pytest.mark.asyncio
async def test_do_mft_run_deleted_records_persist_with_in_use_false():
    """Deleted records (FILE_RECORD_SEGMENT_IN_USE clear) persist with
    in_use=False — they hold recovered file metadata."""
    async with make_live_db() as db:
        project = Project(name="η.A.C deleted")
        db.add(project)
        await db.flush()

        firmware = _make_firmware(project.id, "canary-del.bin", "d")
        db.add(firmware)
        await db.flush()

        rec_deleted = _make_fake_mft_record(
            segment=900_000,
            in_use=False,
            flags=0,  # FILE_RECORD_SEGMENT_IN_USE bit clear
            full_path="Users\\victim\\Temp\\dropper.exe",
            filename="dropper.exe",
            si=_make_fake_attribute_collection_si(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_000_000_000_000_000,
                change_ns=132_000_000_000_000_000,
                access_ns=132_000_000_000_000_000,
            ),
            fn=_make_fake_attribute_collection_fn(
                creation_ns=132_000_000_000_000_000,
                mod_ns=132_000_000_000_000_000,
                change_ns=132_000_000_000_000_000,
                access_ns=132_000_000_000_000_000,
            ),
            data=_make_fake_attribute_collection_data(
                primary_size=204_800, ads=[],
            ),
        )

        with tempfile.TemporaryDirectory() as root:
            img_path = os.path.join(root, "disk.raw")
            with open(img_path, "wb") as fp:
                fp.write(_make_ntfs_boot_sector())

            with patch(
                "app.services.mft_walker.get_detection_roots",
                return_value=[root],
            ), _patch_ntfs_factory([rec_deleted]):
                result = await _do_mft_run(db, firmware.id)

        await db.commit()

        rows = (
            await db.execute(
                select(WindowsMftRecord).where(
                    WindowsMftRecord.firmware_id == firmware.id
                )
            )
        ).scalars().all()
        assert len(rows) == 1
        assert rows[0].in_use is False
        assert rows[0].filename == "dropper.exe"
