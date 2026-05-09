"""Phase 3a integration test: MediaTek parsers fire on a DPCS10-shape layout.

The campaign end-condition for Phase 3a is that the detector walks BOTH
``rootfs/`` (for the kernel module) AND the sibling scatter-zip directory
(for ``preloader_*.bin`` / ``lk.img`` / ``md1dsp.img``). Before the
``get_detection_roots`` helper existed, the detector only saw the
partition the caller passed in as ``extracted_path`` — MediaTek parser
fixtures sat idle on real uploads.

This test:

1. Builds a realistic tmp_path with a ``rootfs/`` holding a fake kernel
   module plus a sibling ``DPCS10_fixture/`` holding three MediaTek
   partition images.
2. Constructs a MagicMock Firmware row pointing ``extracted_path`` at
   the single-partition ``rootfs/vendor/`` dir — mimicking what the
   unpacker writes for scatter-zip uploads.
3. Calls ``detect_hardware_firmware`` with ``walk_roots`` populated from
   ``get_detection_roots``.
4. Verifies:
   - At least 4 blobs detected (kmod + 3 MTK partition images).
   - A row with ``format="mtk_preloader"`` and populated metadata
     (``file_ver``, ``sig_type``).
   - A row with ``format="mtk_lk"``.
   - A row with ``format="mtk_modem"`` (md1dsp).

Uses an in-memory stand-in for the session so the detector's bulk
``db.execute(insert(...))`` gets captured instead of hitting Postgres.
"""

from __future__ import annotations

import os
import struct
import uuid
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

from app.services.firmware_paths import get_detection_roots
from app.services.hardware_firmware.detector import detect_hardware_firmware


def _real(path) -> str:
    """Sync realpath helper — avoids ASYNC240 when called from async tests."""
    return os.path.realpath(str(path))


def _reals(paths) -> set[str]:
    return {os.path.realpath(str(p)) for p in paths}

# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _build_dpcs10_fixture(tmp_path: Path) -> tuple[Path, Path, Path, dict]:
    """Build the DPCS10-shape tree described in the Phase 3a direction.

    Returns (extraction_root, rootfs_dir, scatter_dir, bytes_by_name)
    where ``bytes_by_name`` is a dict of file-name -> bytes written, for
    SHA-based assertions.
    """
    extracted = tmp_path / "firmware" / "extracted"
    rootfs = extracted / "rootfs"
    vendor_modules = rootfs / "vendor" / "lib" / "modules"
    vendor_modules.mkdir(parents=True)
    # Make rootfs look Android-shaped so get_detection_roots promotes the
    # extracted/ container to a detection root.
    for name in ("system", "vendor", "odm"):
        (rootfs / name).mkdir(parents=True, exist_ok=True)

    # --- Fake tiny ELF kernel module (ET_REL, .ko). ----------------------
    # ELF header for 64-bit LE, ET_REL (0x01), EM_AARCH64.
    elf_header = bytearray(b"\x7fELF")
    elf_header += bytes([2, 1, 1, 0]) + b"\x00" * 8  # EI_*
    elf_header += struct.pack("<HH", 0x01, 0xB7)      # e_type=ET_REL, e_machine=AArch64
    elf_header += struct.pack("<I", 1)                # e_version
    elf_header += b"\x00" * 24                        # e_entry..e_shoff
    elf_header += struct.pack("<I", 0)                # e_flags
    # Pad to a tiny valid size (>= _MIN_FILE_SIZE = 512).
    elf_blob = bytes(elf_header).ljust(1024, b"\x00")
    fake_ko = vendor_modules / "fake_driver.ko"
    fake_ko.write_bytes(elf_blob)

    # --- MediaTek partition images ----------------------------------------
    scatter = extracted / "DPCS10_fixture"
    scatter.mkdir()

    # Preloader: MMM\x01\x38 magic, then a plausible GFH_FILE_INFO block.
    # GFH struct is 50 bytes: <3sBHH4sBBIIIIIII8s (magic, version, size,
    # type=0x0000, id, flash_dev, sig_type, load_addr, file_len, max_size,
    # content_offset, sig_len, jump_offset, attr, file_ver).
    preloader_header = b"MMM\x01\x38\x00\x00\x00"
    gfh_block = struct.pack(
        "<3sBHH4sBBIIIIIII8s",
        b"MMM",             # magic
        1,                  # version
        50,                 # size
        0x0000,             # type = GFH_FILE_INFO
        b"pm\x00\x00",      # id
        1,                  # flash_dev
        2,                  # sig_type (non-zero → "signed")
        0x80000000,         # load_addr
        200,                # file_len
        1024,               # max_size
        50,                 # content_offset
        16,                 # sig_len
        0,                  # jump_offset
        0,                  # attr
        b"V1.2\x00\x00\x00\x00",  # file_ver
    )
    preloader_body = preloader_header + gfh_block
    preloader_body = preloader_body.ljust(512, b"\x00")
    preloader_path = scatter / "preloader_fake.bin"
    preloader_path.write_bytes(preloader_body)

    # LK partition record: magic 0x58881688 at offset 0, name at offset 32.
    lk_header = struct.pack("<IIII", 0x58881688, 0, 512, 1) + b"\x00" * 16
    lk_name = b"lk\x00" + b"\x00" * (32 - 3)
    lk_body = lk_header + lk_name + b"\x00" * 32
    lk_body = lk_body.ljust(1024, b"\x00")
    lk_path = scatter / "lk.img"
    lk_path.write_bytes(lk_body)

    # md1dsp image — ASCII "MD1IMG" preceded by a small offset, followed
    # by a minimal section-table so the MediaTek modem parser walks it.
    # Section record (stride 20): name[8] + offset(u32) + size(u32) + 4 bytes pad.
    section1 = b"md1rom\x00\x00" + struct.pack("<II", 0x100, 0x40) + b"\x00" * 4
    section2 = b"md1dsp\x00\x00" + struct.pack("<II", 0x200, 0x40) + b"\x00" * 4
    # Empty terminator (two zeros is the parser's sentinel).
    terminator = b"\x00" * 20
    md_body = (
        b"\x00" * 0x40
        + b"MD1IMG\x00\x00"
        + section1
        + section2
        + terminator
    )
    md_body = md_body.ljust(2048, b"\x00")
    md_path = scatter / "md1dsp.img"
    md_path.write_bytes(md_body)

    bytes_by_name = {
        "fake_driver.ko": elf_blob,
        "preloader_fake.bin": preloader_body,
        "lk.img": lk_body,
        "md1dsp.img": md_body,
    }
    return extracted, rootfs, scatter, bytes_by_name


# ---------------------------------------------------------------------------
# In-memory DB stub
# ---------------------------------------------------------------------------


class _InMemoryDB:
    """Minimal async-session stand-in that captures detect_hardware_firmware's
    bulk insert and exposes the resulting rows for assertions.

    The detector performs:

        stmt = insert(HardwareFirmwareBlob).values(chunk)
        stmt = stmt.on_conflict_do_nothing(...)
        await db.execute(stmt)
        await db.flush()

    We intercept ``execute`` — extracting the .values() payload from the
    statement and storing it on ``self.rows``.
    """

    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []
        self._firmware_row: Any = None

    def set_firmware_row(self, firmware: Any) -> None:
        """Register the Firmware row the detector's ``select()`` should return."""
        self._firmware_row = firmware

    async def execute(self, stmt: Any):
        """Capture insert() values or return a firmware row for select()."""
        from sqlalchemy.sql.dml import Insert as _Insert
        from sqlalchemy.sql.selectable import Select as _Select

        if isinstance(stmt, _Insert):
            # postgresql.insert(Model).values(list_of_dicts) stores the
            # payload in stmt._multi_values[0] as a list of Column->value
            # dicts. Translate back to string-keyed dicts for assertions.
            multi = getattr(stmt, "_multi_values", None)
            if multi and multi[0]:
                for col_dict in multi[0]:
                    self.rows.append(
                        {col.key: value for col, value in col_dict.items()}
                    )
            return MagicMock()

        if isinstance(stmt, _Select):
            mock_result = MagicMock()
            mock_result.scalar_one_or_none = MagicMock(return_value=self._firmware_row)
            return mock_result

        return MagicMock()

    async def flush(self):
        return None

    async def commit(self):
        return None

    async def rollback(self):
        return None


# ---------------------------------------------------------------------------
# The actual test
# ---------------------------------------------------------------------------


async def test_mtk_parsers_fire_on_dpcs10_shape_fixture(tmp_path: Path) -> None:
    """Integration test: MediaTek preloader/LK/modem parsers populate metadata
    when the detector walks every detection root (rootfs + scatter sibling).
    """
    extracted, rootfs, scatter, _ = _build_dpcs10_fixture(tmp_path)

    # Firmware row — ``extracted_path`` points at the SINGLE sub-partition
    # inside rootfs, just like what the unpacker writes for a scatter-zip
    # upload. The helper must climb to ``extracted/`` and surface both
    # siblings.
    firmware = MagicMock()
    firmware.id = uuid.uuid4()
    firmware.extracted_path = str(rootfs / "vendor")
    firmware.device_metadata = None

    # Sanity: get_detection_roots must yield rootfs + scatter.
    roots = await get_detection_roots(firmware)
    root_reals = _reals(roots)
    assert _real(rootfs) in root_reals, (
        f"rootfs not in detection_roots: {roots}"
    )
    assert _real(scatter) in root_reals, (
        f"scatter dir not in detection_roots: {roots}"
    )

    # Run the detector with explicit walk_roots (bypasses the db select()).
    db = _InMemoryDB()
    db.set_firmware_row(firmware)

    count = await detect_hardware_firmware(
        firmware.id,
        db,  # type: ignore[arg-type]
        walk_roots=roots,
    )

    # --- Assertions -------------------------------------------------------
    assert count >= 4, (
        f"Expected >=4 detected blobs (kmod + preloader + lk + md1dsp); "
        f"got {count}. Rows: {[r.get('format') for r in db.rows]}"
    )

    # Debug any rows missing 'format' — helps diagnose ORM / Column key mismatches.
    bad = [r for r in db.rows if "format" not in r]
    assert not bad, (
        f"Rows missing 'format' key: {bad[:3]} (first 3). "
        f"Sample full row: {db.rows[0] if db.rows else None}"
    )

    formats = {r["format"] for r in db.rows}
    assert "ko" in formats or "kernel_module" in formats, (
        f"Kernel module not detected. formats={formats}"
    )
    assert "mtk_preloader" in formats, (
        f"MTK preloader parser did NOT fire. formats={formats}"
    )
    assert "mtk_lk" in formats, (
        f"MTK LK parser did NOT fire. formats={formats}"
    )
    assert "mtk_modem" in formats, (
        f"MTK modem (md1dsp) parser did NOT fire. formats={formats}"
    )

    # Metadata sanity — the preloader parser must populate GFH fields.
    preloader_rows = [r for r in db.rows if r["format"] == "mtk_preloader"]
    assert preloader_rows, "No mtk_preloader row"
    pre_meta = preloader_rows[0]["metadata"]
    assert "file_ver" in pre_meta, (
        f"mtk_preloader metadata missing file_ver: {pre_meta}"
    )
    assert pre_meta.get("sig_type") is not None, (
        f"mtk_preloader metadata missing sig_type: {pre_meta}"
    )

    # md1dsp: the MediaTek modem parser records a section-names list.
    md_rows = [r for r in db.rows if r["format"] == "mtk_modem"]
    assert md_rows, "No mtk_modem row"
    md_meta = md_rows[0]["metadata"]
    assert md_meta.get("magic_offset") is not None, (
        f"mtk_modem metadata missing magic_offset: {md_meta}"
    )

    # LK: the parser records the magic + partition_name.
    lk_rows = [r for r in db.rows if r["format"] == "mtk_lk"]
    assert lk_rows, "No mtk_lk row"
    lk_meta = lk_rows[0]["metadata"]
    assert lk_meta.get("magic") == "0x58881688", (
        f"mtk_lk metadata missing expected magic: {lk_meta}"
    )


async def test_detector_multi_root_dedupes_by_sha256(tmp_path: Path) -> None:
    """Two roots containing the identical blob must produce exactly one row."""
    root_a = tmp_path / "a"
    root_b = tmp_path / "b"
    root_a.mkdir()
    root_b.mkdir()

    # Same preloader bytes in both roots.
    preloader_bytes = (
        b"MMM\x01\x38\x00\x00\x00"
        + struct.pack(
            "<3sBHH4sBBIIIIIII8s",
            b"MMM", 1, 50, 0x0000, b"pm\x00\x00",
            1, 2, 0x80000000, 200, 1024, 50, 16, 0, 0,
            b"V1.0\x00\x00\x00\x00",
        )
    ).ljust(512, b"\x00")
    (root_a / "preloader.bin").write_bytes(preloader_bytes)
    (root_b / "preloader.bin").write_bytes(preloader_bytes)

    firmware = MagicMock()
    firmware.id = uuid.uuid4()
    firmware.extracted_path = str(root_a)
    firmware.device_metadata = None

    db = _InMemoryDB()
    db.set_firmware_row(firmware)

    count = await detect_hardware_firmware(
        firmware.id,
        db,  # type: ignore[arg-type]
        walk_roots=[str(root_a), str(root_b)],
    )
    assert count == 1, (
        f"SHA-dedupe failed: expected 1 row, got {count}. "
        f"Rows: {db.rows}"
    )


async def test_detector_with_no_walk_roots_returns_zero(tmp_path: Path) -> None:
    """An empty walk_roots list must short-circuit without hitting the DB."""
    db = _InMemoryDB()
    count = await detect_hardware_firmware(
        uuid.uuid4(),
        db,  # type: ignore[arg-type]
        walk_roots=[],
    )
    assert count == 0
    assert db.rows == []


# ---------------------------------------------------------------------------
# Phase 5 regression guard
# ---------------------------------------------------------------------------


def test_no_new_direct_extracted_path_reads():
    """Regression guard: walks outside approved files must use get_detection_roots.

    Enforces CLAUDE.md Learned Rule #16. Per-binary flows (emulation,
    fuzzing, sandbox, device dump) legitimately need ``extracted_path``
    because they resolve a single binary path, not a tree walk — they are
    allowlisted below. The helper module itself, the unpackers (which
    ASSIGN extracted_path), and the firmware service (the authoritative
    writer) are also allowlisted.
    """
    allowlist = {
        # Helper + writer
        "firmware_paths.py",
        "firmware_service.py",
        # Unpackers — assign extracted_path
        "unpack.py",
        "unpack_android.py",
        "unpack_linux.py",
        "unpack_common.py",
        # Per-binary flows — need a single rootfs for binary resolution
        "emulation_service.py",  # pre-Phase-5 monolith (retained for history)
        "service.py",  # backend/app/services/emulation/service.py (Phase 5 split)
        "fuzzing_service.py",
        "device_service.py",
        "arq_worker.py",
        # Export is a single-archive bundling step, not a detection walk
        "export_service.py",
    }
    # MCP tools: per-binary flows (emulation, fuzzing, comparison of
    # single-firmware extraction status) still need extracted_path.
    mcp_allowlist = {"emulation.py", "fuzzing.py", "comparison.py"}

    from pathlib import Path as _P

    # Resolve candidate source roots robustly across layouts:
    #   - Container: tests at /app/tests, sources at /app/app/services + /app/app/ai/tools
    #   - Host repo: tests at backend/tests, sources at backend/app/services + backend/app/ai/tools
    tests_dir = _P(__file__).resolve().parent
    backend_dir = tests_dir.parent  # .../backend or /app
    candidate_roots = [
        backend_dir / "app" / "services",
        backend_dir / "app" / "ai" / "tools",
    ]

    offenders = []
    scanned_any = False
    for root in candidate_roots:
        if not root.is_dir():
            continue
        scanned_any = True
        for path in root.rglob("*.py"):
            if path.name in allowlist or path.name in mcp_allowlist:
                continue
            text = path.read_text()
            if (
                "firmware.extracted_path" in text
                or "fw.extracted_path" in text
                or "fw_row.extracted_path" in text
            ):
                # Allow comment-only / docstring-only references. Track
                # whether we're inside a triple-quoted string and skip
                # those lines (along with `#`-comment lines).
                non_comment: list[str] = []
                in_docstring = False
                docstring_delim = ""
                for line in text.splitlines():
                    if not in_docstring:
                        for delim in ('"""', "'''"):
                            if line.count(delim) % 2 == 1:
                                in_docstring = True
                                docstring_delim = delim
                                break
                    elif line.count(docstring_delim) % 2 == 1:
                        in_docstring = False
                        docstring_delim = ""
                        continue
                    if in_docstring:
                        continue
                    if line.strip().startswith("#"):
                        continue
                    if (
                        "firmware.extracted_path" in line
                        or "fw.extracted_path" in line
                        or "fw_row.extracted_path" in line
                    ):
                        non_comment.append(line)
                if non_comment:
                    offenders.append(str(path.relative_to(backend_dir)))
    assert scanned_any, (
        "Regression guard could not locate source directories — "
        f"expected one of {[str(p) for p in candidate_roots]} to exist."
    )
    assert not offenders, (
        f"Direct firmware.extracted_path reads found: {offenders}. "
        f"Use get_detection_roots() per CLAUDE.md rule 16."
    )
